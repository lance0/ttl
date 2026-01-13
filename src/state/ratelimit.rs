//! ICMP Rate Limit Detection
//!
//! Detects when routers are rate-limiting ICMP responses, which causes
//! misleading packet loss statistics. Common indicators:
//!
//! 1. **Isolated hop loss**: Loss at hop N but 0% loss downstream
//! 2. **Uniform flow loss**: All flows losing equally (Paris/Dublin)
//! 3. **Stable loss ratio**: Consistent percentage over time
//!
//! When rate limiting is detected, the TUI shows a warning to help users
//! understand that the "loss" isn't real packet loss.

use std::collections::VecDeque;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

use super::session::{Hop, RateLimitInfo, Session};
use crate::trace::SessionMap;

/// Analyze a session for rate limit indicators at all hops
pub fn analyze_rate_limiting(session: &mut Session) {
    let hop_count = session.hops.len();

    // Collect detection results first to avoid borrow issues
    let results: Vec<(u8, Option<RateLimitInfo>)> = (1..=hop_count as u8)
        .map(|ttl| (ttl, detect_rate_limiting(session, ttl)))
        .collect();

    // Apply results
    for (ttl, info) in results {
        if let Some(hop) = session.hop_mut(ttl) {
            if info.is_some() {
                hop.rate_limit = info;
            } else if hop.rate_limit.is_some() {
                // Clear previous detection if no longer detected
                // (loss may have decreased)
                let completed = hop.received + hop.timeouts;
                if completed > 20 && hop.loss_pct() < 5.0 {
                    hop.rate_limit = None;
                }
            }
        }
    }
}

/// Detect rate limiting at a specific hop
fn detect_rate_limiting(session: &Session, ttl: u8) -> Option<RateLimitInfo> {
    let hop = session.hop(ttl)?;

    // Must have some completed probes
    let completed = hop.received + hop.timeouts;
    if completed < 10 {
        return None; // Not enough data
    }

    let hop_loss = hop.loss_pct();

    // Skip if no significant loss
    if hop_loss < 5.0 {
        return None;
    }

    // Check 1: Isolated hop loss (strongest signal)
    // Loss here but healthy downstream = rate limiting
    let downstream_loss = find_next_responding_hop_loss(session, ttl);
    if let Some(dl) = downstream_loss {
        if hop_loss > 15.0 && dl < 5.0 {
            return Some(RateLimitInfo {
                suspected: true,
                confidence: 0.85,
                reason: Some(format!(
                    "{:.0}% loss here but {:.0}% downstream - packets aren't being dropped",
                    hop_loss, dl
                )),
                hop_loss,
                downstream_loss: Some(dl),
            });
        }
    }

    // Check 2: Uniform loss across all flows (Paris/Dublin traceroute)
    // If all flows lose equally, it's hop-level rate limiting, not path diversity
    if hop.flow_paths.len() >= 2 {
        if is_uniform_flow_loss(hop) {
            return Some(RateLimitInfo {
                suspected: true,
                confidence: 0.75,
                reason: Some("All flows showing equal loss (rate limit, not path issue)".into()),
                hop_loss,
                downstream_loss,
            });
        }
    }

    // Check 3: Consistent loss ratio over time
    // Rate limiting produces stable loss; real congestion fluctuates
    if is_stable_loss_ratio(&hop.recent_results) && hop_loss > 10.0 {
        return Some(RateLimitInfo {
            suspected: true,
            confidence: 0.6,
            reason: Some("Stable loss ratio suggests rate limiting".into()),
            hop_loss,
            downstream_loss,
        });
    }

    None
}

/// Find loss percentage of next hop that has responses
fn find_next_responding_hop_loss(session: &Session, ttl: u8) -> Option<f64> {
    for next_ttl in (ttl + 1)..=session.hops.len() as u8 {
        if let Some(hop) = session.hop(next_ttl) {
            // Need some completed probes to calculate meaningful loss
            let completed = hop.received + hop.timeouts;
            if hop.received > 0 && completed >= 5 {
                return Some(hop.loss_pct());
            }
        }
    }
    None
}

/// Check if all flows have similar loss percentage
fn is_uniform_flow_loss(hop: &Hop) -> bool {
    if hop.flow_paths.len() < 2 {
        return false;
    }

    let losses: Vec<f64> = hop.flow_paths.values()
        .filter(|fp| fp.sent >= 5) // Need enough samples
        .map(|fp| {
            let completed = fp.received + fp.timeouts;
            if completed > 0 {
                (fp.timeouts as f64 / completed as f64) * 100.0
            } else {
                0.0
            }
        })
        .collect();

    if losses.len() < 2 {
        return false;
    }

    // Check if there's significant loss (at least one flow with > 5% loss)
    if losses.iter().all(|&l| l < 5.0) {
        return false;
    }

    // Calculate standard deviation
    let mean = losses.iter().sum::<f64>() / losses.len() as f64;
    let variance = losses.iter()
        .map(|&l| (l - mean).powi(2))
        .sum::<f64>() / losses.len() as f64;
    let stddev = variance.sqrt();

    // Low standard deviation = uniform loss across flows
    // Threshold: stddev < 5% means flows are losing at similar rates
    stddev < 5.0
}

/// Check if loss ratio is stable (low variance over recent window)
fn is_stable_loss_ratio(recent: &VecDeque<bool>) -> bool {
    if recent.len() < 20 {
        return false;
    }

    // Split into three parts and compare loss ratios
    let len = recent.len();
    let third = len / 3;

    let first_loss = recent.iter().take(third)
        .filter(|&&r| !r).count() as f64 / third as f64;
    let second_loss = recent.iter().skip(third).take(third)
        .filter(|&&r| !r).count() as f64 / third as f64;
    let third_loss = recent.iter().skip(2 * third)
        .filter(|&&r| !r).count() as f64 / third as f64;

    // Calculate max difference between any two periods
    let max_diff = (first_loss - second_loss).abs()
        .max((second_loss - third_loss).abs())
        .max((first_loss - third_loss).abs());

    // Stable if all periods have similar loss (within 10%)
    max_diff < 0.10
}

/// Background worker that periodically analyzes sessions for rate limiting
pub async fn run_ratelimit_worker(
    sessions: SessionMap,
    cancel: CancellationToken,
) {
    // Run analysis every 2 seconds (doesn't need to be faster since loss
    // patterns take time to develop)
    let mut interval = tokio::time::interval(Duration::from_secs(2));

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                break;
            }
            _ = interval.tick() => {
                // Analyze all sessions
                let sessions = sessions.read();
                for session_lock in sessions.values() {
                    let mut session = session_lock.write();
                    analyze_rate_limiting(&mut session);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stable_loss_ratio_empty() {
        let recent = VecDeque::new();
        assert!(!is_stable_loss_ratio(&recent));
    }

    #[test]
    fn test_stable_loss_ratio_too_few() {
        let mut recent = VecDeque::new();
        for _ in 0..10 {
            recent.push_back(true);
        }
        assert!(!is_stable_loss_ratio(&recent));
    }

    #[test]
    fn test_stable_loss_ratio_stable() {
        let mut recent = VecDeque::new();
        // 50% loss consistently
        for i in 0..30 {
            recent.push_back(i % 2 == 0);
        }
        assert!(is_stable_loss_ratio(&recent));
    }

    #[test]
    fn test_stable_loss_ratio_varying() {
        let mut recent = VecDeque::new();
        // First third: 100% success
        for _ in 0..10 {
            recent.push_back(true);
        }
        // Second third: 50% loss
        for i in 0..10 {
            recent.push_back(i % 2 == 0);
        }
        // Third third: 100% success
        for _ in 0..10 {
            recent.push_back(true);
        }
        assert!(!is_stable_loss_ratio(&recent));
    }
}
