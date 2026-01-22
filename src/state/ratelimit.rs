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
//!
//! ## Last-Hop Behavior
//!
//! The "isolated hop loss" heuristic (Check 1) requires a downstream hop for
//! comparison. At the final hop (destination), there's no downstream to compare
//! against, so this check won't trigger. This is intentional: high "loss" at
//! the destination is often legitimate (destination may not respond to all
//! probe types, firewall filtering, etc.) rather than rate limiting.

use std::collections::VecDeque;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

use super::session::{Hop, RateLimitInfo, Session};
use crate::trace::receiver::SessionMap;

/// Analyze a session for rate limit indicators at all hops
pub fn analyze_rate_limiting(session: &mut Session) {
    let hop_count = session.hops.len();

    // Collect detection results and downstream loss first to avoid borrow issues
    let results: Vec<(u8, Option<RateLimitInfo>, Option<f64>)> = (1..=hop_count as u8)
        .map(|ttl| {
            let downstream = find_next_responding_hop_loss(session, ttl);
            (ttl, detect_rate_limiting(session, ttl), downstream)
        })
        .collect();

    // Apply results with hysteresis for clearing
    for (ttl, info, downstream_loss) in results {
        if let Some(hop) = session.hop_mut(ttl) {
            if let Some(new_info) = info {
                // Detection matched: reset negative checks and update info
                hop.rate_limit = Some(new_info);
            } else {
                // Heuristics didn't match - increment negative check counter if RL was detected
                // Calculate values before mutable borrow
                let completed = hop.received + hop.timeouts;
                let hop_loss = hop.loss_pct();
                let downstream_high = downstream_loss.is_some_and(|dl| dl >= 10.0);

                if let Some(existing) = &mut hop.rate_limit {
                    existing.negative_checks = existing.negative_checks.saturating_add(1);

                    // Clear RL when:
                    // 1. After 2 negatives AND (loss < 5% OR downstream >= 10%), OR
                    // 2. After 5 negatives regardless (signal is gone if heuristics stop matching)
                    let quick_clear = existing.negative_checks >= 2
                        && completed > 20
                        && (hop_loss < 5.0 || downstream_high);
                    let force_clear = existing.negative_checks >= 5 && completed > 20;

                    if quick_clear || force_clear {
                        hop.rate_limit = None;
                    }
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
    if let Some(dl) = downstream_loss
        && hop_loss > 15.0
        && dl < 5.0
    {
        return Some(RateLimitInfo {
            suspected: true,
            confidence: 0.85,
            reason: Some(format!(
                "{:.0}% loss here but {:.0}% downstream - packets aren't being dropped",
                hop_loss, dl
            )),
            hop_loss,
            downstream_loss: Some(dl),
            negative_checks: 0,
        });
    }

    // Check 2: Uniform loss across all flows (Paris/Dublin traceroute)
    // If all flows lose equally, it's hop-level rate limiting, not path diversity
    if hop.flow_paths.len() >= 2 && is_uniform_flow_loss(hop) {
        return Some(RateLimitInfo {
            suspected: true,
            confidence: 0.75,
            reason: Some("All flows showing equal loss (rate limit, not path issue)".into()),
            hop_loss,
            downstream_loss,
            negative_checks: 0,
        });
    }

    // Check 3: Consistent loss ratio over time
    // Rate limiting produces stable loss; real congestion fluctuates
    // Use recent window loss (not lifetime) to avoid sticky detection during recovery
    let recent_loss = calculate_recent_loss(&hop.recent_results);
    if is_stable_loss_ratio(&hop.recent_results) && recent_loss > 10.0 {
        return Some(RateLimitInfo {
            suspected: true,
            confidence: 0.6,
            reason: Some("Stable loss ratio suggests rate limiting".into()),
            hop_loss,
            downstream_loss,
            negative_checks: 0,
        });
    }

    None
}

/// Calculate loss percentage from recent results window
fn calculate_recent_loss(recent: &VecDeque<bool>) -> f64 {
    if recent.is_empty() {
        return 0.0;
    }
    let losses = recent.iter().filter(|&&r| !r).count();
    (losses as f64 / recent.len() as f64) * 100.0
}

/// Find loss percentage of next hop that has responses.
/// Returns None if no downstream hop has enough data (including for the last hop,
/// which affects rate limit detection - last hop can't be confirmed as rate-limited).
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

    let losses: Vec<f64> = hop
        .flow_paths
        .values()
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
    let variance = losses.iter().map(|&l| (l - mean).powi(2)).sum::<f64>() / losses.len() as f64;
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
    // Handle remainder by giving it to the third segment
    let len = recent.len();
    let seg1_len = len / 3;
    let seg2_len = len / 3;
    let seg3_len = len - seg1_len - seg2_len; // Gets any remainder

    let first_loss = recent.iter().take(seg1_len).filter(|&&r| !r).count() as f64 / seg1_len as f64;
    let second_loss = recent
        .iter()
        .skip(seg1_len)
        .take(seg2_len)
        .filter(|&&r| !r)
        .count() as f64
        / seg2_len as f64;
    let third_loss = recent
        .iter()
        .skip(seg1_len + seg2_len)
        .filter(|&&r| !r)
        .count() as f64
        / seg3_len as f64;

    // Calculate max difference between any two periods
    let max_diff = (first_loss - second_loss)
        .abs()
        .max((second_loss - third_loss).abs())
        .max((first_loss - third_loss).abs());

    // Stable if all periods have similar loss (within 10%)
    max_diff < 0.10
}

/// Background worker that periodically analyzes sessions for rate limiting
pub async fn run_ratelimit_worker(sessions: SessionMap, cancel: CancellationToken) {
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

    #[test]
    fn test_stable_loss_ratio_non_divisible_length() {
        // Test with length not divisible by 3 (e.g., 32)
        // Should still detect stable loss correctly
        let mut recent = VecDeque::new();
        // 50% loss consistently across 32 samples
        for i in 0..32 {
            recent.push_back(i % 2 == 0);
        }
        assert!(is_stable_loss_ratio(&recent));

        // Test with 25 samples (segments: 8, 8, 9)
        let mut recent2 = VecDeque::new();
        for i in 0..25 {
            recent2.push_back(i % 2 == 0);
        }
        assert!(is_stable_loss_ratio(&recent2));
    }

    #[test]
    fn test_calculate_recent_loss() {
        // Empty window
        let empty: VecDeque<bool> = VecDeque::new();
        assert_eq!(calculate_recent_loss(&empty), 0.0);

        // All success (true = success, false = loss)
        let mut all_success = VecDeque::new();
        for _ in 0..10 {
            all_success.push_back(true);
        }
        assert_eq!(calculate_recent_loss(&all_success), 0.0);

        // All loss
        let mut all_loss = VecDeque::new();
        for _ in 0..10 {
            all_loss.push_back(false);
        }
        assert_eq!(calculate_recent_loss(&all_loss), 100.0);

        // 50% loss
        let mut half_loss = VecDeque::new();
        for i in 0..10 {
            half_loss.push_back(i % 2 == 0); // true, false, true, false...
        }
        assert_eq!(calculate_recent_loss(&half_loss), 50.0);
    }
}
