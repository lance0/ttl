use anyhow::Result;
use parking_lot::RwLock;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::config::Config;
use crate::probe::{build_echo_request, create_send_socket, get_identifier, send_icmp, set_ttl};
use crate::state::{ProbeId, Session};
use crate::trace::pending::{PendingMap, PendingProbe};

/// The probe engine sends ICMP probes at configured intervals
pub struct ProbeEngine {
    config: Config,
    target: IpAddr,
    identifier: u16,
    state: Arc<RwLock<Session>>,
    pending: PendingMap,
    cancel: CancellationToken,
}

impl ProbeEngine {
    pub fn new(
        config: Config,
        target: IpAddr,
        state: Arc<RwLock<Session>>,
        pending: PendingMap,
        cancel: CancellationToken,
    ) -> Self {
        Self {
            config,
            target,
            identifier: get_identifier(),
            state,
            pending,
            cancel,
        }
    }

    /// Run the probe engine
    pub async fn run(self) -> Result<()> {
        let ipv6 = self.target.is_ipv6();
        let socket = create_send_socket(ipv6)?;

        let mut seq: u8 = 0;
        let mut total_sent: u64 = 0;
        let mut interval = tokio::time::interval(self.config.interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                _ = self.cancel.cancelled() => {
                    break;
                }
                _ = interval.tick() => {
                    // Check if paused
                    {
                        let state = self.state.read();
                        if state.paused {
                            continue;
                        }
                    }

                    // Check probe count limit
                    if let Some(count) = self.config.count {
                        if total_sent >= count * self.config.max_ttl as u64 {
                            // Signal completion
                            self.cancel.cancel();
                            break;
                        }
                    }

                    // Determine max TTL to probe (stop at destination if known)
                    let max_probe_ttl = {
                        let state = self.state.read();
                        state.dest_ttl.unwrap_or(self.config.max_ttl)
                    };

                    // Send probes for TTLs up to the destination
                    for ttl in 1..=max_probe_ttl {
                        let should_probe = {
                            let state = self.state.read();
                            // Probe if we haven't completed, or if this TTL has responded before
                            !state.complete || state.hop(ttl).is_some_and(|h| h.received > 0)
                        };

                        if !should_probe {
                            continue;
                        }

                        let probe_id = ProbeId::new(ttl, seq);
                        let packet = build_echo_request(self.identifier, probe_id.to_sequence());

                        // Set TTL before sending
                        if let Err(e) = set_ttl(&socket, ttl) {
                            eprintln!("Failed to set TTL {}: {}", ttl, e);
                            continue;
                        }

                        let sent_at = Instant::now();

                        // Register pending BEFORE sending to prevent race with fast responses
                        {
                            let mut pending = self.pending.write();
                            pending.insert(probe_id, PendingProbe {
                                sent_at,
                                target: self.target,
                            });
                        }

                        if let Err(e) = send_icmp(&socket, &packet, self.target) {
                            // Remove pending entry on send failure to avoid false timeouts
                            self.pending.write().remove(&probe_id);
                            eprintln!("Failed to send probe TTL {}: {}", ttl, e);
                            continue;
                        }

                        // Record that we sent a probe
                        {
                            let mut state = self.state.write();
                            if let Some(hop) = state.hop_mut(ttl) {
                                hop.record_sent();
                            }
                            state.total_sent += 1;
                        }

                        total_sent += 1;
                    }

                    seq = seq.wrapping_add(1);
                }
            }
        }

        Ok(())
    }
}

/// Create interval from config
#[allow(dead_code)]
pub fn create_probe_interval(config: &Config) -> tokio::time::Interval {
    let mut interval = tokio::time::interval(config.interval);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    interval
}
