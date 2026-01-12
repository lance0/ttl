use anyhow::Result;
use parking_lot::RwLock;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

use crate::probe::{create_recv_socket, get_identifier, parse_icmp_response, recv_icmp};
use crate::state::{IcmpResponseType, Session};
use crate::trace::pending::PendingMap;

/// The receiver listens for ICMP responses and correlates them to probes
pub struct Receiver {
    state: Arc<RwLock<Session>>,
    pending: PendingMap,
    cancel: CancellationToken,
    timeout: Duration,
    ipv6: bool,
}

impl Receiver {
    pub fn new(
        state: Arc<RwLock<Session>>,
        pending: PendingMap,
        cancel: CancellationToken,
        timeout: Duration,
        ipv6: bool,
    ) -> Self {
        Self {
            state,
            pending,
            cancel,
            timeout,
            ipv6,
        }
    }

    /// Run the receiver on a dedicated thread (blocking I/O)
    pub fn run_blocking(self) -> Result<()> {
        let identifier = get_identifier();
        let socket = create_recv_socket(self.ipv6)?;

        // Set non-blocking with short timeout for polling
        socket.set_read_timeout(Some(Duration::from_millis(100)))?;

        let mut buffer = [0u8; 1500];

        loop {
            // Check cancellation
            if self.cancel.is_cancelled() {
                break;
            }

            let now = Instant::now();

            // Clean up timed out probes from shared pending map
            {
                let mut pending = self.pending.write();
                let timeout = self.timeout;
                pending.retain(|id, probe| {
                    if now.duration_since(probe.sent_at) > timeout {
                        // Record timeout
                        let mut state = self.state.write();
                        if let Some(hop) = state.hop_mut(id.ttl) {
                            hop.record_timeout();
                        }
                        false
                    } else {
                        true
                    }
                });
            }

            // Try to receive a packet
            match recv_icmp(&socket, &mut buffer) {
                Ok((len, responder)) => {
                    if let Some(parsed) = parse_icmp_response(&buffer[..len], responder, identifier)
                    {
                        // Find matching pending probe in shared map
                        let probe = self.pending.write().remove(&parsed.probe_id);
                        if let Some(probe) = probe {
                            let rtt = Instant::now().duration_since(probe.sent_at);

                            // Update state
                            let mut state = self.state.write();
                            if let Some(hop) = state.hop_mut(parsed.probe_id.ttl) {
                                hop.record_response(parsed.responder, rtt);
                            }

                            // Check if we reached the destination
                            if matches!(parsed.response_type, IcmpResponseType::EchoReply) {
                                if parsed.responder == probe.target {
                                    state.complete = true;
                                    // Track the lowest TTL that reached the destination
                                    let ttl = parsed.probe_id.ttl;
                                    if state.dest_ttl.is_none() || ttl < state.dest_ttl.unwrap() {
                                        state.dest_ttl = Some(ttl);
                                    }
                                }
                            }
                        } else {
                            // Late packet arrival - response came after timeout
                            // This is common with high-latency or congested paths
                            #[cfg(debug_assertions)]
                            eprintln!(
                                "Late response: TTL {} seq {} from {} (already timed out)",
                                parsed.probe_id.ttl,
                                parsed.probe_id.seq,
                                parsed.responder
                            );
                        }
                    }
                }
                Err(e) => {
                    // Timeout is expected, other errors log
                    let is_timeout = e
                        .downcast_ref::<std::io::Error>()
                        .is_some_and(|io| io.kind() == std::io::ErrorKind::WouldBlock
                            || io.kind() == std::io::ErrorKind::TimedOut);

                    if !is_timeout {
                        eprintln!("Receive error: {}", e);
                    }
                }
            }
        }

        Ok(())
    }
}

/// Spawn the receiver on a dedicated OS thread
pub fn spawn_receiver(
    state: Arc<RwLock<Session>>,
    pending: PendingMap,
    cancel: CancellationToken,
    timeout: Duration,
    ipv6: bool,
) -> std::thread::JoinHandle<Result<()>> {
    std::thread::spawn(move || {
        let receiver = Receiver::new(state, pending, cancel, timeout, ipv6);
        receiver.run_blocking()
    })
}
