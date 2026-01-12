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

            // FIRST: Drain all pending packets from socket before timeout cleanup
            // This prevents dropping responses that are already queued in the buffer
            loop {
                match recv_icmp(&socket, &mut buffer) {
                    Ok((len, responder)) => {
                        if let Some(parsed) =
                            parse_icmp_response(&buffer[..len], responder, identifier)
                        {
                            // Find matching pending probe in shared map
                            let probe = self.pending.write().remove(&parsed.probe_id);
                            if let Some(probe) = probe {
                                let rtt = Instant::now().duration_since(probe.sent_at);

                                // Update state
                                let mut state = self.state.write();
                                if let Some(hop) = state.hop_mut(parsed.probe_id.ttl) {
                                    hop.record_response_with_mpls(
                                        parsed.responder,
                                        rtt,
                                        parsed.mpls_labels,
                                    );
                                }

                                // Check if we reached the destination
                                if matches!(parsed.response_type, IcmpResponseType::EchoReply) {
                                    if parsed.responder == probe.target {
                                        state.complete = true;
                                        // Track the lowest TTL that reached the destination
                                        let ttl = parsed.probe_id.ttl;
                                        if state.dest_ttl.is_none() || ttl < state.dest_ttl.unwrap()
                                        {
                                            state.dest_ttl = Some(ttl);
                                        }
                                    }
                                }
                            } else {
                                // Late packet arrival - response came after timeout
                                #[cfg(debug_assertions)]
                                eprintln!(
                                    "Late response: TTL {} seq {} from {} (already timed out)",
                                    parsed.probe_id.ttl, parsed.probe_id.seq, parsed.responder
                                );
                            }
                        }
                    }
                    Err(e) => {
                        // WouldBlock/TimedOut means socket is drained, exit inner loop
                        let is_timeout = e.downcast_ref::<std::io::Error>().is_some_and(|io| {
                            io.kind() == std::io::ErrorKind::WouldBlock
                                || io.kind() == std::io::ErrorKind::TimedOut
                        });

                        if !is_timeout {
                            eprintln!("Receive error: {}", e);
                        }
                        break; // Exit inner loop, proceed to timeout cleanup
                    }
                }
            }

            // THEN: Clean up timed out probes from shared pending map
            // This runs after draining the socket, so queued responses aren't lost
            {
                let now = Instant::now();
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

        // Catch panics and convert to error with details
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            receiver.run_blocking()
        })) {
            Ok(result) => result,
            Err(panic_payload) => {
                let msg = if let Some(s) = panic_payload.downcast_ref::<&str>() {
                    s.to_string()
                } else if let Some(s) = panic_payload.downcast_ref::<String>() {
                    s.clone()
                } else {
                    "unknown panic".to_string()
                };
                Err(anyhow::anyhow!("Receiver panicked: {}", msg))
            }
        }
    })
}
