use anyhow::Result;
use parking_lot::RwLock;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

use crate::probe::{create_recv_socket, get_identifier, parse_icmp_response, recv_icmp};
use crate::state::{IcmpResponseType, MplsLabel, ProbeId, Session};
use crate::trace::pending::PendingMap;

/// Maximum consecutive errors before stopping the receiver
const MAX_CONSECUTIVE_ERRORS: u32 = 50;

/// Maximum packets to drain per iteration before yielding to timeout cleanup
/// Prevents starvation at high packet rates
const MAX_DRAIN_BATCH: usize = 100;

/// Collected response data for batched state updates
struct BatchedResponse {
    probe_id: ProbeId,
    responder: IpAddr,
    rtt: Duration,
    mpls_labels: Option<Vec<MplsLabel>>,
    response_type: IcmpResponseType,
    target: IpAddr,
    /// Flow ID for Paris/Dublin traceroute ECMP detection
    flow_id: u8,
    /// Original source port from pending probe (for NAT detection)
    original_src_port: Option<u16>,
    /// Returned source port from ICMP error payload (for NAT detection)
    returned_src_port: Option<u16>,
}

/// The receiver listens for ICMP responses and correlates them to probes
pub struct Receiver {
    state: Arc<RwLock<Session>>,
    pending: PendingMap,
    cancel: CancellationToken,
    timeout: Duration,
    ipv6: bool,
    consecutive_errors: u32,
    /// Base source port for calculating flow_id from response (Paris/Dublin traceroute)
    src_port_base: u16,
    /// Number of flows (for validating derived flow_id is in range)
    num_flows: u8,
}

impl Receiver {
    pub fn new(
        state: Arc<RwLock<Session>>,
        pending: PendingMap,
        cancel: CancellationToken,
        timeout: Duration,
        ipv6: bool,
        src_port_base: u16,
        num_flows: u8,
    ) -> Self {
        Self {
            state,
            pending,
            cancel,
            timeout,
            ipv6,
            consecutive_errors: 0,
            src_port_base,
            num_flows,
        }
    }

    /// Run the receiver on a dedicated thread (blocking I/O)
    pub fn run_blocking(mut self) -> Result<()> {
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

            // FIRST: Drain packets from socket into batch (limited to prevent starvation)
            // This prevents dropping responses that are already queued in the buffer
            let mut batch: Vec<BatchedResponse> = Vec::with_capacity(MAX_DRAIN_BATCH);
            let mut batch_count = 0;

            loop {
                // Limit batch size to yield to timeout cleanup
                if batch_count >= MAX_DRAIN_BATCH {
                    break;
                }

                match recv_icmp(&socket, &mut buffer) {
                    Ok((len, responder)) => {
                        // Reset consecutive error count on successful receive
                        self.consecutive_errors = 0;
                        batch_count += 1;

                        if let Some(parsed) =
                            parse_icmp_response(&buffer[..len], responder, identifier)
                        {
                            // Derive flow_id from source port in ICMP error payload
                            // For UDP/TCP: src_port = src_port_base + flow_id
                            // For ICMP: src_port is None, flow_id = 0
                            // Validate range to avoid mis-attribution from NAT rewrites or unrelated errors
                            let flow_id = parsed
                                .src_port
                                .and_then(|p| {
                                    if p >= self.src_port_base
                                        && p < self.src_port_base + self.num_flows as u16
                                    {
                                        Some((p - self.src_port_base) as u8)
                                    } else {
                                        // Port outside expected range - treat as ICMP (flow 0)
                                        None
                                    }
                                })
                                .unwrap_or(0);

                            // Find matching pending probe (key includes flow_id for multi-flow)
                            let probe = self.pending.write().remove(&(parsed.probe_id, flow_id));
                            if let Some(probe) = probe {
                                let rtt = Instant::now().duration_since(probe.sent_at);

                                // Collect for batched state update
                                batch.push(BatchedResponse {
                                    probe_id: parsed.probe_id,
                                    responder: parsed.responder,
                                    rtt,
                                    mpls_labels: parsed.mpls_labels,
                                    response_type: parsed.response_type,
                                    target: probe.target,
                                    flow_id: probe.flow_id,
                                    original_src_port: probe.original_src_port,
                                    returned_src_port: parsed.src_port,
                                });
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

                        if is_timeout {
                            // Normal timeout, reset error count and continue
                            self.consecutive_errors = 0;
                        } else {
                            // Real error, track consecutive failures
                            self.consecutive_errors += 1;
                            eprintln!(
                                "Receive error ({}/{}): {}",
                                self.consecutive_errors, MAX_CONSECUTIVE_ERRORS, e
                            );

                            if self.consecutive_errors >= MAX_CONSECUTIVE_ERRORS {
                                return Err(anyhow::anyhow!(
                                    "Receiver stopped: {} consecutive errors (last: {})",
                                    self.consecutive_errors,
                                    e
                                ));
                            }
                        }
                        break; // Exit inner loop, proceed to state update
                    }
                }
            }

            // SECOND: Apply all batched state updates with single lock acquisition
            if !batch.is_empty() {
                let mut state = self.state.write();
                for resp in batch {
                    if let Some(hop) = state.hop_mut(resp.probe_id.ttl) {
                        // Record aggregate stats (existing behavior)
                        hop.record_response_with_mpls(resp.responder, resp.rtt, resp.mpls_labels);
                        // Record per-flow stats for Paris/Dublin traceroute ECMP detection
                        hop.record_flow_response(resp.flow_id, resp.responder, resp.rtt);
                        // Record NAT detection result (compare sent vs returned source port)
                        hop.record_nat_check(resp.original_src_port, resp.returned_src_port);
                    }

                    // Check if we reached the destination
                    if matches!(resp.response_type, IcmpResponseType::EchoReply)
                        && resp.responder == resp.target
                    {
                        state.complete = true;
                        let ttl = resp.probe_id.ttl;
                        if state.dest_ttl.is_none() || ttl < state.dest_ttl.unwrap() {
                            state.dest_ttl = Some(ttl);
                        }
                    }
                }
            }

            // THEN: Clean up timed out probes from shared pending map
            // This runs after draining the socket, so queued responses aren't lost
            {
                let now = Instant::now();
                let mut pending = self.pending.write();
                let timeout = self.timeout;
                // Key is (ProbeId, flow_id) tuple
                pending.retain(|(probe_id, _flow_id), probe| {
                    if now.duration_since(probe.sent_at) > timeout {
                        // Record timeout (both hop-level and flow-level)
                        let mut state = self.state.write();
                        if let Some(hop) = state.hop_mut(probe_id.ttl) {
                            hop.record_timeout();
                            hop.record_flow_timeout(probe.flow_id);
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
    src_port_base: u16,
    num_flows: u8,
) -> std::thread::JoinHandle<Result<()>> {
    std::thread::spawn(move || {
        let receiver = Receiver::new(state, pending, cancel, timeout, ipv6, src_port_base, num_flows);

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
