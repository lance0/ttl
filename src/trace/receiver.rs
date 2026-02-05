use anyhow::Result;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

use crate::probe::{
    InterfaceInfo, create_recv_socket_with_interface, get_identifier, parse_icmp_response,
    recv_icmp_with_ttl,
};
use crate::state::{
    IcmpResponseType, MplsLabel, PmtudPhase, ProbeEvent, ProbeId, ProbeOutcome, Session,
};
use crate::trace::pending::PendingMap;

/// Map of target IP to session, shared across multiple engines and the receiver
pub type SessionMap = Arc<RwLock<HashMap<IpAddr, Arc<RwLock<Session>>>>>;

/// Configuration for the ICMP receiver
#[derive(Clone)]
pub struct ReceiverConfig {
    /// Probe timeout duration
    pub timeout: Duration,
    /// Whether targets are IPv6
    pub ipv6: bool,
    /// Base source port for flow identification (Paris/Dublin traceroute)
    pub src_port_base: u16,
    /// Number of flows for multi-path ECMP detection
    pub num_flows: u8,
    /// Network interface to bind receiver socket to
    pub interface: Option<InterfaceInfo>,
    /// Don't bind receiver to interface (for asymmetric routing)
    pub recv_any: bool,
}

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
    /// Packet size for PMTUD correlation (if this was a PMTUD probe)
    packet_size: Option<u16>,
    /// MTU from ICMP Frag Needed / Packet Too Big (for PMTUD)
    reported_mtu: Option<u16>,
    /// TTL/hop-limit from the response IP header (for asymmetry detection)
    response_ttl: Option<u8>,
    /// Quoted TTL from ICMP error payload (for TTL manipulation detection)
    quoted_ttl: Option<u8>,
}

/// The receiver listens for ICMP responses and correlates them to probes
pub struct Receiver {
    sessions: SessionMap,
    pending: PendingMap,
    cancel: CancellationToken,
    config: ReceiverConfig,
    consecutive_errors: u32,
    /// List of target IPs for probe lookup (cached from sessions keys)
    targets: Vec<IpAddr>,
}

impl Receiver {
    pub fn new(
        sessions: SessionMap,
        pending: PendingMap,
        cancel: CancellationToken,
        config: ReceiverConfig,
    ) -> Self {
        // Cache target list for probe lookup
        let targets: Vec<IpAddr> = sessions.read().keys().cloned().collect();
        Self {
            sessions,
            pending,
            cancel,
            config,
            consecutive_errors: 0,
            targets,
        }
    }

    /// Run the receiver on a dedicated thread (blocking I/O)
    pub fn run_blocking(mut self) -> Result<()> {
        let identifier = get_identifier();
        // Skip interface binding if recv_any is set (allows asymmetric routing)
        let effective_interface = if self.config.recv_any {
            None
        } else {
            self.config.interface.as_ref()
        };
        let socket_info = create_recv_socket_with_interface(self.config.ipv6, effective_interface)?;
        let is_dgram = socket_info.is_dgram;
        let socket = socket_info.socket;

        // Set non-blocking with short timeout for polling
        socket.set_read_timeout(Some(Duration::from_millis(100)))?;

        let mut buffer = [0u8; 9216];

        loop {
            // FIRST: Drain packets from socket into batch (limited to prevent starvation)
            // This prevents dropping responses that are already queued in the buffer
            let mut batch: Vec<BatchedResponse> = Vec::with_capacity(MAX_DRAIN_BATCH);
            let mut batch_count = 0;

            loop {
                // Limit batch size to yield to timeout cleanup
                if batch_count >= MAX_DRAIN_BATCH {
                    break;
                }

                match recv_icmp_with_ttl(&socket, &mut buffer, self.config.ipv6) {
                    Ok(recv_result) => {
                        // Reset consecutive error count on successful receive
                        self.consecutive_errors = 0;
                        batch_count += 1;

                        if let Some(parsed) = parse_icmp_response(
                            &buffer[..recv_result.len],
                            recv_result.source,
                            identifier,
                            is_dgram,
                        ) {
                            // Derive flow_id from source port in ICMP error payload
                            // For UDP/TCP: src_port = src_port_base + flow_id
                            // For ICMP: src_port is None, flow_id = 0
                            // Validate range to avoid mis-attribution from NAT rewrites or unrelated errors
                            let flow_id = parsed
                                .src_port
                                .and_then(|p| {
                                    if p >= self.config.src_port_base
                                        && p < self.config.src_port_base
                                            + self.config.num_flows as u16
                                    {
                                        Some((p - self.config.src_port_base) as u8)
                                    } else {
                                        // Port outside expected range - treat as ICMP (flow 0)
                                        None
                                    }
                                })
                                .unwrap_or(0);

                            // Find matching pending probe (key includes flow_id, target, is_pmtud)
                            let mut found_probe = None;
                            {
                                let mut pending = self.pending.write();

                                // If we have original_dest from ICMP error, use direct lookup
                                if let Some(dest) = parsed.original_dest {
                                    // Try normal probe first
                                    if let Some(probe) =
                                        pending.remove(&(parsed.probe_id, flow_id, dest, false))
                                    {
                                        found_probe = Some(probe);
                                    } else if let Some(probe) =
                                        pending.remove(&(parsed.probe_id, flow_id, dest, true))
                                    {
                                        // Try PMTUD probe
                                        found_probe = Some(probe);
                                    }
                                }

                                // Fallback: iterate targets (for Echo Reply which has no quoted dest)
                                if found_probe.is_none() {
                                    for target in &self.targets {
                                        // Try normal probe first
                                        if let Some(probe) = pending.remove(&(
                                            parsed.probe_id,
                                            flow_id,
                                            *target,
                                            false,
                                        )) {
                                            found_probe = Some(probe);
                                            break;
                                        }
                                        // Try PMTUD probe
                                        if let Some(probe) = pending.remove(&(
                                            parsed.probe_id,
                                            flow_id,
                                            *target,
                                            true,
                                        )) {
                                            found_probe = Some(probe);
                                            break;
                                        }
                                    }
                                }
                            }
                            if let Some(probe) = found_probe {
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
                                    packet_size: probe.packet_size,
                                    reported_mtu: parsed.mtu,
                                    response_ttl: recv_result.response_ttl,
                                    quoted_ttl: parsed.quoted_ttl,
                                });
                            } else {
                                // Late packet arrival - response came after timeout
                                // Record as LateReply for replay accuracy
                                if let Some(target) = parsed.original_dest {
                                    let sessions = self.sessions.read();
                                    if let Some(session_lock) = sessions.get(&target) {
                                        let mut state = session_lock.write();
                                        let offset_ms = state.offset_ms();
                                        state.record_event(ProbeEvent {
                                            offset_ms,
                                            ttl: parsed.probe_id.ttl,
                                            seq: parsed.probe_id.seq,
                                            flow_id,
                                            outcome: ProbeOutcome::LateReply {
                                                addr: parsed.responder,
                                                rtt_us: 0, // RTT unknown for late arrivals
                                            },
                                        });
                                    }
                                }
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

            // SECOND: Apply all batched state updates
            if !batch.is_empty() {
                let sessions = self.sessions.read();
                for resp in batch {
                    // Look up the session for this target
                    if let Some(session) = sessions.get(&resp.target) {
                        let mut state = session.write();
                        let is_pmtud_probe = resp.packet_size.is_some();

                        // Only record hop responses for normal probes, not PMTUD probes
                        // PMTUD probes are for MTU discovery, not traceroute measurements
                        if !is_pmtud_probe {
                            if let Some(hop) = state.hop_mut(resp.probe_id.ttl) {
                                // Record aggregate stats with optional flap detection
                                // Only detect flaps in single-flow mode (multi-flow expects path changes)
                                if self.config.num_flows == 1 {
                                    hop.record_response_detecting_flaps(
                                        resp.responder,
                                        resp.rtt,
                                        resp.mpls_labels.clone(),
                                    );
                                } else {
                                    hop.record_response_with_mpls(
                                        resp.responder,
                                        resp.rtt,
                                        resp.mpls_labels.clone(),
                                    );
                                }
                                // Record per-flow stats for Paris/Dublin traceroute ECMP detection
                                hop.record_flow_response(resp.flow_id, resp.responder, resp.rtt);
                                // Record NAT detection result (compare sent vs returned source port)
                                hop.record_nat_check(
                                    resp.original_src_port,
                                    resp.returned_src_port,
                                );
                                // Asymmetric routing detection (single-flow mode only, like flap detection)
                                if self.config.num_flows == 1
                                    && let Some(ttl) = resp.response_ttl
                                {
                                    hop.record_response_ttl(ttl, self.config.ipv6);
                                }

                                // TTL manipulation detection (TimeExceeded code 0 only, all flow modes)
                                // Code 0 = TTL exceeded in transit, Code 1 = fragment reassembly exceeded
                                // Only code 0 is relevant for TTL manipulation - code 1 can have quoted TTL > 1
                                if matches!(resp.response_type, IcmpResponseType::TimeExceeded(0))
                                    && let Some(quoted) = resp.quoted_ttl
                                {
                                    hop.record_ttl_manip_check(quoted);
                                }
                            }

                            // Record event for animated replay (monotonic timing)
                            let offset_ms = state.offset_ms();
                            state.record_event(ProbeEvent {
                                offset_ms,
                                ttl: resp.probe_id.ttl,
                                seq: resp.probe_id.seq,
                                flow_id: resp.flow_id,
                                outcome: ProbeOutcome::Reply {
                                    addr: resp.responder,
                                    rtt_us: resp.rtt.as_micros() as u64,
                                },
                            });
                        }

                        // Check if we reached the destination
                        if matches!(resp.response_type, IcmpResponseType::EchoReply)
                            && resp.responder == resp.target
                        {
                            state.complete = true;
                            let ttl = resp.probe_id.ttl;
                            if state.dest_ttl.is_none_or(|d| ttl < d) {
                                state.dest_ttl = Some(ttl);
                            }
                        }

                        // PMTUD: Update state if this was a PMTUD probe
                        // Verify packet_size matches current_size to ignore late responses from old sizes
                        if let Some(probe_size) = resp.packet_size
                            && let Some(ref mut pmtud) = state.pmtud
                            && pmtud.phase == PmtudPhase::Searching
                            && probe_size == pmtud.current_size
                        {
                            // Check if this is Fragmentation Needed / Packet Too Big
                            let is_frag_needed = matches!(
                                resp.response_type,
                                IcmpResponseType::DestUnreachable(4)  // IPv4 Frag Needed
                                    | IcmpResponseType::PacketTooBig // ICMPv6 Packet Too Big
                            );

                            if is_frag_needed {
                                // ICMP Frag Needed - use reported MTU if available
                                if let Some(mtu) = resp.reported_mtu {
                                    pmtud.record_frag_needed(mtu);
                                } else {
                                    // No MTU in response - treat as failure
                                    pmtud.record_failure();
                                }
                            } else {
                                // Any other response = success at this size
                                // (EchoReply, TimeExceeded, PortUnreachable, etc.)
                                pmtud.record_success();
                            }
                        }
                    }
                }
            }

            // Check cancellation AFTER draining socket, so queued responses aren't lost
            if self.cancel.is_cancelled() {
                // Flush remaining pending probes as timeouts before exiting
                self.flush_pending_as_timeouts();
                break;
            }

            // THEN: Clean up timed out probes from shared pending map
            // This runs after draining the socket, so queued responses aren't lost
            {
                let now = Instant::now();
                let mut pending = self.pending.write();
                let sessions = self.sessions.read();
                let timeout = self.config.timeout;
                // Key is (ProbeId, flow_id, target, is_pmtud) tuple
                pending.retain(|(probe_id, _flow_id, target, _is_pmtud), probe| {
                    if now.duration_since(probe.sent_at) > timeout {
                        let is_pmtud_probe = probe.packet_size.is_some();

                        if let Some(session) = sessions.get(target) {
                            let mut state = session.write();

                            // Only record hop timeouts for normal probes, not PMTUD probes
                            if !is_pmtud_probe {
                                if let Some(hop) = state.hop_mut(probe_id.ttl) {
                                    hop.record_timeout();
                                    hop.record_flow_timeout(probe.flow_id);
                                }

                                // Record event for animated replay (monotonic timing)
                                let offset_ms = state.offset_ms();
                                state.record_event(ProbeEvent {
                                    offset_ms,
                                    ttl: probe_id.ttl,
                                    seq: probe_id.seq,
                                    flow_id: probe.flow_id,
                                    outcome: ProbeOutcome::Timeout,
                                });
                            }

                            // PMTUD: Record failure for timed out PMTUD probes
                            // Verify packet_size matches current_size to ignore late timeouts from old sizes
                            if let Some(probe_size) = probe.packet_size
                                && let Some(ref mut pmtud) = state.pmtud
                                && pmtud.phase == PmtudPhase::Searching
                                && probe_size == pmtud.current_size
                            {
                                pmtud.record_failure();
                            }
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

    /// Flush all remaining pending probes as timeouts on shutdown.
    fn flush_pending_as_timeouts(&self) {
        let mut pending = self.pending.write();
        let sessions = self.sessions.read();

        // Drain all remaining probes and record them as timeouts
        for ((probe_id, _flow_id, target, is_pmtud), probe) in pending.drain() {
            if let Some(session) = sessions.get(&target) {
                let mut state = session.write();

                // Only record hop timeouts for normal probes, not PMTUD probes
                if !is_pmtud && let Some(hop) = state.hop_mut(probe_id.ttl) {
                    hop.record_timeout();
                    hop.record_flow_timeout(probe.flow_id);
                }
            }
        }
    }
}

/// Spawn the receiver on a dedicated OS thread
pub fn spawn_receiver(
    sessions: SessionMap,
    pending: PendingMap,
    cancel: CancellationToken,
    config: ReceiverConfig,
) -> std::thread::JoinHandle<Result<()>> {
    std::thread::spawn(move || {
        let receiver = Receiver::new(sessions, pending, cancel, config);

        // Catch panics and convert to error with details
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| receiver.run_blocking())) {
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
