use anyhow::Result;
use parking_lot::RwLock;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::config::{Config, ProbeProtocol};
use crate::probe::{
    build_echo_request, build_tcp_syn, build_udp_payload, create_send_socket,
    create_tcp_socket, create_udp_dgram_socket, create_udp_dgram_socket_bound,
    get_identifier, get_local_addr, send_icmp, send_tcp_probe, send_udp_probe, set_ttl,
};
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
        match self.config.protocol {
            ProbeProtocol::Auto => self.run_auto().await,
            ProbeProtocol::Icmp => self.run_icmp().await,
            ProbeProtocol::Udp => self.run_udp().await,
            ProbeProtocol::Tcp => self.run_tcp().await,
        }
    }

    /// Auto-detect working protocol: try ICMP, fallback to UDP, then TCP
    async fn run_auto(mut self) -> Result<()> {
        let ipv6 = self.target.is_ipv6();

        // Try ICMP first (most reliable, but requires raw sockets)
        if create_send_socket(ipv6).is_ok() {
            return self.run_icmp().await;
        }

        // Fallback to UDP (works with DGRAM sockets, less privileged)
        if create_udp_dgram_socket(ipv6).is_ok() {
            // Set default UDP port if not specified
            if self.config.port.is_none() {
                self.config.port = Some(33434);
            }
            return self.run_udp().await;
        }

        // Last resort: TCP (requires raw sockets but may work in some environments)
        if self.config.port.is_none() {
            self.config.port = Some(80);
        }
        self.run_tcp().await
    }

    /// Run ICMP probing mode
    async fn run_icmp(self) -> Result<()> {
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
                        // ICMP uses single flow (flow_id=0) - checksum trick not yet implemented
                        let flow_id = 0u8;
                        {
                            let mut pending = self.pending.write();
                            pending.insert((probe_id, flow_id), PendingProbe {
                                sent_at,
                                target: self.target,
                                flow_id,
                                original_src_port: None, // ICMP has no source port
                            });
                        }

                        if let Err(e) = send_icmp(&socket, &packet, self.target) {
                            // Remove pending entry on send failure to avoid false timeouts
                            self.pending.write().remove(&(probe_id, flow_id));
                            eprintln!("Failed to send probe TTL {}: {}", ttl, e);
                            continue;
                        }

                        // Record that we sent a probe
                        {
                            let mut state = self.state.write();
                            if let Some(hop) = state.hop_mut(ttl) {
                                hop.record_sent();
                                hop.record_flow_sent(0); // ICMP uses single flow (checksum trick not yet implemented)
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

    /// Run UDP probing mode
    async fn run_udp(self) -> Result<()> {
        let ipv6 = self.target.is_ipv6();
        let num_flows = self.config.flows;

        // Create sockets for each flow (Paris/Dublin traceroute multi-flow support)
        // Each socket is bound to a different source port for flow identification
        let mut sockets = Vec::with_capacity(num_flows as usize);
        for flow_id in 0..num_flows {
            let src_port = self.config.src_port_base + (flow_id as u16);
            let socket = create_udp_dgram_socket_bound(ipv6, src_port)?;
            sockets.push(socket);
        }

        // Base port for UDP probes (classic traceroute)
        let base_port = self.config.port.unwrap_or(33434);

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

                    // Check probe count limit (multiplied by flows)
                    if let Some(count) = self.config.count {
                        let total_probes = count * self.config.max_ttl as u64 * num_flows as u64;
                        if total_sent >= total_probes {
                            self.cancel.cancel();
                            break;
                        }
                    }

                    // Determine max TTL to probe
                    let max_probe_ttl = {
                        let state = self.state.read();
                        state.dest_ttl.unwrap_or(self.config.max_ttl)
                    };

                    // Send probes for each flow and each TTL (Paris/Dublin traceroute)
                    for flow_id in 0..num_flows {
                        let socket = &sockets[flow_id as usize];
                        let src_port = self.config.src_port_base + (flow_id as u16);

                        for ttl in 1..=max_probe_ttl {
                            let should_probe = {
                                let state = self.state.read();
                                !state.complete || state.hop(ttl).is_some_and(|h| h.received > 0)
                            };

                            if !should_probe {
                                continue;
                            }

                            let probe_id = ProbeId::new(ttl, seq);
                            let payload = build_udp_payload(probe_id);

                            // Set TTL before sending
                            if let Err(e) = set_ttl(socket, ttl) {
                                eprintln!("Failed to set TTL {}: {}", ttl, e);
                                continue;
                            }

                            // Use incrementing port per TTL to help with ECMP (unless fixed)
                            let dst_port = if self.config.port_fixed {
                                base_port
                            } else {
                                base_port + (ttl as u16)
                            };

                            let sent_at = Instant::now();

                            // Register pending BEFORE sending (key includes flow_id for multi-flow)
                            {
                                let mut pending = self.pending.write();
                                pending.insert((probe_id, flow_id), PendingProbe {
                                    sent_at,
                                    target: self.target,
                                    flow_id,
                                    original_src_port: Some(src_port), // For NAT detection
                                });
                            }

                            if let Err(e) = send_udp_probe(socket, &payload, self.target, dst_port) {
                                self.pending.write().remove(&(probe_id, flow_id));
                                eprintln!("Failed to send UDP probe TTL {} flow {}: {}", ttl, flow_id, e);
                                continue;
                            }

                            // Record that we sent a probe
                            {
                                let mut state = self.state.write();
                                if let Some(hop) = state.hop_mut(ttl) {
                                    hop.record_sent();
                                    hop.record_flow_sent(flow_id);
                                }
                                state.total_sent += 1;
                            }

                            total_sent += 1;
                        }
                    }

                    seq = seq.wrapping_add(1);
                }
            }
        }

        Ok(())
    }

    /// Run TCP SYN probing mode
    async fn run_tcp(self) -> Result<()> {
        let ipv6 = self.target.is_ipv6();
        let socket = create_tcp_socket(ipv6)?;
        let num_flows = self.config.flows;

        // Base port for TCP probes (default: 80)
        let base_port = self.config.port.unwrap_or(80);

        // Source IP for checksum calculation
        let src_ip = get_local_addr(self.target);

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

                    // Check probe count limit (multiplied by flows)
                    if let Some(count) = self.config.count {
                        let total_probes = count * self.config.max_ttl as u64 * num_flows as u64;
                        if total_sent >= total_probes {
                            self.cancel.cancel();
                            break;
                        }
                    }

                    // Determine max TTL to probe
                    let max_probe_ttl = {
                        let state = self.state.read();
                        state.dest_ttl.unwrap_or(self.config.max_ttl)
                    };

                    // Send probes for each flow and each TTL (Paris/Dublin traceroute)
                    for flow_id in 0..num_flows {
                        // Source port varies per flow for flow identification
                        let src_port = self.config.src_port_base + (flow_id as u16);

                        for ttl in 1..=max_probe_ttl {
                            let should_probe = {
                                let state = self.state.read();
                                !state.complete || state.hop(ttl).is_some_and(|h| h.received > 0)
                            };

                            if !should_probe {
                                continue;
                            }

                            let probe_id = ProbeId::new(ttl, seq);

                            // Use incrementing port per TTL to help with ECMP (unless fixed)
                            let dst_port = if self.config.port_fixed {
                                base_port
                            } else {
                                base_port + (ttl as u16)
                            };

                            // Build TCP SYN packet with flow-specific source port
                            let packet = build_tcp_syn(probe_id, src_port, dst_port, src_ip, self.target);

                            // Set TTL before sending
                            if let Err(e) = set_ttl(&socket, ttl) {
                                eprintln!("Failed to set TTL {}: {}", ttl, e);
                                continue;
                            }

                            let sent_at = Instant::now();

                            // Register pending BEFORE sending (key includes flow_id for multi-flow)
                            {
                                let mut pending = self.pending.write();
                                pending.insert((probe_id, flow_id), PendingProbe {
                                    sent_at,
                                    target: self.target,
                                    flow_id,
                                    original_src_port: Some(src_port), // For NAT detection
                                });
                            }

                            if let Err(e) = send_tcp_probe(&socket, &packet, self.target, dst_port) {
                                self.pending.write().remove(&(probe_id, flow_id));
                                eprintln!("Failed to send TCP probe TTL {} flow {}: {}", ttl, flow_id, e);
                                continue;
                            }

                            // Record that we sent a probe
                            {
                                let mut state = self.state.write();
                                if let Some(hop) = state.hop_mut(ttl) {
                                    hop.record_sent();
                                    hop.record_flow_sent(flow_id);
                                }
                                state.total_sent += 1;
                            }

                            total_sent += 1;
                        }
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
