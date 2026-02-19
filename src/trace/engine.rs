use anyhow::Result;
use parking_lot::RwLock;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

use crate::config::{Config, ProbeProtocol};
use crate::probe::{
    DEFAULT_PAYLOAD_SIZE, DEFAULT_UDP_PAYLOAD, ICMP_HEADER_SIZE, InterfaceInfo, TCP_HEADER_SIZE,
    bind_to_source_ip, build_echo_request, build_tcp_syn_sized, build_udp_payload_sized,
    create_send_socket_with_interface, create_tcp_socket_with_interface, create_udp_dgram_socket,
    create_udp_dgram_socket_bound_full, create_udp_dgram_socket_bound_with_interface,
    enable_recv_ttl, get_identifier, get_local_addr_with_interface, parse_icmp_response,
    recv_icmp_with_ttl, send_icmp, send_tcp_probe, send_udp_probe, set_dont_fragment, set_dscp,
    set_ttl,
};
use crate::state::{IcmpResponseType, PmtudPhase, ProbeId, Session};
use crate::trace::pending::{PendingMap, PendingProbe};

/// Safety cap for IPv6 echo-reply draining per tick.
/// Prevents shutdown starvation if the socket is continuously readable.
#[cfg(target_os = "linux")]
const MAX_IPV6_ECHO_DRAIN_BATCH: usize = 256;

/// The probe engine sends ICMP probes at configured intervals
pub struct ProbeEngine {
    config: Config,
    target: IpAddr,
    identifier: u16,
    state: Arc<RwLock<Session>>,
    pending: PendingMap,
    cancel: CancellationToken,
    interface: Option<InterfaceInfo>,
}

impl ProbeEngine {
    pub fn new(
        config: Config,
        target: IpAddr,
        state: Arc<RwLock<Session>>,
        pending: PendingMap,
        cancel: CancellationToken,
        interface: Option<InterfaceInfo>,
    ) -> Self {
        Self {
            config,
            target,
            identifier: get_identifier(),
            state,
            pending,
            cancel,
            interface,
        }
    }

    /// Get rate limit delay between probes (if rate is configured)
    fn rate_delay(&self) -> Option<Duration> {
        self.config.rate.and_then(|rate| {
            if rate > 0 {
                Some(Duration::from_secs_f64(1.0 / rate as f64))
            } else {
                None
            }
        })
    }

    /// Apply rate limiting delay if configured
    ///
    /// On macOS/FreeBSD, a minimum delay is always applied even without --rate.
    /// This is required because BSD-derived systems batch rapid setsockopt(IP_TTL) calls,
    /// causing packets to be sent with stale TTL values. A small delay ensures
    /// each set_ttl() takes effect before the next send().
    /// See: https://github.com/lance0/ttl/issues/12
    async fn apply_rate_limit(&self) {
        if let Some(delay) = self.rate_delay() {
            tokio::time::sleep(delay).await;
        } else if cfg!(any(
            target_os = "macos",
            target_os = "freebsd",
            target_os = "netbsd"
        )) {
            // macOS/FreeBSD/NetBSD require a minimum delay between probes to ensure
            // setsockopt(IP_TTL) takes effect before each send().
            // Without this, rapid probe bursts all get sent with the same TTL.
            // 500µs provides sufficient margin for the kernel to process the sockopt change.
            tokio::time::sleep(Duration::from_micros(500)).await;
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
        // Use interface-aware socket creation to test if interface binding works
        if create_send_socket_with_interface(ipv6, self.interface.as_ref()).is_ok() {
            return self.run_icmp().await;
        }

        // Fallback to UDP (works with DGRAM sockets, less privileged)
        // Test with interface binding when --interface is set to fail fast
        let udp_works = if self.interface.is_some() {
            // Test that we can create a bound socket with interface binding
            create_udp_dgram_socket_bound_with_interface(
                ipv6,
                self.config.src_port_base,
                self.interface.as_ref(),
            )
            .is_ok()
        } else {
            create_udp_dgram_socket(ipv6).is_ok()
        };

        if udp_works {
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
        let socket_info = create_send_socket_with_interface(ipv6, self.interface.as_ref())?;
        let socket = socket_info.socket;
        let is_dgram = socket_info.is_dgram;

        // Linux-only: Enable hop limit reception on send socket for Echo Reply polling
        // This allows asymmetry detection to work for the destination hop
        #[cfg(target_os = "linux")]
        if ipv6 {
            let _ = enable_recv_ttl(&socket, true);
        }

        // Determine source IP for socket binding and IPv6 checksum
        // For IPv6, we MUST bind to ensure checksum matches the actual source
        let src_ip = self
            .config
            .source_ip
            .unwrap_or_else(|| get_local_addr_with_interface(self.target, self.interface.as_ref()));

        // Bind to source IP if configured OR if IPv6 (required for checksum consistency)
        // Skip binding if source is unspecified (:: or 0.0.0.0) - let kernel choose
        if (self.config.source_ip.is_some() || ipv6)
            && !src_ip.is_unspecified()
            && let Err(e) = bind_to_source_ip(&socket, src_ip)
        {
            if self.config.source_ip.is_some() {
                // User explicitly requested this source IP - hard fail
                return Err(e);
            }
            // Auto-detected source IP failed to bind (e.g., link-local scope mismatch)
            // Warn and continue - kernel will choose source, checksum may be wrong
            eprintln!(
                "Warning: Failed to bind to source IP {}: {}. IPv6 checksum may be incorrect.",
                src_ip, e
            );
        }

        let mut seq: u8 = 0;
        // PMTUD uses separate seq counter; collision prevented by is_pmtud flag in pending key
        let mut pmtud_seq: u8 = 0;
        let mut rounds_completed: u64 = 0;
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

                    // Check probe round limit (-c flag means number of probe rounds)
                    if let Some(count) = self.config.count
                        && rounds_completed >= count
                    {
                        // Signal completion
                        self.cancel.cancel();
                        break;
                    }

                    // Determine max TTL to probe (stop at destination if known)
                    let max_probe_ttl = {
                        let state = self.state.read();
                        state.dest_ttl.unwrap_or(self.config.max_ttl)
                    };

                    // Send probes for TTLs up to the destination
                    for ttl in 1..=max_probe_ttl {
                        // Always probe all TTLs up to destination (max_probe_ttl already limits range)
                        // Previously we skipped non-responding hops after destination was found,
                        // but this prevented detecting hops that recover from rate limiting
                        // and caused sent counters to freeze on non-responding hops.

                        let probe_id = ProbeId::new(ttl, seq);

                        // Calculate payload size from config (packet_size includes IP+ICMP headers)
                        // IPv4 header = 20 bytes, IPv6 header = 40 bytes
                        let ip_header_size = if self.target.is_ipv6() { 40 } else { 20 };
                        let payload_size = self.config.packet_size
                            .map(|s| (s as usize).saturating_sub(ip_header_size + ICMP_HEADER_SIZE))
                            .unwrap_or(DEFAULT_PAYLOAD_SIZE);

                        // For IPv6, pass addresses for checksum computation
                        let ipv6_addrs = match (src_ip, self.target) {
                            (IpAddr::V6(src), IpAddr::V6(dest)) => Some((src, dest)),
                            _ => None,
                        };

                        let packet = build_echo_request(
                            self.identifier,
                            probe_id.to_sequence(),
                            payload_size,
                            self.target.is_ipv6(),
                            ipv6_addrs,
                        );

                        // Set TTL before sending
                        if let Err(e) = set_ttl(&socket, ttl, self.target.is_ipv6()) {
                            eprintln!("Failed to set TTL {}: {}", ttl, e);
                            continue;
                        }

                        // Set DSCP if configured
                        if let Some(dscp) = self.config.dscp
                            && let Err(e) = set_dscp(&socket, dscp, self.target.is_ipv6())
                        {
                            eprintln!("Failed to set DSCP {}: {}", dscp, e);
                        }

                        let sent_at = Instant::now();

                        // Register pending BEFORE sending to prevent race with fast responses
                        // ICMP uses single flow (flow_id=0) - checksum trick not yet implemented
                        let flow_id = 0u8;
                        {
                            let mut pending = self.pending.write();
                            pending.insert((probe_id, flow_id, self.target, false), PendingProbe {
                                sent_at,
                                target: self.target,
                                flow_id,
                                original_src_port: None, // ICMP has no source port
                                packet_size: None,
                            });
                        }

                        if let Err(e) = send_icmp(&socket, &packet, self.target) {
                            // Remove pending entry on send failure to avoid false timeouts
                            self.pending.write().remove(&(probe_id, flow_id, self.target, false));
                            eprintln!("Failed to send probe TTL {}: {}", ttl, e);
                            continue;
                        }

                        // Increment sent count immediately (mtr parity)
                        {
                            let mut state = self.state.write();
                            state.total_sent += 1;
                            if let Some(hop) = state.hop_mut(ttl) {
                                hop.record_sent();
                                hop.record_flow_sent(flow_id);
                            }
                        }

                        // Apply rate limiting if configured
                        self.apply_rate_limit().await;
                    }

                    // PMTUD: Send additional probe at destination TTL with current test size
                    // Uses separate pmtud_seq counter to avoid ProbeId collision with normal probes
                    if let Some(dest_ttl) = self.check_pmtud_ready()
                        && let Some(probe_size) = self.get_pmtud_probe_size()
                        && self.send_pmtud_probe_icmp(&socket, dest_ttl, probe_size, pmtud_seq, src_ip).await
                    {
                        pmtud_seq = pmtud_seq.wrapping_add(1);
                        self.apply_rate_limit().await;
                    }

                    // Linux-only: Poll send socket for Echo Reply
                    // Linux delivers ICMPv6 Echo Reply only to the socket that sent the request.
                    // macOS delivers to any raw ICMPv6 socket, so the receiver handles it there.
                    #[cfg(target_os = "linux")]
                    if ipv6 {
                        self.poll_ipv6_echo_reply(&socket, is_dgram);
                    }

                    seq = seq.wrapping_add(1);
                    rounds_completed += 1;
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
            let socket = create_udp_dgram_socket_bound_full(
                ipv6,
                src_port,
                self.interface.as_ref(),
                self.config.source_ip,
            )?;

            // Set DSCP if configured (set once per socket)
            if let Some(dscp) = self.config.dscp
                && let Err(e) = set_dscp(&socket, dscp, ipv6)
            {
                eprintln!("Failed to set DSCP {} on flow {}: {}", dscp, flow_id, e);
            }

            sockets.push(socket);
        }

        // Base port for UDP probes (classic traceroute)
        let base_port = self.config.port.unwrap_or(33434);

        let mut seq: u8 = 0;
        let mut rounds_completed: u64 = 0;
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

                    // Check probe round limit (-c flag means number of probe rounds)
                    if let Some(count) = self.config.count
                        && rounds_completed >= count
                    {
                        self.cancel.cancel();
                        break;
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
                            // Always probe all TTLs up to destination (see ICMP loop comment)

                            let probe_id = ProbeId::new(ttl, seq);

                            // Calculate UDP payload size from config
                            // packet_size includes IP header (20 for IPv4, 40 for IPv6) + UDP header (8)
                            let ip_header_size = if ipv6 { 40 } else { 20 };
                            const UDP_HEADER_SIZE: usize = 8;
                            let payload_size = self.config.packet_size
                                .map(|s| (s as usize).saturating_sub(ip_header_size + UDP_HEADER_SIZE))
                                .unwrap_or(DEFAULT_UDP_PAYLOAD);
                            let payload = build_udp_payload_sized(probe_id, payload_size);

                            // Set TTL before sending
                            if let Err(e) = set_ttl(socket, ttl, ipv6) {
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

                            // Register pending BEFORE sending (key includes flow_id and target for multi-flow/multi-target)
                            {
                                let mut pending = self.pending.write();
                                pending.insert((probe_id, flow_id, self.target, false), PendingProbe {
                                    sent_at,
                                    target: self.target,
                                    flow_id,
                                    original_src_port: Some(src_port), // For NAT detection
                                    packet_size: None,
                                });
                            }

                            if let Err(e) = send_udp_probe(socket, &payload, self.target, dst_port) {
                                self.pending.write().remove(&(probe_id, flow_id, self.target, false));
                                eprintln!("Failed to send UDP probe TTL {} flow {}: {}", ttl, flow_id, e);
                                continue;
                            }

                            // Increment sent count immediately (mtr parity)
                            {
                                let mut state = self.state.write();
                                state.total_sent += 1;
                                if let Some(hop) = state.hop_mut(ttl) {
                                    hop.record_sent();
                                    hop.record_flow_sent(flow_id);
                                }
                            }

                            // Apply rate limiting if configured
                            self.apply_rate_limit().await;
                        }
                    }

                    seq = seq.wrapping_add(1);
                    rounds_completed += 1;
                }
            }
        }

        Ok(())
    }

    /// Run TCP SYN probing mode
    async fn run_tcp(self) -> Result<()> {
        let ipv6 = self.target.is_ipv6();
        let socket = create_tcp_socket_with_interface(ipv6, self.interface.as_ref())?;

        // Bind to specific source IP if configured
        if let Some(source_ip) = self.config.source_ip {
            bind_to_source_ip(&socket, source_ip)?;
        }

        // Set DSCP if configured
        if let Some(dscp) = self.config.dscp
            && let Err(e) = set_dscp(&socket, dscp, ipv6)
        {
            eprintln!("Failed to set DSCP {}: {}", dscp, e);
        }

        let num_flows = self.config.flows;

        // Base port for TCP probes (default: 80)
        let base_port = self.config.port.unwrap_or(80);

        // Source IP for checksum calculation (use explicit source_ip, or interface IP, or kernel default)
        let src_ip = self
            .config
            .source_ip
            .unwrap_or_else(|| get_local_addr_with_interface(self.target, self.interface.as_ref()));

        let mut seq: u8 = 0;
        let mut rounds_completed: u64 = 0;
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

                    // Check probe round limit (-c flag means number of probe rounds)
                    if let Some(count) = self.config.count
                        && rounds_completed >= count
                    {
                        self.cancel.cancel();
                        break;
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
                            // Always probe all TTLs up to destination (see ICMP loop comment)

                            let probe_id = ProbeId::new(ttl, seq);

                            // Use incrementing port per TTL to help with ECMP (unless fixed)
                            let dst_port = if self.config.port_fixed {
                                base_port
                            } else {
                                base_port + (ttl as u16)
                            };

                            // Calculate TCP payload size from config
                            // packet_size includes IP header (20 for IPv4, 40 for IPv6) + TCP header (20)
                            let ip_header_size = if ipv6 { 40 } else { 20 };
                            let payload_size = self.config.packet_size
                                .map(|s| (s as usize).saturating_sub(ip_header_size + TCP_HEADER_SIZE))
                                .unwrap_or(0);

                            // Build TCP SYN packet with flow-specific source port
                            let packet = build_tcp_syn_sized(probe_id, src_port, dst_port, src_ip, self.target, payload_size);

                            // Set TTL before sending
                            if let Err(e) = set_ttl(&socket, ttl, self.target.is_ipv6()) {
                                eprintln!("Failed to set TTL {}: {}", ttl, e);
                                continue;
                            }

                            let sent_at = Instant::now();

                            // Register pending BEFORE sending (key includes flow_id and target for multi-flow/multi-target)
                            {
                                let mut pending = self.pending.write();
                                pending.insert((probe_id, flow_id, self.target, false), PendingProbe {
                                    sent_at,
                                    target: self.target,
                                    flow_id,
                                    original_src_port: Some(src_port), // For NAT detection
                                    packet_size: None,
                                });
                            }

                            if let Err(e) = send_tcp_probe(&socket, &packet, self.target, dst_port) {
                                self.pending.write().remove(&(probe_id, flow_id, self.target, false));
                                eprintln!("Failed to send TCP probe TTL {} flow {}: {}", ttl, flow_id, e);
                                continue;
                            }

                            // Increment sent count immediately (mtr parity)
                            {
                                let mut state = self.state.write();
                                state.total_sent += 1;
                                if let Some(hop) = state.hop_mut(ttl) {
                                    hop.record_sent();
                                    hop.record_flow_sent(flow_id);
                                }
                            }

                            // Apply rate limiting if configured
                            self.apply_rate_limit().await;
                        }
                    }

                    seq = seq.wrapping_add(1);
                    rounds_completed += 1;
                }
            }
        }

        Ok(())
    }

    // =========================================================================
    // PMTUD (Path MTU Discovery) support
    // =========================================================================

    /// Check if PMTUD is enabled and ready to start searching
    /// Returns (should_do_pmtud, dest_ttl) if PMTUD probes should be sent this tick
    fn check_pmtud_ready(&self) -> Option<u8> {
        if !self.config.pmtud {
            return None;
        }

        let mut state = self.state.write();
        let dest_ttl = state.dest_ttl?;

        // Check and potentially transition PMTUD state
        if let Some(ref mut pmtud) = state.pmtud {
            match pmtud.phase {
                PmtudPhase::WaitingForDestination => {
                    // Destination found - start PMTUD search
                    pmtud.start_search();
                    Some(dest_ttl)
                }
                PmtudPhase::Searching => Some(dest_ttl),
                PmtudPhase::Complete => None, // Already done
            }
        } else {
            None
        }
    }

    /// Get current PMTUD probe size (if searching)
    fn get_pmtud_probe_size(&self) -> Option<u16> {
        let state = self.state.read();
        state.pmtud.as_ref().and_then(|p| {
            if p.phase == PmtudPhase::Searching {
                Some(p.current_size)
            } else {
                None
            }
        })
    }

    /// Send an ICMP PMTUD probe at the specified TTL with the given packet size
    /// Returns true if probe was sent successfully
    async fn send_pmtud_probe_icmp(
        &self,
        socket: &socket2::Socket,
        dest_ttl: u8,
        packet_size: u16,
        seq: u8,
        src_ip: IpAddr,
    ) -> bool {
        let probe_id = ProbeId::new(dest_ttl, seq);

        // Calculate payload size from total packet size
        // packet_size includes IP + ICMP headers
        let ip_header_size: usize = if self.target.is_ipv6() { 40 } else { 20 };
        let payload_size = (packet_size as usize).saturating_sub(ip_header_size + ICMP_HEADER_SIZE);

        // For IPv6, pass addresses for checksum computation
        let ipv6_addrs = match (src_ip, self.target) {
            (IpAddr::V6(src), IpAddr::V6(dest)) => Some((src, dest)),
            _ => None,
        };

        let packet = build_echo_request(
            self.identifier,
            probe_id.to_sequence(),
            payload_size,
            self.target.is_ipv6(),
            ipv6_addrs,
        );

        // Set TTL
        if let Err(e) = set_ttl(socket, dest_ttl, self.target.is_ipv6()) {
            eprintln!("PMTUD: Failed to set TTL {}: {}", dest_ttl, e);
            return false;
        }

        // Set Don't Fragment flag (critical for PMTUD)
        if let Err(e) = set_dont_fragment(socket, self.target.is_ipv6()) {
            eprintln!("PMTUD: Failed to set DF flag: {}", e);
            return false;
        }

        // Set DSCP if configured
        if let Some(dscp) = self.config.dscp
            && let Err(e) = set_dscp(socket, dscp, self.target.is_ipv6())
        {
            eprintln!("PMTUD: Failed to set DSCP: {}", e);
        }

        let sent_at = Instant::now();
        let flow_id = 0u8;

        // Register pending probe with packet_size for correlation
        // Use is_pmtud=true to distinguish from normal probes with same ProbeId
        {
            let mut pending = self.pending.write();
            pending.insert(
                (probe_id, flow_id, self.target, true),
                PendingProbe {
                    sent_at,
                    target: self.target,
                    flow_id,
                    original_src_port: None,
                    packet_size: Some(packet_size),
                },
            );
        }

        // Send the probe
        match send_icmp(socket, &packet, self.target) {
            Ok(_) => {
                // Increment sent count immediately (mtr parity)
                // PMTUD only increments total_sent, not hop-level stats
                let mut state = self.state.write();
                state.total_sent += 1;
                true
            }
            Err(e) => {
                // Remove pending entry
                self.pending
                    .write()
                    .remove(&(probe_id, flow_id, self.target, true));

                // Check for EMSGSIZE - packet too large for local interface
                if let Some(io_err) = e.downcast_ref::<std::io::Error>()
                    && io_err.raw_os_error() == Some(libc::EMSGSIZE)
                {
                    // Clamp PMTUD max to current size - 1
                    let mut state = self.state.write();
                    if let Some(ref mut pmtud) = state.pmtud {
                        pmtud.max_size = packet_size.saturating_sub(1);
                        pmtud.successes = 0;
                        pmtud.failures = 0;
                        // Recalculate current size
                        if pmtud.is_converged() {
                            pmtud.discovered_mtu = Some(pmtud.min_size);
                            pmtud.phase = PmtudPhase::Complete;
                        } else {
                            pmtud.current_size = pmtud.next_probe_size();
                        }
                    }
                    return false;
                }

                eprintln!("PMTUD: Failed to send probe size {}: {}", packet_size, e);
                false
            }
        }
    }

    /// Poll the send socket for IPv6 Echo Reply responses (Linux-only)
    ///
    /// Linux delivers ICMPv6 Echo Reply ONLY to the socket that sent the request.
    /// Since we use separate send/receive sockets, the receiver never gets Echo Reply.
    /// This method polls the send socket after each round to catch Echo Reply responses.
    ///
    /// Time Exceeded (type 3) is delivered to any raw ICMPv6 socket, so the receiver
    /// handles intermediate hops fine. Only Echo Reply needs this special handling.
    ///
    /// Note: macOS delivers Echo Reply to any raw ICMPv6 socket, so this is not needed there.
    #[cfg(target_os = "linux")]
    fn poll_ipv6_echo_reply(&self, socket: &socket2::Socket, is_dgram: bool) {
        // Set socket to non-blocking for polling
        let _ = socket.set_nonblocking(true);

        let mut buffer = [0u8; 9216];
        let mut drained = 0usize;

        // Drain any pending Echo Reply responses
        loop {
            if self.cancel.is_cancelled() || drained >= MAX_IPV6_ECHO_DRAIN_BATCH {
                break;
            }

            match recv_icmp_with_ttl(socket, &mut buffer, true) {
                Ok(recv_result) => {
                    drained += 1;

                    // Parse the ICMP response
                    // For IPv6 raw sockets, kernel strips the IPv6 header
                    let Some(parsed) = parse_icmp_response(
                        &buffer[..recv_result.len],
                        recv_result.source,
                        self.identifier,
                        is_dgram,
                    ) else {
                        continue;
                    };

                    // Only handle Echo Reply here (type 129)
                    // Time Exceeded is handled by the receiver
                    if !matches!(parsed.response_type, IcmpResponseType::EchoReply) {
                        continue;
                    }

                    // Look up pending probe
                    let flow_id = 0u8; // ICMP uses single flow
                    let probe_opt = {
                        let mut pending = self.pending.write();
                        // Try normal probe first
                        pending
                            .remove(&(parsed.probe_id, flow_id, self.target, false))
                            .or_else(|| {
                                // Try PMTUD probe
                                pending.remove(&(parsed.probe_id, flow_id, self.target, true))
                            })
                    };

                    if let Some(probe) = probe_opt {
                        let rtt = Instant::now().duration_since(probe.sent_at);
                        let is_pmtud_probe = probe.packet_size.is_some();

                        // Record response (sent counting already happened at send time)
                        let mut state = self.state.write();

                        // Only record hop stats for normal probes, not PMTUD probes
                        if !is_pmtud_probe && let Some(hop) = state.hop_mut(parsed.probe_id.ttl) {
                            // Use flap-detecting record for single-flow mode (ICMP is always single-flow)
                            hop.record_response_detecting_flaps(parsed.responder, rtt, None);
                            hop.record_flow_response(flow_id, parsed.responder, rtt);
                            // Record response TTL for asymmetry detection
                            if let Some(response_ttl) = recv_result.response_ttl {
                                hop.record_response_ttl(response_ttl, true);
                            }
                        }

                        // Mark trace as complete if this is the destination
                        if parsed.responder == self.target {
                            state.complete = true;
                            let ttl = parsed.probe_id.ttl;
                            if state.dest_ttl.is_none_or(|d| ttl < d) {
                                state.dest_ttl = Some(ttl);
                            }
                        }

                        // Handle PMTUD probe success
                        if let Some(probe_size) = probe.packet_size
                            && let Some(ref mut pmtud) = state.pmtud
                            && pmtud.phase == PmtudPhase::Searching
                            && probe_size == pmtud.current_size
                        {
                            pmtud.record_success();
                        }
                    }
                }
                Err(e) => {
                    // Only break on WouldBlock/TimedOut (socket drained)
                    // Log other errors for debugging
                    let is_timeout = e.downcast_ref::<std::io::Error>().is_some_and(|io| {
                        io.kind() == std::io::ErrorKind::WouldBlock
                            || io.kind() == std::io::ErrorKind::TimedOut
                    });
                    if !is_timeout {
                        eprintln!("IPv6 Echo Reply poll error: {}", e);
                    }
                    break;
                }
            }
        }

        // Restore blocking mode for sending
        let _ = socket.set_nonblocking(false);
    }
}
