use anyhow::Result;
use parking_lot::RwLock;
use socket2::Socket;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

use crate::config::{Config, ProbeProtocol};
use crate::probe::rawip::{
    IPPROTO_ICMP, IPPROTO_TCP, IPPROTO_UDP, IPV4_HEADER_SIZE, build_ipv4_packet,
    build_udp_datagram, create_raw_hdrincl_socket_with_interface, send_raw_ipv4,
};
use crate::probe::{
    DEFAULT_PAYLOAD_SIZE, DEFAULT_UDP_PAYLOAD, ICMP_HEADER_SIZE, InterfaceInfo, SocketInfo,
    TCP_HEADER_SIZE, bind_to_source_ip, build_echo_request, build_tcp_syn_sized,
    build_udp_payload_sized, create_send_socket_with_interface, create_tcp_socket_with_interface,
    create_udp_dgram_socket, create_udp_dgram_socket_bound_full,
    create_udp_dgram_socket_bound_with_interface, detect_source_ip, get_identifier,
    get_local_addr_with_interface, send_icmp, send_tcp_probe, send_udp_probe, set_dont_fragment,
    set_dscp, set_ttl,
};
#[cfg(target_os = "linux")]
use crate::probe::{enable_recv_ttl, parse_icmp_response, recv_icmp_with_ttl};
#[cfg(target_os = "linux")]
use crate::state::IcmpResponseType;
use crate::state::{PmtudPhase, ProbeId, Session};
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

    /// Apply the user-configured `--rate` delay between probes, if any.
    ///
    /// No platform floor is needed: IPv4 sends via IP_HDRINCL (TTL in the header) and IPv6
    /// sends each probe from a fresh socket on macOS/FreeBSD/NetBSD (`per_probe_send`), so
    /// there is no `setsockopt(IP_TTL / hop-limit)`-before-async-`sendto` race to mask
    /// (issue #12). Linux's `sendto` never exhibited the race. The previous 500µs floor
    /// has therefore been retired.
    async fn apply_rate_limit(&self) {
        if let Some(delay) = self.rate_delay() {
            tokio::time::sleep(delay).await;
        }
    }

    /// Build a fully-configured ICMP send socket: created via the platform-specific
    /// path, bound to the requested interface, and (when a source IP is configured, or
    /// for IPv6 where the checksum depends on it) bound to `src_ip`.
    ///
    /// Serves the IPv6 send path (IPv4 uses IP_HDRINCL). On `per_probe_send` platforms
    /// (macOS/FreeBSD/NetBSD) this is called once per probe: those kernels send
    /// asynchronously, so the TTL/hop-limit is stamped from the socket's *current* state
    /// when a queued datagram drains — under back-to-back sends the queue doesn't drain
    /// between probes and they all pick up the final value, collapsing the trace to one
    /// hop. A fresh socket carries exactly one datagram, so its hop limit is always the
    /// intended one. See issue #12 and the Apple DTS thread
    /// <https://developer.apple.com/forums/thread/726398>. Linux reuses one shared socket.
    fn build_send_socket(&self, ipv6: bool, src_ip: IpAddr) -> Result<SocketInfo> {
        let socket_info = create_send_socket_with_interface(ipv6, self.interface.as_ref())?;

        // Bind to source IP if configured OR if IPv6 (required for checksum consistency).
        // Skip binding if source is unspecified (:: or 0.0.0.0) - let kernel choose.
        if (self.config.source_ip.is_some() || ipv6)
            && !src_ip.is_unspecified()
            && let Err(e) =
                bind_to_source_ip(&socket_info.socket, src_ip, self.config.source_ip_scope_id)
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

        Ok(socket_info)
    }

    /// Build a UDP send socket bound to `src_port` (and the requested interface/source
    /// IP), with DSCP applied. Used once per flow on Linux and once per probe on the
    /// `per_probe_send` platforms (macOS/FreeBSD/NetBSD), where a fresh socket per probe
    /// avoids the async-sendto TTL race (issue #12, same mechanism as
    /// [`Self::build_send_socket`]). The flow's source port is preserved across
    /// re-creations so flow identification and NAT detection still work; the socket enables
    /// address reuse so rapid re-binding of that port does not fail.
    fn build_udp_send_socket(
        &self,
        ipv6: bool,
        src_port: u16,
        source_ip: Option<IpAddr>,
    ) -> Result<Socket> {
        let socket = create_udp_dgram_socket_bound_full(
            ipv6,
            src_port,
            self.interface.as_ref(),
            source_ip,
            self.config.source_ip_scope_id,
        )?;
        if let Some(dscp) = self.config.dscp
            && let Err(e) = set_dscp(&socket, dscp, ipv6)
        {
            eprintln!("Failed to set DSCP {}: {}", dscp, e);
        }
        Ok(socket)
    }

    /// Build a TCP (raw) send socket bound to the configured source IP, with DSCP applied.
    /// Used once on Linux and once per probe on the `per_probe_send` platforms
    /// (macOS/FreeBSD/NetBSD) to avoid the async-sendto TTL race (issue #12). The TCP
    /// source port lives in the crafted SYN packet rather than a socket bind, so nothing
    /// flow-specific needs to be reapplied here.
    fn build_tcp_send_socket(&self, ipv6: bool) -> Result<Socket> {
        let socket = create_tcp_socket_with_interface(ipv6, self.interface.as_ref())?;
        if let Some(source_ip) = self.config.source_ip {
            bind_to_source_ip(&socket, source_ip, self.config.source_ip_scope_id)?;
        }
        if let Some(dscp) = self.config.dscp
            && let Err(e) = set_dscp(&socket, dscp, ipv6)
        {
            eprintln!("Failed to set DSCP {}: {}", dscp, e);
        }
        Ok(socket)
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
        // IPv4 uses the unified IP_HDRINCL send path (TTL written into the IP header;
        // see issue #12 and the rawip module). IPv6 has no IPv4-style IP_HDRINCL and
        // continues below with the per-probe-socket path.
        if !self.target.is_ipv6() {
            return self.run_icmp_hdrincl().await;
        }

        let ipv6 = self.target.is_ipv6();

        // Determine source IP for socket binding and IPv6 checksum.
        // For IPv6, we MUST bind to ensure the checksum matches the actual source.
        // Computed once and reused for every send socket we build (including the
        // per-probe sockets created in the loop on per_probe_send platforms).
        let src_ip = self
            .config
            .source_ip
            .unwrap_or_else(|| get_local_addr_with_interface(self.target, self.interface.as_ref()));

        // Shared send socket. On per_probe_send platforms (macOS/FreeBSD/NetBSD) the
        // per-TTL probes are sent from fresh sockets created inside the loop (see issue #12
        // and `build_send_socket`); this shared socket still serves the single PMTUD probe
        // and, on Linux, Echo Reply polling.
        let socket_info = self.build_send_socket(ipv6, src_ip)?;
        let socket = socket_info.socket;
        #[cfg(target_os = "linux")]
        let is_dgram = socket_info.is_dgram;

        // Linux-only: Enable hop limit reception on send socket for Echo Reply polling
        // This allows asymmetry detection to work for the destination hop
        #[cfg(target_os = "linux")]
        if ipv6 {
            let _ = enable_recv_ttl(&socket, true);
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

                        // per_probe_send (macOS/FreeBSD/NetBSD): fresh socket per probe to avoid the async-sendto
                        // TTL batching race (issue #12). A shared DGRAM socket stamps queued
                        // datagrams with whatever TTL it holds at drain time, so rapid sends all
                        // pick up the last TTL set and the trace collapses to one hop. One socket
                        // per probe carries exactly one datagram, so its TTL is always correct.
                        // Correlation is unaffected: macOS already rewrites the ICMP identifier on
                        // DGRAM sockets, and the receiver matches on the sequence / payload-embedded
                        // id rather than that identifier (see correlate.rs payload fallback).
                        #[cfg(per_probe_send)]
                        let probe_socket = match self.build_send_socket(ipv6, src_ip) {
                            Ok(info) => info.socket,
                            Err(e) => {
                                eprintln!("Failed to create send socket for TTL {}: {}", ttl, e);
                                continue;
                            }
                        };
                        #[cfg(per_probe_send)]
                        let send_sock = &probe_socket;
                        #[cfg(not(per_probe_send))]
                        let send_sock = &socket;

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
                            false,
                        );

                        // Set TTL before sending
                        if let Err(e) = set_ttl(send_sock, ttl, self.target.is_ipv6()) {
                            eprintln!("Failed to set TTL {}: {}", ttl, e);
                            continue;
                        }

                        // Set DSCP if configured
                        if let Some(dscp) = self.config.dscp
                            && let Err(e) = set_dscp(send_sock, dscp, self.target.is_ipv6())
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

                        if let Err(e) = send_icmp(send_sock, &packet, self.target) {
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
        // IPv4 uses the unified IP_HDRINCL send path (see issue #12 and the rawip
        // module). IPv6 continues below with the per-flow-socket path.
        if !self.target.is_ipv6() {
            return self.run_udp_hdrincl().await;
        }

        let ipv6 = self.target.is_ipv6();
        let num_flows = self.config.flows;

        // On NetBSD, DGRAM sockets bound to 0.0.0.0 fail with EHOSTUNREACH.
        // Auto-detect the source IP the kernel would use for this target.
        let source_ip = if self.config.source_ip.is_some() {
            self.config.source_ip
        } else if cfg!(target_os = "netbsd") {
            Some(detect_source_ip(self.target)?)
        } else {
            None
        };

        // Create sockets for each flow (Paris/Dublin multi-flow support); each is bound to
        // a distinct source port for flow identification. On per_probe_send platforms the
        // per-flow sockets are instead created per-probe inside the loop (issue #12 — the
        // async-sendto TTL race),
        // so this shared Vec is only built on other platforms.
        #[cfg(not(per_probe_send))]
        let sockets = {
            let mut sockets = Vec::with_capacity(num_flows as usize);
            for flow_id in 0..num_flows {
                let src_port = self.config.src_port_base + (flow_id as u16);
                sockets.push(self.build_udp_send_socket(ipv6, src_port, source_ip)?);
            }
            sockets
        };

        // per_probe_send platforms send each probe from a fresh socket in the loop (issue #12). Validate
        // socket creation/binding for every flow up front with `?` so a misconfigured
        // --source-ip, interface, or port fails fast here instead of spinning silently in
        // the probe loop (the loop logs+continues on error to tolerate transient failures).
        #[cfg(per_probe_send)]
        for flow_id in 0..num_flows {
            let src_port = self.config.src_port_base + (flow_id as u16);
            self.build_udp_send_socket(ipv6, src_port, source_ip)?;
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
                        let src_port = self.config.src_port_base + (flow_id as u16);

                        // Linux: reuse this flow's shared socket created above.
                        #[cfg(not(per_probe_send))]
                        let flow_socket = &sockets[flow_id as usize];

                        for ttl in 1..=max_probe_ttl {
                            // Always probe all TTLs up to destination (see ICMP loop comment)

                            // per_probe_send (macOS/FreeBSD/NetBSD): fresh socket per probe (issue #12), re-bound to this
                            // flow's source port so flow ID / NAT detection still work.
                            #[cfg(per_probe_send)]
                            let probe_socket =
                                match self.build_udp_send_socket(ipv6, src_port, source_ip) {
                                    Ok(s) => s,
                                    Err(e) => {
                                        eprintln!(
                                            "Failed to create UDP send socket for TTL {} flow {}: {}",
                                            ttl, flow_id, e
                                        );
                                        continue;
                                    }
                                };
                            #[cfg(per_probe_send)]
                            let send_sock = &probe_socket;
                            #[cfg(not(per_probe_send))]
                            let send_sock = flow_socket;

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
                            if let Err(e) = set_ttl(send_sock, ttl, ipv6) {
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

                            if let Err(e) = send_udp_probe(send_sock, &payload, self.target, dst_port)
                            {
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
        // IPv4 uses the unified IP_HDRINCL send path (see issue #12 and the rawip
        // module). IPv6 continues below with the shared raw-socket path.
        if !self.target.is_ipv6() {
            return self.run_tcp_hdrincl().await;
        }

        let ipv6 = self.target.is_ipv6();

        // Shared raw socket reused on Linux. On per_probe_send platforms each probe uses a fresh
        // socket created inside the loop (issue #12 — the async-sendto TTL race). The TCP
        // source port is carried in the crafted SYN, not a socket bind, so nothing
        // flow-specific is lost by recreating the socket.
        #[cfg(not(per_probe_send))]
        let socket = self.build_tcp_send_socket(ipv6)?;

        // per_probe_send platforms send each probe from a fresh socket in the loop (issue #12). Validate
        // socket creation/binding up front with `?` so a misconfigured --source-ip or
        // interface fails fast here instead of spinning silently in the probe loop.
        #[cfg(per_probe_send)]
        self.build_tcp_send_socket(ipv6)?;

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

                            // per_probe_send (macOS/FreeBSD/NetBSD): fresh socket per probe (issue #12).
                            #[cfg(per_probe_send)]
                            let probe_socket = match self.build_tcp_send_socket(ipv6) {
                                Ok(s) => s,
                                Err(e) => {
                                    eprintln!(
                                        "Failed to create TCP send socket for TTL {} flow {}: {}",
                                        ttl, flow_id, e
                                    );
                                    continue;
                                }
                            };
                            #[cfg(per_probe_send)]
                            let send_sock = &probe_socket;
                            #[cfg(not(per_probe_send))]
                            let send_sock = &socket;

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
                            if let Err(e) = set_ttl(send_sock, ttl, self.target.is_ipv6()) {
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

                            if let Err(e) = send_tcp_probe(send_sock, &packet, self.target, dst_port)
                            {
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
    // IPv4 unified send path (IP_HDRINCL)
    //
    // For IPv4 the TTL is written directly into a hand-built IP header and sent via
    // one raw IP_HDRINCL socket, instead of setsockopt(IP_TTL) before an asynchronous
    // sendto. That removes the stale-TTL race (issue #12) by construction, uniformly
    // across platforms, and needs no per-probe socket churn or inter-probe delay.
    // IPv6 has no IPv4-style IP_HDRINCL and keeps the per-probe-socket path above.
    // =========================================================================

    /// Resolve the IPv4 source address for this trace (for the IP header and the
    /// transport-layer checksums). Errors if `--source-ip` is set to an IPv6 address for
    /// an IPv4 target; when unset, uses the routing lookup (the bind in
    /// [`Self::ipv4_bind_src`] is what fail-fast-validates an explicit `--source-ip`).
    fn ipv4_src(&self) -> Result<Ipv4Addr> {
        match self.config.source_ip {
            Some(IpAddr::V4(s)) => Ok(s),
            Some(IpAddr::V6(_)) => Err(anyhow::anyhow!(
                "--source-ip is an IPv6 address but the target is IPv4"
            )),
            None => match get_local_addr_with_interface(self.target, self.interface.as_ref()) {
                IpAddr::V4(s) => Ok(s),
                // Routing returned no IPv4 source; the kernel fills the header source,
                // though transport checksums would then be built for 0.0.0.0.
                IpAddr::V6(_) => Ok(Ipv4Addr::UNSPECIFIED),
            },
        }
    }

    /// The `--source-ip` to bind the raw socket to (Some only when explicitly set, so a
    /// non-local value fails fast at bind); None lets the kernel choose by route.
    fn ipv4_bind_src(&self) -> Option<Ipv4Addr> {
        match self.config.source_ip {
            Some(IpAddr::V4(s)) => Some(s),
            _ => None,
        }
    }

    /// The ToS/DSCP byte to stamp into the IPv4 header (DSCP in the upper 6 bits).
    fn ipv4_tos(&self) -> u8 {
        self.config
            .dscp
            .map(|d| ((d as u32) << 2) as u8)
            .unwrap_or(0)
    }

    /// IPv4 ICMP probing via a single raw IP_HDRINCL socket (issue #12).
    async fn run_icmp_hdrincl(self) -> Result<()> {
        let IpAddr::V4(dst) = self.target else {
            unreachable!("run_icmp_hdrincl is IPv4-only");
        };
        let src = self.ipv4_src()?;
        let bind_src = self.ipv4_bind_src();
        let tos = self.ipv4_tos();
        let socket = create_raw_hdrincl_socket_with_interface(self.interface.as_ref(), bind_src)?;

        let mut seq: u8 = 0;
        let mut pmtud_seq: u8 = 0;
        let mut rounds_completed: u64 = 0;
        let mut interval = tokio::time::interval(self.config.interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                _ = self.cancel.cancelled() => break,
                _ = interval.tick() => {
                    {
                        let state = self.state.read();
                        if state.paused {
                            continue;
                        }
                    }

                    if let Some(count) = self.config.count
                        && rounds_completed >= count
                    {
                        self.cancel.cancel();
                        break;
                    }

                    let max_probe_ttl = {
                        let state = self.state.read();
                        state.dest_ttl.unwrap_or(self.config.max_ttl)
                    };

                    for ttl in 1..=max_probe_ttl {
                        let probe_id = ProbeId::new(ttl, seq);

                        // packet_size includes the IPv4 + ICMP headers.
                        let payload_size = self
                            .config
                            .packet_size
                            .map(|s| (s as usize).saturating_sub(IPV4_HEADER_SIZE + ICMP_HEADER_SIZE))
                            .unwrap_or(DEFAULT_PAYLOAD_SIZE);

                        let icmp =
                            build_echo_request(self.identifier, probe_id.to_sequence(), payload_size, false, None, false);
                        let packet = build_ipv4_packet(src, dst, IPPROTO_ICMP, ttl, tos, false, &icmp);

                        let sent_at = Instant::now();
                        let flow_id = 0u8;
                        {
                            let mut pending = self.pending.write();
                            pending.insert((probe_id, flow_id, self.target, false), PendingProbe {
                                sent_at,
                                target: self.target,
                                flow_id,
                                original_src_port: None,
                                packet_size: None,
                            });
                        }

                        if let Err(e) = send_raw_ipv4(&socket, &packet, dst) {
                            self.pending.write().remove(&(probe_id, flow_id, self.target, false));
                            eprintln!("Failed to send probe TTL {}: {}", ttl, e);
                            continue;
                        }

                        {
                            let mut state = self.state.write();
                            state.total_sent += 1;
                            if let Some(hop) = state.hop_mut(ttl) {
                                hop.record_sent();
                                hop.record_flow_sent(flow_id);
                            }
                        }

                        self.apply_rate_limit().await;
                    }

                    // PMTUD: extra DF probe at the destination TTL with the current size.
                    if let Some(dest_ttl) = self.check_pmtud_ready()
                        && let Some(probe_size) = self.get_pmtud_probe_size()
                        && self
                            .send_pmtud_probe_icmp_hdrincl(&socket, src, dst, tos, dest_ttl, probe_size, pmtud_seq)
                            .await
                    {
                        pmtud_seq = pmtud_seq.wrapping_add(1);
                        self.apply_rate_limit().await;
                    }

                    seq = seq.wrapping_add(1);
                    rounds_completed += 1;
                }
            }
        }

        Ok(())
    }

    /// IPv4 UDP probing via IP_HDRINCL. Builds the full UDP datagram (the kernel does
    /// not for HDRINCL packets) and wraps it in a hand-built IP header.
    async fn run_udp_hdrincl(self) -> Result<()> {
        let IpAddr::V4(dst) = self.target else {
            unreachable!("run_udp_hdrincl is IPv4-only");
        };
        let src = self.ipv4_src()?;
        let bind_src = self.ipv4_bind_src();
        let tos = self.ipv4_tos();
        let num_flows = self.config.flows;
        let base_port = self.config.port.unwrap_or(33434);
        let socket = create_raw_hdrincl_socket_with_interface(self.interface.as_ref(), bind_src)?;

        let mut seq: u8 = 0;
        let mut rounds_completed: u64 = 0;
        let mut interval = tokio::time::interval(self.config.interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                _ = self.cancel.cancelled() => break,
                _ = interval.tick() => {
                    {
                        let state = self.state.read();
                        if state.paused {
                            continue;
                        }
                    }

                    if let Some(count) = self.config.count
                        && rounds_completed >= count
                    {
                        self.cancel.cancel();
                        break;
                    }

                    let max_probe_ttl = {
                        let state = self.state.read();
                        state.dest_ttl.unwrap_or(self.config.max_ttl)
                    };

                    for flow_id in 0..num_flows {
                        let src_port = self.config.src_port_base + (flow_id as u16);

                        for ttl in 1..=max_probe_ttl {
                            let probe_id = ProbeId::new(ttl, seq);

                            // packet_size includes the IPv4 + UDP headers.
                            const UDP_HEADER_SIZE: usize = 8;
                            let payload_size = self
                                .config
                                .packet_size
                                .map(|s| (s as usize).saturating_sub(IPV4_HEADER_SIZE + UDP_HEADER_SIZE))
                                .unwrap_or(DEFAULT_UDP_PAYLOAD);
                            let payload = build_udp_payload_sized(probe_id, payload_size);

                            let dst_port = if self.config.port_fixed {
                                base_port
                            } else {
                                base_port + (ttl as u16)
                            };

                            let udp = build_udp_datagram(src, dst, src_port, dst_port, &payload);
                            let packet = build_ipv4_packet(src, dst, IPPROTO_UDP, ttl, tos, false, &udp);

                            let sent_at = Instant::now();
                            {
                                let mut pending = self.pending.write();
                                pending.insert((probe_id, flow_id, self.target, false), PendingProbe {
                                    sent_at,
                                    target: self.target,
                                    flow_id,
                                    original_src_port: Some(src_port),
                                    packet_size: None,
                                });
                            }

                            if let Err(e) = send_raw_ipv4(&socket, &packet, dst) {
                                self.pending.write().remove(&(probe_id, flow_id, self.target, false));
                                eprintln!("Failed to send UDP probe TTL {} flow {}: {}", ttl, flow_id, e);
                                continue;
                            }

                            {
                                let mut state = self.state.write();
                                state.total_sent += 1;
                                if let Some(hop) = state.hop_mut(ttl) {
                                    hop.record_sent();
                                    hop.record_flow_sent(flow_id);
                                }
                            }

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

    /// IPv4 TCP SYN probing via IP_HDRINCL. The TCP segment (with its checksum) is
    /// built as today; only the IP header is now hand-built so the TTL rides in it.
    async fn run_tcp_hdrincl(self) -> Result<()> {
        let IpAddr::V4(dst) = self.target else {
            unreachable!("run_tcp_hdrincl is IPv4-only");
        };
        let src = self.ipv4_src()?;
        let bind_src = self.ipv4_bind_src();
        let tos = self.ipv4_tos();
        let num_flows = self.config.flows;
        let base_port = self.config.port.unwrap_or(80);
        let socket = create_raw_hdrincl_socket_with_interface(self.interface.as_ref(), bind_src)?;

        let mut seq: u8 = 0;
        let mut rounds_completed: u64 = 0;
        let mut interval = tokio::time::interval(self.config.interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                _ = self.cancel.cancelled() => break,
                _ = interval.tick() => {
                    {
                        let state = self.state.read();
                        if state.paused {
                            continue;
                        }
                    }

                    if let Some(count) = self.config.count
                        && rounds_completed >= count
                    {
                        self.cancel.cancel();
                        break;
                    }

                    let max_probe_ttl = {
                        let state = self.state.read();
                        state.dest_ttl.unwrap_or(self.config.max_ttl)
                    };

                    for flow_id in 0..num_flows {
                        let src_port = self.config.src_port_base + (flow_id as u16);

                        for ttl in 1..=max_probe_ttl {
                            let probe_id = ProbeId::new(ttl, seq);

                            let dst_port = if self.config.port_fixed {
                                base_port
                            } else {
                                base_port + (ttl as u16)
                            };

                            // packet_size includes the IPv4 + TCP headers.
                            let payload_size = self
                                .config
                                .packet_size
                                .map(|s| (s as usize).saturating_sub(IPV4_HEADER_SIZE + TCP_HEADER_SIZE))
                                .unwrap_or(0);

                            let tcp = build_tcp_syn_sized(
                                probe_id,
                                src_port,
                                dst_port,
                                IpAddr::V4(src),
                                self.target,
                                payload_size,
                            );
                            let packet = build_ipv4_packet(src, dst, IPPROTO_TCP, ttl, tos, false, &tcp);

                            let sent_at = Instant::now();
                            {
                                let mut pending = self.pending.write();
                                pending.insert((probe_id, flow_id, self.target, false), PendingProbe {
                                    sent_at,
                                    target: self.target,
                                    flow_id,
                                    original_src_port: Some(src_port),
                                    packet_size: None,
                                });
                            }

                            if let Err(e) = send_raw_ipv4(&socket, &packet, dst) {
                                self.pending.write().remove(&(probe_id, flow_id, self.target, false));
                                eprintln!("Failed to send TCP probe TTL {} flow {}: {}", ttl, flow_id, e);
                                continue;
                            }

                            {
                                let mut state = self.state.write();
                                state.total_sent += 1;
                                if let Some(hop) = state.hop_mut(ttl) {
                                    hop.record_sent();
                                    hop.record_flow_sent(flow_id);
                                }
                            }

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

    /// Handle DF flag setup failures during PMTUD probing.
    ///
    /// On NetBSD IPv4, DF is unsupported (no IP_DONTFRAG). In that case we
    /// stop PMTUD probing immediately so we don't retry and spam the same error
    /// every probe round.
    fn handle_pmtud_df_error(&self, unsupported_ipv4_df: bool, err: &anyhow::Error) {
        if unsupported_ipv4_df {
            let mut state = self.state.write();
            if let Some(ref mut pmtud) = state.pmtud {
                pmtud.phase = PmtudPhase::Complete;
                pmtud.discovered_mtu = None;
            }
            eprintln!(
                "PMTUD: IPv4 PMTUD unavailable on NetBSD (missing IP_DONTFRAG); skipping PMTUD probes."
            );
        } else {
            eprintln!("PMTUD: Failed to set DF flag: {}", err);
        }
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
            true,
        );

        // Set TTL
        if let Err(e) = set_ttl(socket, dest_ttl, self.target.is_ipv6()) {
            eprintln!("PMTUD: Failed to set TTL {}: {}", dest_ttl, e);
            return false;
        }

        // Set Don't Fragment flag (critical for PMTUD)
        if let Err(e) = set_dont_fragment(socket, self.target.is_ipv6()) {
            let unsupported_ipv4_df = cfg!(target_os = "netbsd") && !self.target.is_ipv6();
            self.handle_pmtud_df_error(unsupported_ipv4_df, &e);
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

    /// IPv4 PMTUD probe via IP_HDRINCL: an ICMP echo at `dest_ttl` sized to
    /// `packet_size` with the Don't Fragment bit set in the hand-built IP header.
    /// Returns true if the probe was sent. Setting DF in the header also means IPv4
    /// PMTUD now works on NetBSD (which lacks the IP_DONTFRAG socket option).
    #[allow(clippy::too_many_arguments)]
    async fn send_pmtud_probe_icmp_hdrincl(
        &self,
        socket: &Socket,
        src: Ipv4Addr,
        dst: Ipv4Addr,
        tos: u8,
        dest_ttl: u8,
        packet_size: u16,
        seq: u8,
    ) -> bool {
        let probe_id = ProbeId::new(dest_ttl, seq);
        let payload_size =
            (packet_size as usize).saturating_sub(IPV4_HEADER_SIZE + ICMP_HEADER_SIZE);

        let icmp = build_echo_request(
            self.identifier,
            probe_id.to_sequence(),
            payload_size,
            false,
            None,
            true,
        );
        // Don't Fragment set in the IP header so routers return Frag Needed.
        let packet = build_ipv4_packet(src, dst, IPPROTO_ICMP, dest_ttl, tos, true, &icmp);

        let sent_at = Instant::now();
        let flow_id = 0u8;
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

        match send_raw_ipv4(socket, &packet, dst) {
            Ok(_) => {
                let mut state = self.state.write();
                state.total_sent += 1;
                true
            }
            Err(e) => {
                self.pending
                    .write()
                    .remove(&(probe_id, flow_id, self.target, true));

                // EMSGSIZE: packet too large for the local interface; clamp PMTUD max.
                if let Some(io_err) = e.downcast_ref::<std::io::Error>()
                    && io_err.raw_os_error() == Some(libc::EMSGSIZE)
                {
                    let mut state = self.state.write();
                    if let Some(ref mut pmtud) = state.pmtud {
                        pmtud.max_size = packet_size.saturating_sub(1);
                        pmtud.successes = 0;
                        pmtud.failures = 0;
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
                        let rtt = Instant::now().saturating_duration_since(probe.sent_at);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::Target;
    use crate::trace::pending::new_pending_map;
    use std::net::{IpAddr, Ipv4Addr};

    fn make_test_engine(pmtud: bool) -> ProbeEngine {
        let config = Config {
            pmtud,
            ..Config::default()
        };
        let target = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let session = Arc::new(RwLock::new(Session::new(
            Target::new("test".to_string(), target),
            config.clone(),
        )));
        if pmtud {
            let mut state = session.write();
            if let Some(ref mut p) = state.pmtud {
                p.phase = PmtudPhase::Searching;
            }
        }
        ProbeEngine::new(
            config,
            target,
            session,
            new_pending_map(),
            CancellationToken::new(),
            None,
        )
    }

    #[test]
    fn test_handle_pmtud_df_error_marks_complete_for_unsupported_df() {
        let engine = make_test_engine(true);
        engine.handle_pmtud_df_error(true, &anyhow::anyhow!("df unavailable"));

        let state = engine.state.read();
        let pmtud = state.pmtud.as_ref().expect("PMTUD state should exist");
        assert_eq!(pmtud.phase, PmtudPhase::Complete);
        assert!(pmtud.discovered_mtu.is_none());
    }

    #[test]
    fn test_handle_pmtud_df_error_keeps_searching_for_general_errors() {
        let engine = make_test_engine(true);
        engine.handle_pmtud_df_error(false, &anyhow::anyhow!("temporary setsockopt error"));

        let state = engine.state.read();
        let pmtud = state.pmtud.as_ref().expect("PMTUD state should exist");
        assert_eq!(pmtud.phase, PmtudPhase::Searching);
    }
}
