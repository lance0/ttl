//! Raw IPv4 packet construction for `IP_HDRINCL` sending.
//!
//! Building the full IPv4 header ourselves lets us write the TTL directly into the
//! packet instead of calling `setsockopt(IP_TTL)` before an asynchronous `sendto`.
//! On macOS (and other BSD-derived systems) `sendto` is asynchronous: the kernel
//! stamps each queued datagram with the socket's *current* TTL when it drains, so a
//! rapid `setsockopt(IP_TTL); send` loop on a shared socket can emit every probe with
//! the final TTL, collapsing the trace to a single hop (issue #12). Writing the TTL
//! into a hand-built IP header removes that race by construction, uniformly across
//! platforms, and lets one raw socket emit ICMP/UDP/TCP by varying the protocol byte.
//!
//! ## The `ip_len` / `ip_off` byte-order trap
//!
//! With `IP_HDRINCL`, every IPv4 header field is network byte order **except**
//! `ip_len` (total length) and `ip_off` (flags + fragment offset), which some BSD
//! kernels expect in *host* byte order:
//!
//! | OS                | `ip_len` / `ip_off` |
//! |-------------------|---------------------|
//! | Linux             | network order       |
//! | FreeBSD (>= 11.0) | network order       |
//! | macOS / Darwin    | host order          |
//! | NetBSD            | host order          |
//!
//! FreeBSD used host order before 11.0, but all such releases are EOL; current
//! FreeBSD matches Linux. Sources: FreeBSD `ip(4)` ("all fields, including `ip_len`
//! and `ip_off` ... in network byte order"; BUGS notes the pre-11.0 host-order
//! behavior), Darwin `ip(4)` ("the `ip_off` and `ip_len` fields are in host byte
//! order"), NetBSD `raw_ip.c` (`rip_output` byte-swaps `ip_len`/`ip_off` from host
//! order), Linux `raw(7)` / `net/ipv4/raw.c`.
//!
//! The kernel recomputes the IPv4 *header* checksum on all four systems, so we leave
//! it zero. It does **not** compute transport (ICMP/UDP/TCP) checksums for HDRINCL
//! packets — those are built into the transport payload we supply.

use anyhow::Result;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use crate::probe::bind_to_source_ip;
use crate::probe::interface::{InterfaceInfo, bind_socket_to_interface};

/// IPv4 header length with no options.
pub const IPV4_HEADER_SIZE: usize = 20;
/// UDP header length.
pub const UDP_HEADER_SIZE: usize = 8;

/// IPv4 protocol numbers.
pub const IPPROTO_ICMP: u8 = 1;
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;

/// Whether `ip_len` / `ip_off` must be in host byte order for `IP_HDRINCL` on this
/// target. macOS and NetBSD expect host order; Linux and FreeBSD (>= 11) expect
/// network order, like every other field. See the module docs for sources.
#[cfg(any(target_os = "macos", target_os = "ios", target_os = "netbsd"))]
pub const HDRINCL_HOST_ORDER_LEN_OFF: bool = true;
#[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "netbsd")))]
pub const HDRINCL_HOST_ORDER_LEN_OFF: bool = false;

/// One's-complement Internet checksum (RFC 1071) over `data`.
///
/// Used for the IPv4 header and (via the pseudo-header helpers) transport checksums.
pub fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        // Final odd byte is treated as the high byte of a 16-bit word.
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !sum as u16
}

/// Encode a 16-bit IPv4 header field that is byte-order-sensitive under `IP_HDRINCL`
/// (`ip_len`, `ip_off`).
///
/// Pure function taking the byte order explicitly so both branches are unit-testable
/// on a single host; the per-OS choice is [`HDRINCL_HOST_ORDER_LEN_OFF`].
pub fn encode_len_off(value: u16, host_order: bool) -> [u8; 2] {
    if host_order {
        value.to_ne_bytes()
    } else {
        value.to_be_bytes()
    }
}

/// Build a 20-byte IPv4 header (no options) for `IP_HDRINCL` sending.
///
/// `tos` is the full ToS/DSCP byte (DSCP occupies the upper 6 bits). The header
/// checksum is left zero — every target kernel recomputes it for HDRINCL packets.
#[allow(clippy::too_many_arguments)]
pub fn build_ipv4_header(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    protocol: u8,
    ttl: u8,
    tos: u8,
    total_len: u16,
    identification: u16,
    dont_fragment: bool,
) -> [u8; IPV4_HEADER_SIZE] {
    let mut h = [0u8; IPV4_HEADER_SIZE];
    // Version 4, IHL 5 (20-byte header, no options).
    h[0] = 0x45;
    h[1] = tos;
    h[2..4].copy_from_slice(&encode_len_off(total_len, HDRINCL_HOST_ORDER_LEN_OFF));
    h[4..6].copy_from_slice(&identification.to_be_bytes());
    let frag_off: u16 = if dont_fragment { 0x4000 } else { 0x0000 };
    h[6..8].copy_from_slice(&encode_len_off(frag_off, HDRINCL_HOST_ORDER_LEN_OFF));
    h[8] = ttl;
    h[9] = protocol;
    // h[10..12]: header checksum — left zero; kernel recomputes for HDRINCL.
    h[12..16].copy_from_slice(&src.octets());
    h[16..20].copy_from_slice(&dst.octets());
    h
}

/// Compute the IPv4 UDP checksum over the pseudo-header + UDP header + payload.
///
/// `udp` is the full UDP datagram (8-byte header + payload) with its checksum field
/// (bytes 6..8) set to zero by the caller.
pub fn udp_checksum_v4(src: Ipv4Addr, dst: Ipv4Addr, udp: &[u8]) -> u16 {
    // Pseudo-header: src(4) + dst(4) + zero(1) + protocol(1) + udp_len(2), then the
    // UDP datagram (checksum field zero). The whole thing is one Internet checksum.
    let mut buf = Vec::with_capacity(12 + udp.len());
    buf.extend_from_slice(&src.octets());
    buf.extend_from_slice(&dst.octets());
    buf.push(0);
    buf.push(IPPROTO_UDP);
    buf.extend_from_slice(&(udp.len() as u16).to_be_bytes());
    buf.extend_from_slice(udp);
    internet_checksum(&buf)
}

/// Build a full UDP datagram (8-byte header + payload) with a valid IPv4 checksum.
pub fn build_udp_datagram(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = UDP_HEADER_SIZE + payload.len();
    let mut dgram = vec![0u8; udp_len];
    dgram[0..2].copy_from_slice(&src_port.to_be_bytes());
    dgram[2..4].copy_from_slice(&dst_port.to_be_bytes());
    dgram[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    // Checksum (bytes 6..8) computed below.
    dgram[8..].copy_from_slice(payload);
    let cksum = udp_checksum_v4(src, dst, &dgram);
    // A transmitted IPv4 UDP checksum of 0 means "no checksum"; per RFC 768 send the
    // one's-complement form (0xFFFF) instead so the receiver still verifies it.
    let cksum = if cksum == 0 { 0xFFFF } else { cksum };
    dgram[6..8].copy_from_slice(&cksum.to_be_bytes());
    dgram
}

/// Assemble a complete IPv4 packet: hand-built IP header + transport bytes.
///
/// `transport` is the fully-formed transport message (ICMP message, UDP datagram, or
/// TCP segment) including its own checksum.
pub fn build_ipv4_packet(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    protocol: u8,
    ttl: u8,
    tos: u8,
    dont_fragment: bool,
    transport: &[u8],
) -> Vec<u8> {
    let total_payload = IPV4_HEADER_SIZE + transport.len();
    assert!(
        total_payload <= u16::MAX as usize,
        "IPv4 packet too large: {total_payload} bytes (max 65535)"
    );
    let total_len = total_payload as u16;
    let header = build_ipv4_header(src, dst, protocol, ttl, tos, total_len, 0, dont_fragment);
    let mut packet = Vec::with_capacity(total_payload);
    packet.extend_from_slice(&header);
    packet.extend_from_slice(transport);
    packet
}

/// Create a raw IPv4 socket with `IP_HDRINCL` enabled, optionally bound to an
/// interface and/or a source address. The socket can send ICMP/UDP/TCP by setting the
/// IP protocol field of the supplied header. Requires root / `CAP_NET_RAW`.
///
/// `bind_src` is the user-configured `--source-ip`. Binding to it makes the kernel
/// validate that it is a local address (failing with `EADDRNOTAVAIL` otherwise), so an
/// invalid or non-local source fails fast here instead of silently producing packets
/// with a spoofed source and mismatched transport checksums. The on-wire source still
/// comes from the IP header we build; the bind is purely the validation/locality check.
pub fn create_raw_hdrincl_socket_with_interface(
    interface: Option<&InterfaceInfo>,
    bind_src: Option<Ipv4Addr>,
) -> Result<Socket> {
    // IPPROTO_RAW is the conventional "send any protocol via the header" choice. On
    // Linux it also implies IP_HDRINCL, but the BSDs do not, so we always set it
    // explicitly below.
    let socket = Socket::new(
        Domain::IPV4,
        Type::RAW,
        Some(Protocol::from(libc::IPPROTO_RAW)),
    )?;

    set_ip_hdrincl(&socket)?;

    socket.set_nonblocking(false)?;
    socket.set_read_timeout(Some(Duration::from_secs(1)))?;

    // Interface binding (SO_BINDTODEVICE / IP_BOUND_IF) for --interface, before the
    // address bind.
    if let Some(info) = interface {
        bind_socket_to_interface(&socket, info, false)?;
    }

    // Bind to the configured source IP so a non-local --source-ip fails fast.
    if let Some(src) = bind_src {
        bind_to_source_ip(&socket, IpAddr::V4(src))?;
    }

    Ok(socket)
}

/// Enable IP_HDRINCL on a raw IPv4 socket via setsockopt (portable across platforms;
/// avoids depending on a specific socket2 helper name).
fn set_ip_hdrincl(socket: &Socket) -> Result<()> {
    use std::os::unix::io::AsRawFd;
    let one: libc::c_int = 1;
    let ret = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_IP,
            libc::IP_HDRINCL,
            &one as *const _ as *const libc::c_void,
            std::mem::size_of_val(&one) as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

/// Send a fully-formed IPv4 packet (built with [`build_ipv4_packet`]) to `dst`.
///
/// The destination passed to `sendto` matches the header's destination; the port is
/// meaningless for raw IP and is set to zero.
pub fn send_raw_ipv4(socket: &Socket, packet: &[u8], dst: Ipv4Addr) -> Result<usize> {
    let addr = SocketAddr::new(IpAddr::V4(dst), 0);
    let sent = socket.send_to(packet, &SockAddr::from(addr))?;
    Ok(sent)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Canonical IPv4 header from the Wikipedia "IPv4 header checksum" example.
    // With the checksum field zeroed, internet_checksum must yield 0xB861.
    #[test]
    fn test_internet_checksum_known_vector() {
        let header: [u8; 20] = [
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
        ];
        assert_eq!(internet_checksum(&header), 0xb861);
    }

    #[test]
    fn test_internet_checksum_self_verifies() {
        // Inserting the checksum back into the data and re-summing yields 0.
        let mut data = vec![0x45u8, 0x00, 0x00, 0x28, 0x12, 0x34, 0x40, 0x00, 0x40, 0x06];
        let ck = internet_checksum(&data);
        data.extend_from_slice(&ck.to_be_bytes());
        // Re-checksum including the inserted field => 0x0000.
        assert_eq!(internet_checksum(&data), 0x0000);
    }

    #[test]
    fn test_encode_len_off_network_order() {
        assert_eq!(encode_len_off(0x0028, false), [0x00, 0x28]);
        assert_eq!(encode_len_off(0x4000, false), [0x40, 0x00]);
    }

    #[test]
    #[cfg(target_endian = "little")]
    fn test_encode_len_off_host_order_little_endian() {
        // On a little-endian host, "host order" is byte-swapped from network order.
        assert_eq!(encode_len_off(0x0028, true), [0x28, 0x00]);
        assert_eq!(encode_len_off(0x4000, true), [0x00, 0x40]);
    }

    #[test]
    fn test_encode_len_off_branches_match_intrinsics() {
        for v in [0u16, 1, 0x0028, 0x4000, 0xABCD, 0xFFFF] {
            assert_eq!(encode_len_off(v, false), v.to_be_bytes());
            assert_eq!(encode_len_off(v, true), v.to_ne_bytes());
        }
    }

    #[test]
    fn test_build_ipv4_header_fields() {
        let src = Ipv4Addr::new(192, 168, 1, 10);
        let dst = Ipv4Addr::new(8, 8, 8, 8);
        let h = build_ipv4_header(src, dst, IPPROTO_ICMP, 7, 0xb8, 84, 0, false);

        assert_eq!(h[0], 0x45, "version 4, IHL 5");
        assert_eq!(h[1], 0xb8, "ToS byte");
        assert_eq!(h[8], 7, "TTL");
        assert_eq!(h[9], IPPROTO_ICMP, "protocol");
        assert_eq!(&h[12..16], &src.octets(), "source address");
        assert_eq!(&h[16..20], &dst.octets(), "dest address");
        assert_eq!(&h[10..12], &[0, 0], "checksum left zero for kernel");
        // total_len encoded per the platform's byte order.
        assert_eq!(&h[2..4], &encode_len_off(84, HDRINCL_HOST_ORDER_LEN_OFF));
    }

    #[test]
    fn test_build_ipv4_header_dont_fragment_bit() {
        let src = Ipv4Addr::new(10, 0, 0, 1);
        let dst = Ipv4Addr::new(10, 0, 0, 2);
        let with_df = build_ipv4_header(src, dst, IPPROTO_UDP, 64, 0, 100, 0, true);
        let without_df = build_ipv4_header(src, dst, IPPROTO_UDP, 64, 0, 100, 0, false);
        assert_eq!(
            &with_df[6..8],
            &encode_len_off(0x4000, HDRINCL_HOST_ORDER_LEN_OFF)
        );
        assert_eq!(
            &without_df[6..8],
            &encode_len_off(0x0000, HDRINCL_HOST_ORDER_LEN_OFF)
        );
    }

    #[test]
    fn test_udp_datagram_layout_and_checksum() {
        let src = Ipv4Addr::new(192, 168, 1, 10);
        let dst = Ipv4Addr::new(8, 8, 8, 8);
        let payload = b"hello probe";
        let dgram = build_udp_datagram(src, dst, 33434, 33500, payload);

        assert_eq!(dgram.len(), UDP_HEADER_SIZE + payload.len());
        assert_eq!(&dgram[0..2], &33434u16.to_be_bytes(), "src port");
        assert_eq!(&dgram[2..4], &33500u16.to_be_bytes(), "dst port");
        assert_eq!(
            &dgram[4..6],
            &((UDP_HEADER_SIZE + payload.len()) as u16).to_be_bytes(),
            "length"
        );
        assert_eq!(&dgram[8..], payload, "payload copied");
        assert_ne!(&dgram[6..8], &[0, 0], "checksum present");

        // Verify end-to-end: summing the pseudo-header + full datagram (including the
        // now-filled checksum field) with an independent checksum must fold to zero.
        let mut verify = Vec::new();
        verify.extend_from_slice(&src.octets());
        verify.extend_from_slice(&dst.octets());
        verify.push(0);
        verify.push(IPPROTO_UDP);
        verify.extend_from_slice(&(dgram.len() as u16).to_be_bytes());
        verify.extend_from_slice(&dgram);
        assert_eq!(internet_checksum(&verify), 0x0000, "UDP checksum verifies");
    }

    #[test]
    fn test_build_ipv4_packet_assembly() {
        let src = Ipv4Addr::new(1, 2, 3, 4);
        let dst = Ipv4Addr::new(5, 6, 7, 8);
        let transport = vec![0xAAu8; 16];
        let pkt = build_ipv4_packet(src, dst, IPPROTO_TCP, 12, 0, true, &transport);

        assert_eq!(pkt.len(), IPV4_HEADER_SIZE + transport.len());
        assert_eq!(pkt[8], 12, "TTL in header");
        assert_eq!(pkt[9], IPPROTO_TCP, "protocol in header");
        assert_eq!(
            &pkt[IPV4_HEADER_SIZE..],
            &transport[..],
            "transport appended"
        );
        assert_eq!(
            &pkt[2..4],
            &encode_len_off(
                (IPV4_HEADER_SIZE + transport.len()) as u16,
                HDRINCL_HOST_ORDER_LEN_OFF
            ),
            "total length"
        );
    }

    #[test]
    fn test_build_ipv4_packet_max_size() {
        // Transport that fills exactly to u16::MAX
        let max_transport = u16::MAX as usize - IPV4_HEADER_SIZE;
        let transport = vec![0u8; max_transport];
        let pkt = build_ipv4_packet(
            Ipv4Addr::new(1, 2, 3, 4),
            Ipv4Addr::new(5, 6, 7, 8),
            IPPROTO_ICMP,
            64,
            0,
            false,
            &transport,
        );
        assert_eq!(pkt.len(), u16::MAX as usize);
    }

    #[test]
    #[should_panic(expected = "IPv4 packet too large")]
    fn test_build_ipv4_packet_oversized_panics() {
        let oversized = u16::MAX as usize - IPV4_HEADER_SIZE + 1;
        let transport = vec![0u8; oversized];
        build_ipv4_packet(
            Ipv4Addr::new(1, 2, 3, 4),
            Ipv4Addr::new(5, 6, 7, 8),
            IPPROTO_ICMP,
            64,
            0,
            false,
            &transport,
        );
    }

    // On a network-order target (Linux CI), the hand-built header must parse cleanly
    // with an independent IPv4 parser and round-trip its fields.
    #[test]
    #[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "netbsd")))]
    fn test_header_parses_with_pnet_on_network_order() {
        use pnet::packet::ipv4::Ipv4Packet;
        let src = Ipv4Addr::new(192, 168, 0, 1);
        let dst = Ipv4Addr::new(9, 9, 9, 9);
        let transport = vec![0u8; 12];
        let pkt = build_ipv4_packet(src, dst, IPPROTO_ICMP, 5, 0x20, false, &transport);

        let parsed = Ipv4Packet::new(&pkt).expect("valid IPv4 packet");
        assert_eq!(parsed.get_version(), 4);
        assert_eq!(parsed.get_header_length(), 5);
        assert_eq!(parsed.get_ttl(), 5);
        assert_eq!(parsed.get_next_level_protocol().0, IPPROTO_ICMP);
        assert_eq!(
            parsed.get_total_length() as usize,
            IPV4_HEADER_SIZE + transport.len()
        );
        assert_eq!(parsed.get_source(), src);
        assert_eq!(parsed.get_destination(), dst);
        assert_eq!(parsed.get_dscp(), 0x20 >> 2);
    }

    // Privileged, real-kernel validation of the per-OS ip_len/ip_off byte order.
    //
    // Builds a real IPv4 packet for each protocol and sends it via an IP_HDRINCL raw
    // socket; the send only succeeds if the header byte order matches what this kernel
    // expects (BSD kernels reject a wrong-order header with EINVAL at send time). This
    // is the on-device check the unit tests can't perform on their own — it is wired
    // into the Linux, macOS, and FreeBSD CI jobs under root. (macOS exercises the same
    // host-order branch NetBSD uses, giving transitive coverage of NetBSD.)
    //
    // Requires root (raw socket); ignored by default. Run with:
    //   sudo cargo test --lib runtime_hdrincl -- --ignored --nocapture
    #[test]
    #[ignore = "requires root (raw socket); run via --ignored under sudo / in CI"]
    fn runtime_hdrincl_send_all_protocols() {
        use crate::probe::build_echo_request;
        use crate::probe::build_tcp_syn_sized;
        use crate::state::ProbeId;

        // Loopback keeps the test self-contained (no network egress); the byte-order
        // validation in the kernel fires before routing regardless of destination.
        let lo = Ipv4Addr::LOCALHOST;
        let socket = create_raw_hdrincl_socket_with_interface(None, None)
            .expect("create IP_HDRINCL raw socket (needs root)");

        // ICMP echo.
        let icmp = build_echo_request(0x4242, 1, 16, false, None, false);
        let pkt = build_ipv4_packet(lo, lo, IPPROTO_ICMP, 5, 0, false, &icmp);
        send_raw_ipv4(&socket, &pkt, lo)
            .expect("kernel rejected ICMP IP_HDRINCL packet (ip_len/ip_off byte order?)");

        // UDP datagram.
        let udp = build_udp_datagram(lo, lo, 33434, 33500, b"ttl-probe");
        let pkt = build_ipv4_packet(lo, lo, IPPROTO_UDP, 6, 0, false, &udp);
        send_raw_ipv4(&socket, &pkt, lo)
            .expect("kernel rejected UDP IP_HDRINCL packet (ip_len/ip_off byte order?)");

        // TCP SYN.
        let tcp = build_tcp_syn_sized(
            ProbeId::new(7, 1),
            50000,
            80,
            IpAddr::V4(lo),
            IpAddr::V4(lo),
            0,
        );
        let pkt = build_ipv4_packet(lo, lo, IPPROTO_TCP, 7, 0, false, &tcp);
        send_raw_ipv4(&socket, &pkt, lo)
            .expect("kernel rejected TCP IP_HDRINCL packet (ip_len/ip_off byte order?)");

        // Also exercise the Don't Fragment path used by PMTUD.
        let icmp_df = build_echo_request(0x4242, 2, 64, false, None, false);
        let pkt = build_ipv4_packet(lo, lo, IPPROTO_ICMP, 8, 0, true, &icmp_df);
        send_raw_ipv4(&socket, &pkt, lo)
            .expect("kernel rejected DF IP_HDRINCL packet (ip_len/ip_off byte order?)");
    }

    // On-wire field verification (Linux): send an IPv4 ICMP echo via IP_HDRINCL to
    // loopback and receive it on a raw ICMP socket, confirming the kernel transmits
    // exactly the header we built — TTL, ToS, protocol, and source/dest match, and both
    // the (kernel-filled) IP header checksum and our ICMP checksum validate on the wire.
    // This closes the gap that the acceptance-only test leaves (it proves byte order but
    // not the emitted field values). Linux-only (raw recv semantics); requires root.
    #[test]
    #[ignore = "requires root (raw socket); run via --ignored under sudo / in CI"]
    #[cfg(target_os = "linux")]
    fn runtime_hdrincl_onwire_fields_linux() {
        use crate::probe::build_echo_request;
        use socket2::{Domain, Protocol, Type};
        use std::mem::MaybeUninit;

        let lo = Ipv4Addr::LOCALHOST;
        let ident: u16 = 0x7A7A;
        let ttl: u8 = 42;
        let tos: u8 = 0x28;

        let send = create_raw_hdrincl_socket_with_interface(None, None)
            .expect("create IP_HDRINCL socket (needs root)");
        let recv = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))
            .expect("create raw ICMP recv socket (needs root)");
        recv.set_read_timeout(Some(Duration::from_secs(3))).unwrap();

        let icmp = build_echo_request(ident, 1, 16, false, None, false);
        let pkt = build_ipv4_packet(lo, lo, IPPROTO_ICMP, ttl, tos, false, &icmp);
        send_raw_ipv4(&send, &pkt, lo).expect("send IP_HDRINCL echo to loopback");

        // Loopback also yields the kernel's echo reply; read until we see our request.
        let mut buf = [MaybeUninit::<u8>::uninit(); 2048];
        let mut found = false;
        for _ in 0..16 {
            let n = match recv.recv(&mut buf) {
                Ok(n) => n,
                Err(_) => break, // timeout
            };
            // SAFETY: recv() initializes the first `n` bytes of buf.
            let data: &[u8] = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, n) };
            if data.len() < IPV4_HEADER_SIZE + 8 || data[0] >> 4 != 4 {
                continue;
            }
            let ihl = ((data[0] & 0x0f) as usize) * 4;
            if ihl < IPV4_HEADER_SIZE || data.len() < ihl + 8 || data[9] != IPPROTO_ICMP {
                continue;
            }
            let icmp_msg = &data[ihl..];
            // ICMP Echo Request = type 8; identifier at bytes 4..6.
            if icmp_msg[0] != 8 || u16::from_be_bytes([icmp_msg[4], icmp_msg[5]]) != ident {
                continue;
            }

            assert_eq!(data[8], ttl, "TTL on wire");
            assert_eq!(data[1], tos, "ToS on wire");
            assert_eq!(&data[12..16], &lo.octets(), "source on wire");
            assert_eq!(&data[16..20], &lo.octets(), "dest on wire");
            assert_eq!(
                internet_checksum(&data[..ihl]),
                0,
                "IP header checksum valid"
            );
            assert_eq!(internet_checksum(icmp_msg), 0, "ICMP checksum valid");
            found = true;
            break;
        }
        assert!(
            found,
            "did not receive our own IP_HDRINCL echo request on loopback"
        );
    }
}
