use anyhow::Result;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use crate::state::ProbeId;

/// UDP protocol number for IPv4/IPv6
#[allow(dead_code)]
pub const IPPROTO_UDP: u8 = 17;

/// Minimum UDP payload size (header fields)
pub const MIN_UDP_PAYLOAD: usize = 8;
/// Default UDP payload size
pub const DEFAULT_UDP_PAYLOAD: usize = 32;

/// Build a UDP probe payload with default size (convenience wrapper)
/// The payload contains the probe_id for correlation
#[allow(dead_code)]
pub fn build_udp_payload(probe_id: ProbeId) -> Vec<u8> {
    build_udp_payload_sized(probe_id, DEFAULT_UDP_PAYLOAD)
}

/// Build a UDP probe payload with specific size
/// Minimum size is 8 bytes (for probe header), larger payloads are filled with pattern
pub fn build_udp_payload_sized(probe_id: ProbeId, size: usize) -> Vec<u8> {
    let size = size.max(MIN_UDP_PAYLOAD);
    let sequence = probe_id.to_sequence();
    let mut payload = vec![0u8; size];

    // Encode probe_id in first 2 bytes as sequence number
    payload[0] = (sequence >> 8) as u8;
    payload[1] = (sequence & 0xFF) as u8;

    // Add a magic number for identification (helps distinguish our probes)
    payload[2] = 0x54; // 'T'
    payload[3] = 0x54; // 'T'
    payload[4] = 0x4C; // 'L'
    payload[5] = 0x00; // Version

    // Fill remaining bytes with pattern (useful for MTU testing)
    for (i, byte) in payload[6..].iter_mut().enumerate() {
        *byte = (i & 0xFF) as u8;
    }

    payload
}

/// Create a raw UDP socket for sending probes
#[allow(dead_code)]
pub fn create_udp_send_socket(ipv6: bool) -> Result<Socket> {
    let domain = if ipv6 { Domain::IPV6 } else { Domain::IPV4 };

    // Use SOCK_RAW with IPPROTO_UDP for TTL control
    // This requires root/CAP_NET_RAW but gives us TTL control
    let socket = Socket::new(domain, Type::RAW, Some(Protocol::UDP))?;

    socket.set_nonblocking(false)?;
    socket.set_read_timeout(Some(Duration::from_secs(1)))?;

    Ok(socket)
}

/// Create a DGRAM UDP socket for sending probes (fallback, simpler)
pub fn create_udp_dgram_socket(ipv6: bool) -> Result<Socket> {
    let domain = if ipv6 { Domain::IPV6 } else { Domain::IPV4 };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;

    socket.set_nonblocking(false)?;
    socket.set_read_timeout(Some(Duration::from_secs(1)))?;

    Ok(socket)
}

/// Create a DGRAM UDP socket bound to a specific source port (for multi-flow Paris traceroute)
#[allow(dead_code)]
pub fn create_udp_dgram_socket_bound(ipv6: bool, src_port: u16) -> Result<Socket> {
    let socket = create_udp_dgram_socket(ipv6)?;

    // Bind to the specified source port
    let bind_addr = if ipv6 {
        SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), src_port)
    } else {
        SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), src_port)
    };
    socket.bind(&SockAddr::from(bind_addr))?;

    Ok(socket)
}

use crate::probe::interface::{InterfaceInfo, bind_socket_to_interface};

/// Create a DGRAM UDP socket bound to source port and optionally to an interface
/// Interface binding must happen BEFORE address binding for proper behavior
pub fn create_udp_dgram_socket_bound_with_interface(
    ipv6: bool,
    src_port: u16,
    interface: Option<&InterfaceInfo>,
) -> Result<Socket> {
    create_udp_dgram_socket_bound_full(ipv6, src_port, interface, None)
}

/// Create a DGRAM UDP socket bound to source port, interface, and optionally source IP
/// Interface binding must happen BEFORE address binding for proper behavior
pub fn create_udp_dgram_socket_bound_full(
    ipv6: bool,
    src_port: u16,
    interface: Option<&InterfaceInfo>,
    source_ip: Option<IpAddr>,
) -> Result<Socket> {
    let socket = create_udp_dgram_socket(ipv6)?;

    // Bind to interface BEFORE binding to address
    // SO_BINDTODEVICE affects which interface's addresses are valid for binding
    if let Some(info) = interface {
        bind_socket_to_interface(&socket, info, ipv6)?;
    }

    // Bind to the specified source port (and optionally source IP)
    let bind_addr = match source_ip {
        Some(ip) => SocketAddr::new(ip, src_port),
        None => {
            if ipv6 {
                SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), src_port)
            } else {
                SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), src_port)
            }
        }
    };
    socket.bind(&SockAddr::from(bind_addr))?;

    Ok(socket)
}

/// Detect the local source IP the kernel would use to reach a given target.
/// Creates a temporary UDP socket, connects to the target, and reads back
/// the source address via getsockname. Required on NetBSD where DGRAM sockets
/// bound to 0.0.0.0 fail with EHOSTUNREACH.
pub fn detect_source_ip(target: IpAddr) -> Result<IpAddr> {
    let ipv6 = target.is_ipv6();
    let domain = if ipv6 { Domain::IPV6 } else { Domain::IPV4 };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    // Connect to target on a dummy port — no packets are sent for UDP
    let addr = SocketAddr::new(target, 80);
    socket.connect(&SockAddr::from(addr))?;
    let local = socket.local_addr()?;
    let local_addr: SocketAddr = local
        .as_socket()
        .ok_or_else(|| anyhow::anyhow!("Failed to get local socket address"))?;
    Ok(local_addr.ip())
}

/// Send a UDP probe to target
pub fn send_udp_probe(socket: &Socket, payload: &[u8], target: IpAddr, port: u16) -> Result<usize> {
    let addr = SocketAddr::new(target, port);
    let sock_addr = SockAddr::from(addr);
    let sent = socket.send_to(payload, &sock_addr)?;
    Ok(sent)
}

/// Extract ProbeId from UDP payload in ICMP error
/// The payload should be the UDP data portion (after IP + UDP headers)
pub fn extract_probe_id_from_udp_payload(udp_payload: &[u8]) -> Option<ProbeId> {
    if udp_payload.len() < 6 {
        return None;
    }

    // Check magic number
    if udp_payload[2] != 0x54 || udp_payload[3] != 0x54 || udp_payload[4] != 0x4C {
        return None;
    }

    // Extract sequence from first 2 bytes
    let sequence = u16::from_be_bytes([udp_payload[0], udp_payload[1]]);
    Some(ProbeId::from_sequence(sequence))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_udp_payload_roundtrip() {
        let probe_id = ProbeId::new(15, 42);
        let payload = build_udp_payload(probe_id);

        let extracted = extract_probe_id_from_udp_payload(&payload);
        assert!(extracted.is_some());

        let extracted = extracted.unwrap();
        assert_eq!(extracted.ttl, 15);
        assert_eq!(extracted.seq, 42);
    }

    #[test]
    fn test_udp_payload_magic_validation() {
        // Test with invalid magic number
        let payload = vec![0x0F, 0x2A, 0x00, 0x00, 0x00, 0x00];
        let extracted = extract_probe_id_from_udp_payload(&payload);
        assert!(extracted.is_none());
    }

    #[test]
    fn test_udp_payload_too_short() {
        let payload = vec![0x0F, 0x2A, 0x54]; // Only 3 bytes
        let extracted = extract_probe_id_from_udp_payload(&payload);
        assert!(extracted.is_none());
    }

    #[test]
    fn test_detect_source_ip_ipv4() {
        // Detect source IP for a well-known IPv4 target (Google DNS)
        // This exercises the connect+getsockname path.
        // In restricted/offline environments, ENETUNREACH/EHOSTUNREACH is acceptable.
        let ip = detect_source_ip(IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8)));
        match ip {
            Ok(ip) => {
                assert!(ip.is_ipv4(), "detected source should be IPv4");
                // Should not be unspecified (0.0.0.0) or loopback
                assert!(
                    !ip.is_unspecified(),
                    "detected source should not be 0.0.0.0"
                );
                assert!(!ip.is_loopback(), "detected source should not be loopback");
            }
            Err(e) => {
                let allowed = e.downcast_ref::<std::io::Error>().is_some_and(|io| {
                    matches!(
                        io.kind(),
                        std::io::ErrorKind::NetworkUnreachable
                            | std::io::ErrorKind::HostUnreachable
                    )
                });
                assert!(
                    allowed,
                    "unexpected detect_source_ip IPv4 error in test: {e}"
                );
            }
        }
    }

    #[test]
    fn test_detect_source_ip_ipv6() {
        // Detect source IP for a well-known IPv6 target (Google DNS)
        // May fail if the host has no IPv6 connectivity — that's expected
        let ip = detect_source_ip(IpAddr::V6(std::net::Ipv6Addr::new(
            0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888,
        )));
        if let Ok(ip) = ip {
            assert!(ip.is_ipv6(), "detected source should be IPv6");
            assert!(!ip.is_unspecified(), "detected source should not be [::]");
            assert!(!ip.is_loopback(), "detected source should not be ::1");
        }
        // Err is acceptable if host has no IPv6 route
    }
}
