use anyhow::Result;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::mem::MaybeUninit;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use crate::state::ProbeId;

/// UDP protocol number for IPv4/IPv6
pub const IPPROTO_UDP: u8 = 17;

/// Build a UDP probe payload
/// The payload contains the probe_id for correlation
pub fn build_udp_payload(probe_id: ProbeId) -> Vec<u8> {
    let sequence = probe_id.to_sequence();
    let mut payload = vec![0u8; 32]; // Minimum payload size

    // Encode probe_id in first 2 bytes as sequence number
    payload[0] = (sequence >> 8) as u8;
    payload[1] = (sequence & 0xFF) as u8;

    // Add a magic number for identification (helps distinguish our probes)
    payload[2] = 0x54; // 'T'
    payload[3] = 0x54; // 'T'
    payload[4] = 0x4C; // 'L'
    payload[5] = 0x00; // Version

    payload
}

/// Create a raw UDP socket for sending probes
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

/// Send a UDP probe to target
pub fn send_udp_probe(socket: &Socket, payload: &[u8], target: IpAddr, port: u16) -> Result<usize> {
    let addr = SocketAddr::new(target, port);
    let sock_addr = SockAddr::from(addr);
    let sent = socket.send_to(payload, &sock_addr)?;
    Ok(sent)
}

/// Receive ICMP response (for UDP probes, responses come as ICMP errors)
/// This is the same as recv_icmp - we listen on a separate raw ICMP socket
pub fn recv_icmp_for_udp(socket: &Socket, buffer: &mut [u8]) -> Result<(usize, IpAddr)> {
    let uninit_buf: &mut [MaybeUninit<u8>] = unsafe {
        std::slice::from_raw_parts_mut(buffer.as_mut_ptr() as *mut MaybeUninit<u8>, buffer.len())
    };

    let (len, addr) = socket.recv_from(uninit_buf)?;
    let ip = addr
        .as_socket()
        .map(|s| s.ip())
        .ok_or_else(|| anyhow::anyhow!("Invalid source address"))?;
    Ok((len, ip))
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
}
