//! TCP SYN probe building and parsing for traceroute
//!
//! Sends TCP SYN packets that trigger ICMP Time Exceeded from intermediate routers.
//! The probe_id is encoded in the TCP sequence number for correlation.

use anyhow::Result;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use crate::state::ProbeId;

/// TCP protocol number
pub const IPPROTO_TCP: u8 = 6;

/// Default source port for TCP probes (high ephemeral port)
const TCP_SRC_PORT: u16 = 50000;

/// TCP flags
const TCP_FLAG_SYN: u8 = 0x02;

/// Build a TCP SYN packet for probing
/// Returns the raw TCP header (no IP header - kernel adds that)
pub fn build_tcp_syn(
    probe_id: ProbeId,
    src_port: u16,
    dst_port: u16,
    src_ip: IpAddr,
    dst_ip: IpAddr,
) -> Vec<u8> {
    let mut packet = vec![0u8; 20]; // Minimum TCP header size

    // Source port (2 bytes)
    packet[0..2].copy_from_slice(&src_port.to_be_bytes());

    // Destination port (2 bytes)
    packet[2..4].copy_from_slice(&dst_port.to_be_bytes());

    // Sequence number (4 bytes) - encode probe_id
    // Use the full sequence as probe_id in high bits, low bits for TTL/seq encoding
    let seq = (probe_id.to_sequence() as u32) << 16;
    packet[4..8].copy_from_slice(&seq.to_be_bytes());

    // Acknowledgment number (4 bytes) - 0 for SYN
    packet[8..12].copy_from_slice(&0u32.to_be_bytes());

    // Data offset (4 bits) + reserved (4 bits)
    // Data offset = 5 (20 bytes / 4 = 5 32-bit words)
    packet[12] = 0x50;

    // Flags (SYN = 0x02)
    packet[13] = TCP_FLAG_SYN;

    // Window size (2 bytes)
    packet[14..16].copy_from_slice(&65535u16.to_be_bytes());

    // Checksum (2 bytes) - calculated below
    // packet[16..18] = checksum

    // Urgent pointer (2 bytes) - 0
    packet[18..20].copy_from_slice(&0u16.to_be_bytes());

    // Calculate TCP checksum
    let checksum = tcp_checksum(&packet, src_ip, dst_ip);
    packet[16..18].copy_from_slice(&checksum.to_be_bytes());

    packet
}

/// Calculate TCP checksum including pseudo-header
fn tcp_checksum(tcp_header: &[u8], src_ip: IpAddr, dst_ip: IpAddr) -> u16 {
    let mut sum: u32 = 0;

    // Pseudo-header contribution
    match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            // IPv4 pseudo-header: src_ip (4) + dst_ip (4) + zero (1) + protocol (1) + tcp_len (2)
            for octet in src.octets().chunks(2) {
                sum += u16::from_be_bytes([octet[0], octet[1]]) as u32;
            }
            for octet in dst.octets().chunks(2) {
                sum += u16::from_be_bytes([octet[0], octet[1]]) as u32;
            }
            sum += IPPROTO_TCP as u32;
            sum += tcp_header.len() as u32;
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            // IPv6 pseudo-header: src_ip (16) + dst_ip (16) + tcp_len (4) + zeros (3) + next_header (1)
            for chunk in src.octets().chunks(2) {
                sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
            }
            for chunk in dst.octets().chunks(2) {
                sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
            }
            sum += tcp_header.len() as u32;
            sum += IPPROTO_TCP as u32;
        }
        _ => {
            // Mixed IPv4/IPv6 - shouldn't happen
            return 0;
        }
    }

    // TCP header contribution (treating checksum field as 0)
    let mut i = 0;
    while i + 1 < tcp_header.len() {
        // Skip checksum field at offset 16-17
        if i != 16 {
            sum += u16::from_be_bytes([tcp_header[i], tcp_header[i + 1]]) as u32;
        }
        i += 2;
    }

    // Handle odd byte if present
    if i < tcp_header.len() {
        sum += (tcp_header[i] as u32) << 8;
    }

    // Fold 32-bit sum to 16 bits
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // One's complement
    !sum as u16
}

/// Create a raw TCP socket for sending SYN probes
pub fn create_tcp_socket(ipv6: bool) -> Result<Socket> {
    let domain = if ipv6 { Domain::IPV6 } else { Domain::IPV4 };

    // Use SOCK_RAW with IPPROTO_TCP
    // Requires root/CAP_NET_RAW
    let socket = Socket::new(domain, Type::RAW, Some(Protocol::TCP))?;

    socket.set_nonblocking(false)?;
    socket.set_read_timeout(Some(Duration::from_secs(1)))?;

    Ok(socket)
}

/// Send a TCP SYN probe to target
pub fn send_tcp_probe(
    socket: &Socket,
    packet: &[u8],
    target: IpAddr,
    port: u16,
) -> Result<usize> {
    let addr = SocketAddr::new(target, port);
    let sock_addr = SockAddr::from(addr);
    let sent = socket.send_to(packet, &sock_addr)?;
    Ok(sent)
}

/// Extract ProbeId from TCP header in ICMP error payload
/// The TCP header appears after the original IP header in ICMP errors
pub fn extract_probe_id_from_tcp(tcp_header: &[u8]) -> Option<ProbeId> {
    if tcp_header.len() < 8 {
        return None;
    }

    // Extract sequence number (bytes 4-7)
    let seq = u32::from_be_bytes([tcp_header[4], tcp_header[5], tcp_header[6], tcp_header[7]]);

    // Probe ID is in high 16 bits of sequence number
    let probe_seq = (seq >> 16) as u16;

    Some(ProbeId::from_sequence(probe_seq))
}

/// Get the source IP address for checksum calculation
/// Uses UDP connect trick to determine the local IP that routes to target
pub fn get_local_addr(target: IpAddr) -> IpAddr {
    use std::net::UdpSocket;

    // UDP connect trick: connect a UDP socket to the target to determine
    // which local IP the kernel would use for routing
    let bind_addr = match target {
        IpAddr::V4(_) => "0.0.0.0:0",
        IpAddr::V6(_) => "[::]:0",
    };

    let target_addr = std::net::SocketAddr::new(target, 80);

    if let Ok(socket) = UdpSocket::bind(bind_addr) {
        if socket.connect(target_addr).is_ok() {
            if let Ok(local_addr) = socket.local_addr() {
                return local_addr.ip();
            }
        }
    }

    // Fallback to unspecified if lookup fails
    match target {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_syn_roundtrip() {
        let probe_id = ProbeId::new(15, 42);
        let src_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let dst_ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));

        let packet = build_tcp_syn(probe_id, TCP_SRC_PORT, 80, src_ip, dst_ip);

        // Verify packet structure
        assert_eq!(packet.len(), 20);

        // Verify SYN flag
        assert_eq!(packet[13], TCP_FLAG_SYN);

        // Extract and verify probe_id
        let extracted = extract_probe_id_from_tcp(&packet);
        assert!(extracted.is_some());

        let extracted = extracted.unwrap();
        assert_eq!(extracted.ttl, 15);
        assert_eq!(extracted.seq, 42);
    }

    #[test]
    fn test_tcp_header_too_short() {
        let packet = vec![0u8; 4]; // Only 4 bytes
        let extracted = extract_probe_id_from_tcp(&packet);
        assert!(extracted.is_none());
    }

    #[test]
    fn test_tcp_checksum_nonzero() {
        let probe_id = ProbeId::new(1, 1);
        let src_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let dst_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        let packet = build_tcp_syn(probe_id, TCP_SRC_PORT, 80, src_ip, dst_ip);

        // Checksum should be non-zero
        let checksum = u16::from_be_bytes([packet[16], packet[17]]);
        assert_ne!(checksum, 0);
    }
}
