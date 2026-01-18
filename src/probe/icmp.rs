use pnet::packet::MutablePacket;
use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
use pnet::packet::icmp::{IcmpCode, IcmpType, IcmpTypes, checksum};
use std::net::Ipv6Addr;

/// ICMP header size (fixed)
pub const ICMP_HEADER_SIZE: usize = 8;
/// Default payload size (standard ping)
pub const DEFAULT_PAYLOAD_SIZE: usize = 56;
/// Minimum payload size (4 bytes ProbeId + 4 bytes timestamp)
pub const MIN_PAYLOAD_SIZE: usize = 8;

/// Calculate ICMPv6 checksum including IPv6 pseudo-header.
///
/// ICMPv6 checksum (RFC 8200) covers the IPv6 pseudo-header + ICMP message.
/// Pseudo-header: src addr, dest addr, upper-layer length, next header (58).
///
/// Algorithm derived from trippy (BSD-licensed).
fn icmp_ipv6_checksum(data: &[u8], src_addr: Ipv6Addr, dest_addr: Ipv6Addr) -> u16 {
    let mut sum = 0u32;

    // Add source address (8 x 16-bit words)
    for segment in src_addr.segments() {
        sum += u32::from(segment);
    }

    // Add destination address (8 x 16-bit words)
    for segment in dest_addr.segments() {
        sum += u32::from(segment);
    }

    // Add upper-layer packet length
    sum += data.len() as u32;

    // Add next header (ICMPv6 = 58)
    sum += 58u32;

    // Add ICMP data (16-bit words, skip checksum field at bytes 2-3)
    let mut i = 0;
    while i + 1 < data.len() {
        if i != 2 {
            // Skip checksum field
            sum += u32::from(u16::from_be_bytes([data[i], data[i + 1]]));
        }
        i += 2;
    }
    // Handle odd trailing byte
    if i < data.len() {
        sum += u32::from(data[i]) << 8;
    }

    // Fold 32-bit sum to 16-bit with carry
    while sum >> 16 != 0 {
        sum = (sum >> 16) + (sum & 0xFFFF);
    }

    !sum as u16
}

/// Get process identifier for ICMP identification field
pub fn get_identifier() -> u16 {
    std::process::id() as u16
}

/// Build an ICMP Echo Request packet with configurable payload size
///
/// Set ipv6=true to build an ICMPv6 Echo Request.
///
/// For IPv6, pass `ipv6_addrs = Some((src, dest))` to compute the ICMPv6 checksum.
/// The checksum requires the IPv6 pseudo-header which includes source/dest addresses.
///
/// Payload layout (for macOS DGRAM correlation fallback):
/// - Bytes 0-1: identifier (backup for kernel override on macOS DGRAM sockets)
/// - Bytes 2-3: sequence (backup for kernel override)
/// - Bytes 4-7: timestamp (lower 32 bits)
/// - Bytes 8+: pattern fill
pub fn build_echo_request(
    identifier: u16,
    sequence: u16,
    payload_size: usize,
    ipv6: bool,
    ipv6_addrs: Option<(Ipv6Addr, Ipv6Addr)>,
) -> Vec<u8> {
    // Catch future callers who forget to pass addresses for IPv6
    debug_assert!(
        !ipv6 || ipv6_addrs.is_some(),
        "IPv6 requires ipv6_addrs for checksum computation"
    );

    let payload_size = payload_size.max(MIN_PAYLOAD_SIZE);
    let packet_size = ICMP_HEADER_SIZE + payload_size;
    let mut buffer = vec![0u8; packet_size];

    let mut packet = MutableEchoRequestPacket::new(&mut buffer).unwrap();

    if ipv6 {
        packet.set_icmp_type(IcmpType::new(128));
    } else {
        packet.set_icmp_type(IcmpTypes::EchoRequest);
    }
    packet.set_icmp_code(IcmpCode::new(0));
    packet.set_identifier(identifier);
    packet.set_sequence_number(sequence);

    // Fill payload
    let payload = packet.payload_mut();

    // Embed identifier and sequence at bytes 0-3 for macOS DGRAM fallback
    // (kernel may override ICMP header identifier on DGRAM sockets)
    payload[0..2].copy_from_slice(&identifier.to_be_bytes());
    payload[2..4].copy_from_slice(&sequence.to_be_bytes());

    // Put timestamp in bytes 4-7 (lower 32 bits)
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_micros() as u32;
    payload[4..8].copy_from_slice(&timestamp.to_be_bytes());

    // Fill rest with pattern
    for (i, byte) in payload[8..].iter_mut().enumerate() {
        *byte = (i & 0xFF) as u8;
    }

    // Calculate checksum
    if ipv6 {
        // ICMPv6 checksum requires IPv6 pseudo-header (includes src/dest addresses)
        if let Some((src, dest)) = ipv6_addrs {
            let cksum = icmp_ipv6_checksum(&buffer, src, dest);
            let mut packet = MutableEchoRequestPacket::new(&mut buffer).unwrap();
            packet.set_checksum(cksum);
        }
        // If no addresses provided, leave checksum as 0 (legacy behavior)
    } else {
        // IPv4 ICMP checksum (no pseudo-header needed)
        let cksum = checksum(&pnet::packet::icmp::IcmpPacket::new(&buffer).unwrap());
        let mut packet = MutableEchoRequestPacket::new(&mut buffer).unwrap();
        packet.set_checksum(cksum);
    }

    buffer
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_echo_request() {
        let packet = build_echo_request(1234, 5678, DEFAULT_PAYLOAD_SIZE, false, None);
        assert_eq!(packet.len(), ICMP_HEADER_SIZE + DEFAULT_PAYLOAD_SIZE);
        assert_eq!(packet[0], 8); // Echo Request type
        assert_eq!(packet[1], 0); // Code
    }

    #[test]
    fn test_build_echo_request_ipv6() {
        use std::str::FromStr;
        let src = Ipv6Addr::from_str("2001:db8::1").unwrap();
        let dest = Ipv6Addr::from_str("2001:db8::2").unwrap();
        let packet = build_echo_request(1234, 5678, DEFAULT_PAYLOAD_SIZE, true, Some((src, dest)));
        assert_eq!(packet.len(), ICMP_HEADER_SIZE + DEFAULT_PAYLOAD_SIZE);
        assert_eq!(packet[0], 128); // ICMPv6 Echo Request type
        assert_eq!(packet[1], 0); // Code
    }

    #[test]
    fn test_build_echo_request_ipv6_with_checksum() {
        use std::str::FromStr;
        let src = Ipv6Addr::from_str("2001:db8::1").unwrap();
        let dest = Ipv6Addr::from_str("2001:db8::2").unwrap();
        let packet = build_echo_request(1234, 5678, DEFAULT_PAYLOAD_SIZE, true, Some((src, dest)));
        assert_eq!(packet.len(), ICMP_HEADER_SIZE + DEFAULT_PAYLOAD_SIZE);
        assert_eq!(packet[0], 128); // ICMPv6 Echo Request type
        assert_eq!(packet[1], 0); // Code
        // Checksum should be non-zero
        let cksum = u16::from_be_bytes([packet[2], packet[3]]);
        assert_ne!(cksum, 0, "ICMPv6 checksum should be computed");
    }

    #[test]
    fn test_icmp_ipv6_checksum_known_value() {
        // Test fixture from trippy (BSD-licensed) to verify checksum correctness
        use std::str::FromStr;
        let src_addr = Ipv6Addr::from_str("fe80::811:3f6:7601:6c3f").unwrap();
        let dest_addr = Ipv6Addr::from_str("fe80::1c8d:7d69:d0b6:8182").unwrap();
        let bytes = [
            0x88, 0x00, 0x73, 0x6a, 0x40, 0x00, 0x00, 0x00, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x08, 0x11, 0x03, 0xf6, 0x76, 0x01, 0x6c, 0x3f,
        ];
        assert_eq!(29546, icmp_ipv6_checksum(&bytes, src_addr, dest_addr));
    }

    #[test]
    fn test_build_echo_request_custom_size() {
        // Test larger payload
        let packet = build_echo_request(1234, 5678, 1400, false, None);
        assert_eq!(packet.len(), ICMP_HEADER_SIZE + 1400);

        // Test minimum payload
        let packet = build_echo_request(1234, 5678, 0, false, None);
        assert_eq!(packet.len(), ICMP_HEADER_SIZE + MIN_PAYLOAD_SIZE);
    }
}
