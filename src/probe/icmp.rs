use pnet::packet::MutablePacket;
use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
use pnet::packet::icmp::{IcmpCode, IcmpType, IcmpTypes, checksum};

/// ICMP header size (fixed)
pub const ICMP_HEADER_SIZE: usize = 8;
/// Default payload size (standard ping)
pub const DEFAULT_PAYLOAD_SIZE: usize = 56;
/// Minimum payload size (4 bytes ProbeId + 4 bytes timestamp)
pub const MIN_PAYLOAD_SIZE: usize = 8;

/// Get process identifier for ICMP identification field
pub fn get_identifier() -> u16 {
    std::process::id() as u16
}

/// Build an ICMP Echo Request packet with configurable payload size
///
/// Set ipv6=true to build an ICMPv6 Echo Request.
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
) -> Vec<u8> {
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
    if !ipv6 {
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
        let packet = build_echo_request(1234, 5678, DEFAULT_PAYLOAD_SIZE, false);
        assert_eq!(packet.len(), ICMP_HEADER_SIZE + DEFAULT_PAYLOAD_SIZE);
        assert_eq!(packet[0], 8); // Echo Request type
        assert_eq!(packet[1], 0); // Code
    }

    #[test]
    fn test_build_echo_request_ipv6() {
        let packet = build_echo_request(1234, 5678, DEFAULT_PAYLOAD_SIZE, true);
        assert_eq!(packet.len(), ICMP_HEADER_SIZE + DEFAULT_PAYLOAD_SIZE);
        assert_eq!(packet[0], 128); // ICMPv6 Echo Request type
        assert_eq!(packet[1], 0); // Code
    }

    #[test]
    fn test_build_echo_request_custom_size() {
        // Test larger payload
        let packet = build_echo_request(1234, 5678, 1400, false);
        assert_eq!(packet.len(), ICMP_HEADER_SIZE + 1400);

        // Test minimum payload
        let packet = build_echo_request(1234, 5678, 0, false);
        assert_eq!(packet.len(), ICMP_HEADER_SIZE + MIN_PAYLOAD_SIZE);
    }
}
