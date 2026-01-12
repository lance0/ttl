use crate::state::{IcmpResponseType, ProbeId};
use pnet::packet::icmp::{IcmpPacket, IcmpTypes};
use pnet::packet::ipv4::Ipv4Packet;
use std::net::IpAddr;

// ICMPv6 type codes
const ICMPV6_ECHO_REPLY: u8 = 129;
const ICMPV6_TIME_EXCEEDED: u8 = 3;
const ICMPV6_DEST_UNREACHABLE: u8 = 1;

// ICMPv6 Echo Request type (for error payload validation)
const ICMPV6_ECHO_REQUEST: u8 = 128;

/// Parsed ICMP response
#[derive(Debug, Clone)]
pub struct ParsedResponse {
    pub responder: IpAddr,
    pub probe_id: ProbeId,
    pub response_type: IcmpResponseType,
}

/// Calculate ICMP checksum (RFC 1071)
/// Returns true if checksum is valid (sums to 0xFFFF or 0x0000 after folding)
fn validate_icmp_checksum(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }

    let mut sum: u32 = 0;

    // Sum 16-bit words
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }

    // Handle odd byte
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }

    // Fold 32-bit sum to 16 bits
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // Valid checksum results in 0xFFFF (or 0x0000 for zero checksum)
    sum == 0xFFFF || sum == 0x0000
}

/// Parse an ICMP response and correlate it to our probe
///
/// Returns None if:
/// - Packet is malformed
/// - Packet is not a response to our probe (wrong identifier)
/// - ICMP checksum is invalid (for Echo Reply only)
pub fn parse_icmp_response(
    data: &[u8],
    responder: IpAddr,
    our_identifier: u16,
) -> Option<ParsedResponse> {
    // Detect IP version from first nibble
    if data.is_empty() {
        return None;
    }

    let ip_version = (data[0] >> 4) & 0x0F;

    match ip_version {
        4 => parse_icmp_response_v4(data, responder, our_identifier),
        6 => parse_icmp_response_v6(data, responder, our_identifier),
        _ => None,
    }
}

/// Parse IPv4 ICMP response
fn parse_icmp_response_v4(
    data: &[u8],
    responder: IpAddr,
    our_identifier: u16,
) -> Option<ParsedResponse> {
    let ip_packet = Ipv4Packet::new(data)?;
    let ip_header_len = (ip_packet.get_header_length() as usize) * 4;

    if data.len() < ip_header_len + 8 {
        return None;
    }

    let icmp_data = &data[ip_header_len..];
    let icmp_packet = IcmpPacket::new(icmp_data)?;

    let icmp_type = icmp_packet.get_icmp_type();

    match icmp_type {
        IcmpTypes::EchoReply => {
            // Echo Reply: identifier and sequence are in bytes 4-7
            if icmp_data.len() < 8 {
                return None;
            }

            // Validate ICMP checksum for Echo Reply
            if !validate_icmp_checksum(icmp_data) {
                return None;
            }

            let identifier = u16::from_be_bytes([icmp_data[4], icmp_data[5]]);
            let sequence = u16::from_be_bytes([icmp_data[6], icmp_data[7]]);

            if identifier != our_identifier {
                return None;
            }

            Some(ParsedResponse {
                responder,
                probe_id: ProbeId::from_sequence(sequence),
                response_type: IcmpResponseType::EchoReply,
            })
        }
        IcmpTypes::TimeExceeded => {
            parse_icmp_error_payload_v4(icmp_data, responder, our_identifier, IcmpResponseType::TimeExceeded)
        }
        IcmpTypes::DestinationUnreachable => {
            let code = icmp_packet.get_icmp_code().0;
            parse_icmp_error_payload_v4(
                icmp_data,
                responder,
                our_identifier,
                IcmpResponseType::DestUnreachable(code),
            )
        }
        _ => None,
    }
}

// IPv6 Next Header protocol numbers
const IPV6_NH_HOP_BY_HOP: u8 = 0;
const IPV6_NH_ROUTING: u8 = 43;
const IPV6_NH_FRAGMENT: u8 = 44;
const IPV6_NH_ICMPV6: u8 = 58;
const IPV6_NH_NO_NEXT: u8 = 59;
const IPV6_NH_DEST_OPTS: u8 = 60;

/// Skip IPv6 extension headers and return offset to ICMPv6 payload
/// Returns None if ICMPv6 is not the upper layer protocol
fn skip_ipv6_extension_headers(data: &[u8]) -> Option<usize> {
    const IPV6_HEADER_LEN: usize = 40;

    if data.len() < IPV6_HEADER_LEN {
        return None;
    }

    // Next Header field is at byte 6 of IPv6 header
    let mut next_header = data[6];
    let mut offset = IPV6_HEADER_LEN;

    // Walk through extension headers until we find ICMPv6 or something else
    loop {
        match next_header {
            IPV6_NH_ICMPV6 => {
                // Found ICMPv6
                return Some(offset);
            }
            IPV6_NH_HOP_BY_HOP | IPV6_NH_ROUTING | IPV6_NH_DEST_OPTS => {
                // Variable-length extension header
                // Byte 0: Next Header, Byte 1: Length (in 8-octet units, excluding first 8)
                if data.len() < offset + 2 {
                    return None;
                }
                next_header = data[offset];
                let ext_len = (data[offset + 1] as usize + 1) * 8;
                offset += ext_len;
                if offset > data.len() {
                    return None;
                }
            }
            IPV6_NH_FRAGMENT => {
                // Fragment header is fixed 8 bytes
                if data.len() < offset + 8 {
                    return None;
                }
                next_header = data[offset];
                offset += 8;
            }
            IPV6_NH_NO_NEXT => {
                // No upper layer payload
                return None;
            }
            _ => {
                // Unknown or unsupported protocol (ESP, AH, etc.)
                // Can't safely skip, so reject
                return None;
            }
        }
    }
}

/// Parse IPv6 ICMPv6 response
///
/// Note: ICMPv6 checksum validation is intentionally omitted. Unlike ICMPv4,
/// ICMPv6 checksums require the IPv6 pseudo-header (source/dest addresses,
/// payload length, next header) which isn't available after extension header
/// parsing. The kernel validates ICMPv6 checksums before delivery to raw sockets.
fn parse_icmp_response_v6(
    data: &[u8],
    responder: IpAddr,
    our_identifier: u16,
) -> Option<ParsedResponse> {
    // Skip any extension headers to find ICMPv6
    let icmp_offset = skip_ipv6_extension_headers(data)?;

    if data.len() < icmp_offset + 8 {
        return None;
    }

    let icmp_data = &data[icmp_offset..];
    let icmp_type = icmp_data[0];
    let icmp_code = icmp_data[1];

    match icmp_type {
        ICMPV6_ECHO_REPLY => {
            if icmp_data.len() < 8 {
                return None;
            }
            let identifier = u16::from_be_bytes([icmp_data[4], icmp_data[5]]);
            let sequence = u16::from_be_bytes([icmp_data[6], icmp_data[7]]);

            if identifier != our_identifier {
                return None;
            }

            Some(ParsedResponse {
                responder,
                probe_id: ProbeId::from_sequence(sequence),
                response_type: IcmpResponseType::EchoReply,
            })
        }
        ICMPV6_TIME_EXCEEDED => {
            parse_icmp_error_payload_v6(icmp_data, responder, our_identifier, IcmpResponseType::TimeExceeded)
        }
        ICMPV6_DEST_UNREACHABLE => {
            parse_icmp_error_payload_v6(
                icmp_data,
                responder,
                our_identifier,
                IcmpResponseType::DestUnreachable(icmp_code),
            )
        }
        _ => None,
    }
}

/// Parse the payload of an IPv4 ICMP error message (Time Exceeded or Dest Unreachable)
fn parse_icmp_error_payload_v4(
    icmp_data: &[u8],
    responder: IpAddr,
    our_identifier: u16,
    response_type: IcmpResponseType,
) -> Option<ParsedResponse> {
    // ICMP error format:
    // [0-3]  ICMP header (type, code, checksum)
    // [4-7]  Unused (4 bytes)
    // [8..]  Original IP header + first 8 bytes of original ICMP

    if icmp_data.len() < 8 + 20 + 8 {
        // Need at least ICMP header + IP header + ICMP header
        return None;
    }

    let original_ip_data = &icmp_data[8..];
    let original_ip = Ipv4Packet::new(original_ip_data)?;
    let orig_ihl = (original_ip.get_header_length() as usize) * 4;

    if original_ip_data.len() < orig_ihl + 8 {
        return None;
    }

    let original_icmp_data = &original_ip_data[orig_ihl..];

    // Extract identifier and sequence from original ICMP header
    // [0]    Type (should be 8 for Echo Request)
    // [1]    Code (should be 0)
    // [2-3]  Checksum
    // [4-5]  Identifier
    // [6-7]  Sequence

    if original_icmp_data[0] != 8 {
        // Not our Echo Request
        return None;
    }

    let identifier = u16::from_be_bytes([original_icmp_data[4], original_icmp_data[5]]);
    let sequence = u16::from_be_bytes([original_icmp_data[6], original_icmp_data[7]]);

    if identifier != our_identifier {
        return None;
    }

    Some(ParsedResponse {
        responder,
        probe_id: ProbeId::from_sequence(sequence),
        response_type,
    })
}

/// Parse the payload of an IPv6 ICMPv6 error message (Time Exceeded or Dest Unreachable)
///
/// Note: Assumes the embedded original IPv6 packet has no extension headers.
/// This is valid for our use case since we send ICMPv6 Echo Requests directly
/// (Next Header = 58) without any extension headers.
fn parse_icmp_error_payload_v6(
    icmp_data: &[u8],
    responder: IpAddr,
    our_identifier: u16,
    response_type: IcmpResponseType,
) -> Option<ParsedResponse> {
    // ICMPv6 error format:
    // [0-3]  ICMPv6 header (type, code, checksum)
    // [4-7]  Unused (4 bytes)
    // [8..]  Original IPv6 header (40 bytes) + first 8 bytes of original ICMPv6

    const IPV6_HEADER_LEN: usize = 40;

    if icmp_data.len() < 8 + IPV6_HEADER_LEN + 8 {
        return None;
    }

    let original_ipv6_data = &icmp_data[8..];
    let original_icmp_data = &original_ipv6_data[IPV6_HEADER_LEN..];

    // Extract identifier and sequence from original ICMPv6 header
    // [0]    Type (should be 128 for Echo Request)
    // [1]    Code (should be 0)
    // [2-3]  Checksum
    // [4-5]  Identifier
    // [6-7]  Sequence

    if original_icmp_data[0] != ICMPV6_ECHO_REQUEST {
        // Not our Echo Request
        return None;
    }

    let identifier = u16::from_be_bytes([original_icmp_data[4], original_icmp_data[5]]);
    let sequence = u16::from_be_bytes([original_icmp_data[6], original_icmp_data[7]]);

    if identifier != our_identifier {
        return None;
    }

    Some(ParsedResponse {
        responder,
        probe_id: ProbeId::from_sequence(sequence),
        response_type,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to compute and set ICMP checksum for a packet slice
    /// Assumes checksum field is at offset 2-3 of the ICMP section
    fn set_icmp_checksum(icmp_data: &mut [u8]) {
        // Clear checksum field first
        icmp_data[2] = 0;
        icmp_data[3] = 0;

        let mut sum: u32 = 0;
        let mut i = 0;
        while i + 1 < icmp_data.len() {
            sum += u16::from_be_bytes([icmp_data[i], icmp_data[i + 1]]) as u32;
            i += 2;
        }
        if i < icmp_data.len() {
            sum += (icmp_data[i] as u32) << 8;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        let checksum = !sum as u16;
        icmp_data[2] = (checksum >> 8) as u8;
        icmp_data[3] = (checksum & 0xFF) as u8;
    }

    #[test]
    fn test_probe_id_round_trip() {
        let original = ProbeId::new(15, 42);
        let sequence = original.to_sequence();
        let decoded = ProbeId::from_sequence(sequence);
        assert_eq!(original.ttl, decoded.ttl);
        assert_eq!(original.seq, decoded.seq);
    }

    #[test]
    fn test_probe_id_boundary_values() {
        // Test max TTL and seq values
        let max = ProbeId::new(255, 255);
        let decoded = ProbeId::from_sequence(max.to_sequence());
        assert_eq!(max.ttl, decoded.ttl);
        assert_eq!(max.seq, decoded.seq);

        // Test zero values
        let zero = ProbeId::new(0, 0);
        let decoded = ProbeId::from_sequence(zero.to_sequence());
        assert_eq!(zero.ttl, decoded.ttl);
        assert_eq!(zero.seq, decoded.seq);
    }

    #[test]
    fn test_empty_packet_returns_none() {
        let responder = IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1));
        assert!(parse_icmp_response(&[], responder, 0x1234).is_none());
    }

    #[test]
    fn test_truncated_packet_returns_none() {
        let responder = IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1));
        // Just an IP version nibble, nothing else
        let truncated = [0x45]; // IPv4, IHL=5
        assert!(parse_icmp_response(&truncated, responder, 0x1234).is_none());
    }

    #[test]
    fn test_invalid_ip_version_returns_none() {
        let responder = IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1));
        // IP version 3 doesn't exist
        let invalid = [0x30, 0x00, 0x00, 0x00];
        assert!(parse_icmp_response(&invalid, responder, 0x1234).is_none());
    }

    #[test]
    fn test_identifier_mismatch_returns_none() {
        let responder = IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1));
        // Build a valid-looking Echo Reply packet with wrong identifier
        // IPv4 header (20 bytes minimum with IHL=5) + ICMP header (8 bytes)
        let mut packet = vec![0u8; 28];

        // IPv4 header
        packet[0] = 0x45; // Version 4, IHL 5
        packet[9] = 1;    // Protocol: ICMP

        // ICMP Echo Reply
        packet[20] = 0;   // Type: Echo Reply
        packet[21] = 0;   // Code: 0
        // Identifier: 0x5678 (wrong - we're looking for 0x1234)
        packet[24] = 0x56;
        packet[25] = 0x78;
        // Sequence
        packet[26] = 0x00;
        packet[27] = 0x01;

        assert!(parse_icmp_response(&packet, responder, 0x1234).is_none());
    }

    #[test]
    fn test_parse_echo_reply_v4() {
        let responder = IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8));
        let our_id = 0x1234;

        // Build Echo Reply packet
        let mut packet = vec![0u8; 28];

        // IPv4 header
        packet[0] = 0x45; // Version 4, IHL 5 (20 bytes)
        packet[9] = 1;    // Protocol: ICMP

        // ICMP Echo Reply
        packet[20] = 0;   // Type: Echo Reply
        packet[21] = 0;   // Code: 0
        // Identifier
        packet[24] = 0x12;
        packet[25] = 0x34;
        // Sequence (TTL=10, seq=5)
        let probe_id = ProbeId::new(10, 5);
        let seq = probe_id.to_sequence();
        packet[26] = (seq >> 8) as u8;
        packet[27] = (seq & 0xFF) as u8;

        // Set valid ICMP checksum
        set_icmp_checksum(&mut packet[20..]);

        let result = parse_icmp_response(&packet, responder, our_id);
        assert!(result.is_some());

        let parsed = result.unwrap();
        assert_eq!(parsed.responder, responder);
        assert_eq!(parsed.probe_id.ttl, 10);
        assert_eq!(parsed.probe_id.seq, 5);
        assert_eq!(parsed.response_type, IcmpResponseType::EchoReply);
    }

    #[test]
    fn test_parse_time_exceeded_v4() {
        let responder = IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1));
        let our_id = 0xABCD;

        // Build Time Exceeded packet
        // Outer IPv4 (20) + ICMP header (8) + Original IPv4 (20) + Original ICMP (8) = 56 bytes
        let mut packet = vec![0u8; 56];

        // Outer IPv4 header
        packet[0] = 0x45;
        packet[9] = 1; // ICMP

        // ICMP Time Exceeded
        packet[20] = 11;  // Type: Time Exceeded
        packet[21] = 0;   // Code: TTL exceeded

        // Original IP header (inside ICMP payload at offset 28)
        packet[28] = 0x45; // Version 4, IHL 5
        packet[37] = 1;    // Protocol: ICMP

        // Original ICMP Echo Request (at offset 48)
        packet[48] = 8;    // Type: Echo Request
        packet[49] = 0;    // Code: 0
        // Identifier
        packet[52] = 0xAB;
        packet[53] = 0xCD;
        // Sequence (TTL=5, seq=3)
        let probe_id = ProbeId::new(5, 3);
        let seq = probe_id.to_sequence();
        packet[54] = (seq >> 8) as u8;
        packet[55] = (seq & 0xFF) as u8;

        let result = parse_icmp_response(&packet, responder, our_id);
        assert!(result.is_some());

        let parsed = result.unwrap();
        assert_eq!(parsed.probe_id.ttl, 5);
        assert_eq!(parsed.probe_id.seq, 3);
        assert_eq!(parsed.response_type, IcmpResponseType::TimeExceeded);
    }

    #[test]
    fn test_variable_ihl_v4() {
        let responder = IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8));
        let our_id = 0x1234;

        // Build Echo Reply with IHL=6 (24 byte IP header with options)
        let mut packet = vec![0u8; 32]; // 24 IP + 8 ICMP

        // IPv4 header with IHL=6
        packet[0] = 0x46; // Version 4, IHL 6 (24 bytes)
        packet[9] = 1;    // Protocol: ICMP

        // ICMP Echo Reply at offset 24
        packet[24] = 0;   // Type: Echo Reply
        packet[25] = 0;   // Code: 0
        // Identifier
        packet[28] = 0x12;
        packet[29] = 0x34;
        // Sequence
        let probe_id = ProbeId::new(7, 2);
        let seq = probe_id.to_sequence();
        packet[30] = (seq >> 8) as u8;
        packet[31] = (seq & 0xFF) as u8;

        // Set valid ICMP checksum (ICMP starts at offset 24)
        set_icmp_checksum(&mut packet[24..]);

        let result = parse_icmp_response(&packet, responder, our_id);
        assert!(result.is_some());

        let parsed = result.unwrap();
        assert_eq!(parsed.probe_id.ttl, 7);
        assert_eq!(parsed.probe_id.seq, 2);
    }
}
