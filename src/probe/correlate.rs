use crate::probe::tcp::extract_probe_id_from_tcp;
use crate::probe::udp::extract_probe_id_from_udp_payload;
use crate::state::{IcmpResponseType, MplsLabel, ProbeId};
use pnet::packet::icmp::{IcmpPacket, IcmpTypes};
use pnet::packet::ipv4::Ipv4Packet;
use std::net::IpAddr;

// IP protocol numbers
const IPPROTO_ICMP: u8 = 1;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_ICMPV6: u8 = 58;

// ICMPv6 type codes
const ICMPV6_ECHO_REPLY: u8 = 129;
const ICMPV6_PACKET_TOO_BIG: u8 = 2;
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
    /// MPLS labels from ICMP extensions (RFC 4950), if present
    pub mpls_labels: Option<Vec<MplsLabel>>,
    /// Source port from original UDP/TCP packet (for flow identification in Paris/Dublin traceroute)
    /// This allows the receiver to compute flow_id = src_port - base_src_port
    pub src_port: Option<u16>,
    /// MTU from ICMP Fragmentation Needed (Type 3 Code 4) or ICMPv6 Packet Too Big (Type 2)
    /// Used for Path MTU Discovery
    pub mtu: Option<u16>,
    /// TTL from quoted IP header in ICMP error (for TTL manipulation detection)
    /// For Time Exceeded, this should be 0 or 1 per RFC; values > 1 suggest manipulation
    pub quoted_ttl: Option<u8>,
    /// Original destination IP from quoted packet in ICMP error
    /// Used to disambiguate multi-target responses
    pub original_dest: Option<IpAddr>,
}

// ICMP extension constants (RFC 4884, RFC 4950)
const ICMP_EXT_VERSION: u8 = 2;
const MPLS_LABEL_STACK_CLASS: u8 = 1;
const MPLS_LABEL_STACK_TYPE: u8 = 1;
const MIN_ORIGINAL_DATAGRAM: usize = 128;

/// Parse ICMP extensions from an error message payload (RFC 4884)
/// Returns MPLS label stack if present (RFC 4950)
///
/// The icmp_payload parameter should be the ICMP error payload starting
/// after the 8-byte ICMP header (i.e., starting with the original datagram).
/// The icmp_length parameter is the "length" field from the ICMP header
/// (byte 5 of the full ICMP message), which indicates the original datagram
/// length in 32-bit words when non-zero.
fn parse_icmp_extensions_with_length(
    icmp_payload: &[u8],
    icmp_length: u8,
) -> Option<Vec<MplsLabel>> {
    // RFC 4884: The "length" field indicates original datagram length in 32-bit words
    // If non-zero, extensions start at (length * 4) bytes
    // If zero (legacy), extensions start at 128 bytes (if present)
    let ext_start = if icmp_length > 0 {
        (icmp_length as usize) * 4
    } else {
        MIN_ORIGINAL_DATAGRAM
    };

    if icmp_payload.len() < ext_start + 4 {
        return None;
    }

    let ext_header = &icmp_payload[ext_start..];

    // Version (high nibble of first byte) must be 2
    let version = (ext_header[0] >> 4) & 0x0F;
    if version != ICMP_EXT_VERSION {
        return None;
    }

    // Skip checksum validation for now (optional in compliant mode)
    // Parse extension objects starting at offset 4
    let mut offset = 4;
    while offset + 4 <= ext_header.len() {
        // Object header: length (16 bits), class (8 bits), type (8 bits)
        let obj_length = u16::from_be_bytes([ext_header[offset], ext_header[offset + 1]]) as usize;
        let obj_class = ext_header[offset + 2];
        let obj_type = ext_header[offset + 3];

        // Validate object length
        if obj_length < 4 || offset + obj_length > ext_header.len() {
            break;
        }

        // Check for MPLS Label Stack (class=1, type=1)
        if obj_class == MPLS_LABEL_STACK_CLASS && obj_type == MPLS_LABEL_STACK_TYPE {
            let label_data = &ext_header[offset + 4..offset + obj_length];
            let mut labels = Vec::new();

            // Each label entry is 4 bytes
            for chunk in label_data.chunks_exact(4) {
                // chunks_exact(4) guarantees chunk.len() == 4, so this is infallible
                let bytes: [u8; 4] = [chunk[0], chunk[1], chunk[2], chunk[3]];
                let label = MplsLabel::from_bytes(&bytes);
                labels.push(label);
                // Stop at bottom of stack
                if label.bottom {
                    break;
                }
            }

            if !labels.is_empty() {
                return Some(labels);
            }
        }

        offset += obj_length;
    }

    None
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
/// When `is_dgram` is true, the packet starts directly at the ICMP header
/// (no IP header, as returned by macOS DGRAM sockets).
///
/// Returns None if:
/// - Packet is malformed
/// - Packet is not a response to our probe (wrong identifier)
/// - ICMP checksum is invalid (for Echo Reply only)
pub fn parse_icmp_response(
    data: &[u8],
    responder: IpAddr,
    our_identifier: u16,
    is_dgram: bool,
) -> Option<ParsedResponse> {
    if data.is_empty() {
        return None;
    }

    if is_dgram {
        // DGRAM socket: no IP header, use responder address to determine version
        if responder.is_ipv4() {
            parse_icmp_response_v4_dgram(data, responder, our_identifier)
        } else {
            parse_icmp_response_v6_dgram(data, responder, our_identifier)
        }
    } else if responder.is_ipv6() {
        // RAW IPv6 socket: Linux kernel strips IPv6 header, delivers ICMPv6 directly
        // Use DGRAM parser which expects no IP header
        parse_icmp_response_v6_dgram(data, responder, our_identifier)
    } else {
        // RAW IPv4 socket: has IP header
        parse_icmp_response_v4(data, responder, our_identifier)
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

            if identifier == our_identifier {
                return Some(ParsedResponse {
                    responder,
                    probe_id: ProbeId::from_sequence(sequence),
                    response_type: IcmpResponseType::EchoReply,
                    mpls_labels: None,
                    src_port: None,
                    mtu: None,
                    quoted_ttl: None,
                    // For Echo Reply, responder IS the target
                    original_dest: Some(responder),
                });
            }

            // Payload fallback: macOS DGRAM send may modify identifier
            // ICMP header is 8 bytes, payload starts at icmp_data[8]
            if icmp_data.len() >= 12
                && let Some((_, payload_seq)) =
                    extract_id_from_payload(&icmp_data[8..], our_identifier)
            {
                return Some(ParsedResponse {
                    responder,
                    probe_id: ProbeId::from_sequence(payload_seq),
                    response_type: IcmpResponseType::EchoReply,
                    mpls_labels: None,
                    src_port: None,
                    mtu: None,
                    quoted_ttl: None,
                    // For Echo Reply, responder IS the target
                    original_dest: Some(responder),
                });
            }
            None
        }
        IcmpTypes::TimeExceeded => {
            let code = icmp_packet.get_icmp_code().0;
            parse_icmp_error_payload_v4_with_mtu(
                icmp_data,
                responder,
                our_identifier,
                IcmpResponseType::TimeExceeded(code),
                None,
            )
        }
        IcmpTypes::DestinationUnreachable => {
            let code = icmp_packet.get_icmp_code().0;
            // For Fragmentation Needed (code 4), extract MTU from bytes 6-7
            let mtu = if code == 4 && icmp_data.len() >= 8 {
                let mtu_val = u16::from_be_bytes([icmp_data[6], icmp_data[7]]);
                if mtu_val > 0 { Some(mtu_val) } else { None }
            } else {
                None
            };
            parse_icmp_error_payload_v4_with_mtu(
                icmp_data,
                responder,
                our_identifier,
                IcmpResponseType::DestUnreachable(code),
                mtu,
            )
        }
        _ => None,
    }
}

// IPv6 Next Header protocol numbers
// Note: These are currently unused because Linux strips the IPv6 header from raw
// ICMPv6 sockets before delivery. Kept for potential future use on other platforms.
#[allow(dead_code)]
const IPV6_NH_HOP_BY_HOP: u8 = 0;
#[allow(dead_code)]
const IPV6_NH_ROUTING: u8 = 43;
#[allow(dead_code)]
const IPV6_NH_FRAGMENT: u8 = 44;
#[allow(dead_code)]
const IPV6_NH_ICMPV6: u8 = 58;
#[allow(dead_code)]
const IPV6_NH_NO_NEXT: u8 = 59;
#[allow(dead_code)]
const IPV6_NH_DEST_OPTS: u8 = 60;

/// Skip IPv6 extension headers and return offset to ICMPv6 payload
/// Returns None if ICMPv6 is not the upper layer protocol
///
/// Note: Currently unused because Linux strips IPv6 headers from raw ICMPv6 sockets.
/// Kept for potential future use on platforms that include the IPv6 header.
#[allow(dead_code)]
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
                // Fragment headers indicate fragmented packets
                // We can't reassemble fragments, so reject them
                return None;
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
///
/// Currently unused because Linux strips IPv6 headers from raw ICMPv6 sockets.
/// The DGRAM parser is used instead. Kept for potential future use.
#[allow(dead_code)]
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

            if identifier == our_identifier {
                return Some(ParsedResponse {
                    responder,
                    probe_id: ProbeId::from_sequence(sequence),
                    response_type: IcmpResponseType::EchoReply,
                    mpls_labels: None,
                    src_port: None,
                    mtu: None,
                    quoted_ttl: None,
                    // For Echo Reply, responder IS the target
                    original_dest: Some(responder),
                });
            }

            // Payload fallback: macOS DGRAM send may modify identifier
            if icmp_data.len() >= 12
                && let Some((_, payload_seq)) =
                    extract_id_from_payload(&icmp_data[8..], our_identifier)
            {
                return Some(ParsedResponse {
                    responder,
                    probe_id: ProbeId::from_sequence(payload_seq),
                    response_type: IcmpResponseType::EchoReply,
                    mpls_labels: None,
                    src_port: None,
                    mtu: None,
                    quoted_ttl: None,
                    // For Echo Reply, responder IS the target
                    original_dest: Some(responder),
                });
            }
            None
        }
        ICMPV6_PACKET_TOO_BIG => {
            // ICMPv6 Packet Too Big (Type 2) - for PMTUD
            // MTU is in bytes 4-7 (32-bit field)
            let mtu = if icmp_data.len() >= 8 {
                let mtu_val =
                    u32::from_be_bytes([icmp_data[4], icmp_data[5], icmp_data[6], icmp_data[7]]);
                if mtu_val > 0 && mtu_val <= 65535 {
                    Some(mtu_val as u16)
                } else {
                    None
                }
            } else {
                None
            };
            parse_icmp_error_payload_v6_with_mtu(
                icmp_data,
                responder,
                our_identifier,
                IcmpResponseType::PacketTooBig,
                mtu,
            )
        }
        ICMPV6_TIME_EXCEEDED => parse_icmp_error_payload_v6_with_mtu(
            icmp_data,
            responder,
            our_identifier,
            IcmpResponseType::TimeExceeded(icmp_code),
            None,
        ),
        ICMPV6_DEST_UNREACHABLE => parse_icmp_error_payload_v6_with_mtu(
            icmp_data,
            responder,
            our_identifier,
            IcmpResponseType::DestUnreachable(icmp_code),
            None,
        ),
        _ => None,
    }
}

/// Parse the payload of an IPv4 ICMP error message (Time Exceeded or Dest Unreachable)
fn parse_icmp_error_payload_v4_with_mtu(
    icmp_data: &[u8],
    responder: IpAddr,
    our_identifier: u16,
    response_type: IcmpResponseType,
    mtu: Option<u16>,
) -> Option<ParsedResponse> {
    // ICMP error format (RFC 4884):
    // [0]    Type
    // [1]    Code
    // [2-3]  Checksum
    // [4]    Unused
    // [5]    Length (original datagram length in 32-bit words, 0 = legacy)
    // [6-7]  Unused
    // [8..]  Original IP header + first 8 bytes of original payload
    // [8 + length*4..] ICMP extensions (if length > 0)
    // [136..] ICMP extensions (if length == 0, legacy mode)

    if icmp_data.len() < 8 + 20 + 8 {
        // Need at least ICMP header + IP header + 8 bytes of original payload
        return None;
    }

    // Extract RFC 4884 length field (byte 5 of ICMP header)
    let icmp_length = icmp_data[5];

    let original_ip_data = &icmp_data[8..];
    let original_ip = Ipv4Packet::new(original_ip_data)?;
    let orig_ihl = (original_ip.get_header_length() as usize) * 4;
    let orig_protocol = original_ip.get_next_level_protocol().0;
    // Extract quoted TTL for TTL manipulation detection
    let quoted_ttl = original_ip.get_ttl();
    // Extract original destination for multi-target disambiguation
    let original_dest = Some(IpAddr::V4(original_ip.get_destination()));

    if original_ip_data.len() < orig_ihl + 8 {
        return None;
    }

    let original_payload = &original_ip_data[orig_ihl..];

    // Try to parse ICMP extensions using RFC 4884 length field
    let mpls_labels = parse_icmp_extensions_with_length(&icmp_data[8..], icmp_length);

    // Handle based on original protocol
    match orig_protocol {
        IPPROTO_ICMP => {
            // Original packet was ICMP Echo Request
            // [0]    Type (should be 8 for Echo Request)
            // [1]    Code (should be 0)
            // [2-3]  Checksum
            // [4-5]  Identifier
            // [6-7]  Sequence

            if original_payload[0] != 8 {
                // Not an Echo Request
                return None;
            }

            let identifier = u16::from_be_bytes([original_payload[4], original_payload[5]]);
            let sequence = u16::from_be_bytes([original_payload[6], original_payload[7]]);

            if identifier == our_identifier {
                return Some(ParsedResponse {
                    responder,
                    probe_id: ProbeId::from_sequence(sequence),
                    response_type,
                    mpls_labels,
                    src_port: None,
                    mtu,
                    quoted_ttl: Some(quoted_ttl),
                    original_dest,
                });
            }

            // Payload fallback: macOS DGRAM send may modify identifier
            // Original ICMP: [0-7] header, [8..] payload
            //
            // NOTE: RFC 792 allows routers to quote only 8 bytes of original payload.
            // If a router quotes the minimum AND macOS rewrites the ICMP identifier,
            // this hop will be unmatchable (shows as timeout). This is rare in practice
            // as most modern routers quote more data per RFC 4884.
            if original_payload.len() >= 12
                && let Some((_, payload_seq)) =
                    extract_id_from_payload(&original_payload[8..], our_identifier)
            {
                return Some(ParsedResponse {
                    responder,
                    probe_id: ProbeId::from_sequence(payload_seq),
                    response_type,
                    mpls_labels,
                    src_port: None,
                    mtu,
                    quoted_ttl: Some(quoted_ttl),
                    original_dest,
                });
            }
            None
        }
        IPPROTO_TCP => {
            // Original packet was TCP SYN probe
            // TCP header: [0-1] src port, [2-3] dst port, [4-7] seq number, ...
            // Probe ID is encoded in seq number (high 16 bits)

            if original_payload.len() < 8 {
                // Need at least 8 bytes for seq number extraction
                return None;
            }

            // Extract source port for flow identification (Paris/Dublin traceroute)
            let src_port = u16::from_be_bytes([original_payload[0], original_payload[1]]);
            let probe_id = extract_probe_id_from_tcp(original_payload)?;

            Some(ParsedResponse {
                responder,
                probe_id,
                response_type,
                mpls_labels,
                src_port: Some(src_port),
                mtu,
                quoted_ttl: Some(quoted_ttl),
                original_dest,
            })
        }
        IPPROTO_UDP => {
            // Original packet was UDP probe
            // UDP header: [0-1] src port, [2-3] dst port, [4-5] length, [6-7] checksum
            // Our payload starts at offset 8

            if original_payload.len() < 8 + 6 {
                // Need UDP header + at least 6 bytes of payload
                return None;
            }

            // Extract source port for flow identification (Paris/Dublin traceroute)
            let src_port = u16::from_be_bytes([original_payload[0], original_payload[1]]);
            let udp_payload = &original_payload[8..];
            let probe_id = extract_probe_id_from_udp_payload(udp_payload)?;

            Some(ParsedResponse {
                responder,
                probe_id,
                response_type,
                mpls_labels,
                src_port: Some(src_port),
                mtu,
                quoted_ttl: Some(quoted_ttl),
                original_dest,
            })
        }
        _ => None,
    }
}

/// Parse the payload of an IPv6 ICMPv6 error message (Time Exceeded, Dest Unreachable, or Packet Too Big)
///
/// Note: Assumes the embedded original IPv6 packet has no extension headers.
/// This is valid for our use case since we send ICMPv6 Echo Requests and UDP directly
/// (Next Header = 58 or 17) without any extension headers.
///
/// Currently unused because Linux strips IPv6 headers from raw ICMPv6 sockets.
/// The DGRAM error parser is used instead. Kept for potential future use.
#[allow(dead_code)]
fn parse_icmp_error_payload_v6_with_mtu(
    icmp_data: &[u8],
    responder: IpAddr,
    our_identifier: u16,
    response_type: IcmpResponseType,
    mtu: Option<u16>,
) -> Option<ParsedResponse> {
    // ICMPv6 error format (RFC 4884):
    // [0]    Type
    // [1]    Code
    // [2-3]  Checksum
    // [4-7]  Type-specific (MTU for Packet Too Big, unused for others)
    // [8..]  Original IPv6 header (40 bytes) + first 8 bytes of original payload
    // [8 + length*4..] ICMP extensions (if length > 0)
    // [136..] ICMP extensions (if length == 0, legacy mode)

    const IPV6_HEADER_LEN: usize = 40;

    // Require: 8 (ICMPv6 header) + 40 (IPv6 header) + 8 (original ICMP/UDP header) = 56 bytes
    // Some routers send shorter payloads; log when this happens for debugging
    if icmp_data.len() < 8 + IPV6_HEADER_LEN + 8 {
        #[cfg(debug_assertions)]
        eprintln!(
            "ICMPv6 error dropped: payload too short ({} bytes, need 56) from {:?}",
            icmp_data.len(),
            responder
        );
        return None;
    }

    // Extract RFC 4884 length field (byte 5 of ICMPv6 header)
    let icmp_length = icmp_data[5];

    let original_ipv6_data = &icmp_data[8..];
    // Next header field is at byte 6 of IPv6 header
    let next_header = original_ipv6_data[6];
    // Hop limit (IPv6 equivalent of TTL) is at byte 7
    let quoted_ttl = original_ipv6_data[7];
    // Extract original destination for multi-target disambiguation (bytes 24-39)
    let original_dest = Some(IpAddr::V6(std::net::Ipv6Addr::new(
        u16::from_be_bytes([original_ipv6_data[24], original_ipv6_data[25]]),
        u16::from_be_bytes([original_ipv6_data[26], original_ipv6_data[27]]),
        u16::from_be_bytes([original_ipv6_data[28], original_ipv6_data[29]]),
        u16::from_be_bytes([original_ipv6_data[30], original_ipv6_data[31]]),
        u16::from_be_bytes([original_ipv6_data[32], original_ipv6_data[33]]),
        u16::from_be_bytes([original_ipv6_data[34], original_ipv6_data[35]]),
        u16::from_be_bytes([original_ipv6_data[36], original_ipv6_data[37]]),
        u16::from_be_bytes([original_ipv6_data[38], original_ipv6_data[39]]),
    )));
    let original_payload = &original_ipv6_data[IPV6_HEADER_LEN..];

    // Try to parse ICMP extensions using RFC 4884 length field
    let mpls_labels = parse_icmp_extensions_with_length(&icmp_data[8..], icmp_length);

    // Handle based on original protocol
    match next_header {
        IPPROTO_ICMPV6 => {
            // Original packet was ICMPv6 Echo Request
            // [0]    Type (should be 128 for Echo Request)
            // [1]    Code (should be 0)
            // [2-3]  Checksum
            // [4-5]  Identifier
            // [6-7]  Sequence

            if original_payload[0] != ICMPV6_ECHO_REQUEST {
                // Not our Echo Request
                return None;
            }

            let identifier = u16::from_be_bytes([original_payload[4], original_payload[5]]);
            let sequence = u16::from_be_bytes([original_payload[6], original_payload[7]]);

            if identifier == our_identifier {
                return Some(ParsedResponse {
                    responder,
                    probe_id: ProbeId::from_sequence(sequence),
                    response_type,
                    mpls_labels,
                    src_port: None,
                    mtu,
                    quoted_ttl: Some(quoted_ttl),
                    original_dest,
                });
            }

            // Payload fallback: macOS DGRAM send may modify identifier
            // Original ICMPv6: [0-7] header, [8..] payload
            //
            // NOTE: RFC 4443 allows routers to quote minimum data. If a router quotes
            // only the minimum AND macOS rewrites the ICMPv6 identifier, this hop will
            // be unmatchable (shows as timeout). Rare in practice.
            if original_payload.len() >= 12
                && let Some((_, payload_seq)) =
                    extract_id_from_payload(&original_payload[8..], our_identifier)
            {
                return Some(ParsedResponse {
                    responder,
                    probe_id: ProbeId::from_sequence(payload_seq),
                    response_type,
                    mpls_labels,
                    src_port: None,
                    mtu,
                    quoted_ttl: Some(quoted_ttl),
                    original_dest,
                });
            }
            None
        }
        IPPROTO_TCP => {
            // Original packet was TCP SYN probe
            // TCP header: [0-1] src port, [2-3] dst port, [4-7] seq number, ...
            // Probe ID is encoded in seq number (high 16 bits)

            if original_payload.len() < 8 {
                // Need at least 8 bytes for seq number extraction
                return None;
            }

            // Extract source port for flow identification (Paris/Dublin traceroute)
            let src_port = u16::from_be_bytes([original_payload[0], original_payload[1]]);
            let probe_id = extract_probe_id_from_tcp(original_payload)?;

            Some(ParsedResponse {
                responder,
                probe_id,
                response_type,
                mpls_labels,
                src_port: Some(src_port),
                mtu,
                quoted_ttl: Some(quoted_ttl),
                original_dest,
            })
        }
        IPPROTO_UDP => {
            // Original packet was UDP probe
            // UDP header: [0-1] src port, [2-3] dst port, [4-5] length, [6-7] checksum
            // Our payload starts at offset 8

            if original_payload.len() < 8 + 6 {
                // Need UDP header + at least 6 bytes of payload
                return None;
            }

            // Extract source port for flow identification (Paris/Dublin traceroute)
            let src_port = u16::from_be_bytes([original_payload[0], original_payload[1]]);
            let udp_payload = &original_payload[8..];
            let probe_id = extract_probe_id_from_udp_payload(udp_payload)?;

            Some(ParsedResponse {
                responder,
                probe_id,
                response_type,
                mpls_labels,
                src_port: Some(src_port),
                mtu,
                quoted_ttl: Some(quoted_ttl),
                original_dest,
            })
        }
        _ => None,
    }
}

// ============================================================================
// DGRAM socket parsing (no IP header - used on macOS)
// ============================================================================

/// Helper to extract identifier from payload (fallback for macOS DGRAM id override)
/// Payload layout: [0-1] identifier, [2-3] sequence, [4-7] timestamp
fn extract_id_from_payload(payload: &[u8], our_identifier: u16) -> Option<(u16, u16)> {
    if payload.len() < 4 {
        return None;
    }
    let payload_id = u16::from_be_bytes([payload[0], payload[1]]);
    let payload_seq = u16::from_be_bytes([payload[2], payload[3]]);
    if payload_id == our_identifier {
        Some((payload_id, payload_seq))
    } else {
        None
    }
}

/// Parse IPv4 ICMP from DGRAM socket (no IP header)
fn parse_icmp_response_v4_dgram(
    icmp_data: &[u8],
    responder: IpAddr,
    our_identifier: u16,
) -> Option<ParsedResponse> {
    if icmp_data.len() < 8 {
        return None;
    }

    let icmp_type = icmp_data[0];
    let icmp_code = icmp_data[1];

    match icmp_type {
        0 => {
            // Echo Reply
            // Validate checksum
            if !validate_icmp_checksum(icmp_data) {
                return None;
            }

            // Try header identifier first
            let identifier = u16::from_be_bytes([icmp_data[4], icmp_data[5]]);
            let sequence = u16::from_be_bytes([icmp_data[6], icmp_data[7]]);

            if identifier == our_identifier {
                return Some(ParsedResponse {
                    responder,
                    probe_id: ProbeId::from_sequence(sequence),
                    response_type: IcmpResponseType::EchoReply,
                    mpls_labels: None,
                    src_port: None,
                    mtu: None,
                    quoted_ttl: None,
                    // For Echo Reply, responder IS the target
                    original_dest: Some(responder),
                });
            }

            // Fallback: check payload bytes 0-3 (macOS may override identifier)
            // ICMP header is 8 bytes, payload starts at icmp_data[8]
            if icmp_data.len() >= 12
                && let Some((_, payload_seq)) =
                    extract_id_from_payload(&icmp_data[8..], our_identifier)
            {
                return Some(ParsedResponse {
                    responder,
                    probe_id: ProbeId::from_sequence(payload_seq),
                    response_type: IcmpResponseType::EchoReply,
                    mpls_labels: None,
                    src_port: None,
                    mtu: None,
                    quoted_ttl: None,
                    // For Echo Reply, responder IS the target
                    original_dest: Some(responder),
                });
            }
            None
        }
        11 => {
            // Time Exceeded
            parse_icmp_error_payload_v4_dgram(
                icmp_data,
                responder,
                our_identifier,
                IcmpResponseType::TimeExceeded(icmp_code),
                None,
            )
        }
        3 => {
            // Destination Unreachable
            let mtu = if icmp_code == 4 && icmp_data.len() >= 8 {
                let mtu_val = u16::from_be_bytes([icmp_data[6], icmp_data[7]]);
                if mtu_val > 0 { Some(mtu_val) } else { None }
            } else {
                None
            };
            parse_icmp_error_payload_v4_dgram(
                icmp_data,
                responder,
                our_identifier,
                IcmpResponseType::DestUnreachable(icmp_code),
                mtu,
            )
        }
        _ => None,
    }
}

/// Parse ICMP error (Time Exceeded, Dest Unreachable) from DGRAM socket
fn parse_icmp_error_payload_v4_dgram(
    icmp_data: &[u8],
    responder: IpAddr,
    our_identifier: u16,
    response_type: IcmpResponseType,
    mtu: Option<u16>,
) -> Option<ParsedResponse> {
    // ICMP error: [0-7] ICMP header, [8..] original IP packet
    if icmp_data.len() < 8 + 20 + 8 {
        return None;
    }

    let icmp_length = icmp_data[5];
    let original_ip_data = &icmp_data[8..];
    let original_ip = Ipv4Packet::new(original_ip_data)?;
    let orig_ihl = (original_ip.get_header_length() as usize) * 4;
    let orig_protocol = original_ip.get_next_level_protocol().0;
    let quoted_ttl = original_ip.get_ttl();
    let original_dest = Some(IpAddr::V4(original_ip.get_destination()));

    if original_ip_data.len() < orig_ihl + 8 {
        return None;
    }

    let original_payload = &original_ip_data[orig_ihl..];
    let mpls_labels = parse_icmp_extensions_with_length(&icmp_data[8..], icmp_length);

    match orig_protocol {
        IPPROTO_ICMP => {
            if original_payload[0] != 8 {
                return None;
            }

            // Try header identifier first
            // Note: macOS DGRAM sockets may override the ICMP identifier. If the identifier
            // is overwritten AND the router quotes only 8 bytes of the original ICMP (just
            // the header per RFC 792 minimum), the payload fallback below won't work.
            // In practice, most modern routers quote more data, and macOS may preserve
            // the identifier for outgoing packets even in DGRAM mode.
            let identifier = u16::from_be_bytes([original_payload[4], original_payload[5]]);
            let sequence = u16::from_be_bytes([original_payload[6], original_payload[7]]);

            if identifier == our_identifier {
                return Some(ParsedResponse {
                    responder,
                    probe_id: ProbeId::from_sequence(sequence),
                    response_type,
                    mpls_labels,
                    src_port: None,
                    mtu,
                    quoted_ttl: Some(quoted_ttl),
                    original_dest,
                });
            }

            // Fallback: check quoted ICMP payload bytes 0-3 for embedded ProbeId
            // Only works if router quotes at least 12 bytes (ICMP header + 4 payload)
            // Original ICMP: [0-7] header, [8..] payload
            if original_payload.len() >= 12
                && let Some((_, payload_seq)) =
                    extract_id_from_payload(&original_payload[8..], our_identifier)
            {
                return Some(ParsedResponse {
                    responder,
                    probe_id: ProbeId::from_sequence(payload_seq),
                    response_type,
                    mpls_labels,
                    src_port: None,
                    mtu,
                    quoted_ttl: Some(quoted_ttl),
                    original_dest,
                });
            }
            None
        }
        IPPROTO_TCP => {
            if original_payload.len() < 8 {
                return None;
            }
            let src_port = u16::from_be_bytes([original_payload[0], original_payload[1]]);
            let probe_id = extract_probe_id_from_tcp(original_payload)?;

            Some(ParsedResponse {
                responder,
                probe_id,
                response_type,
                mpls_labels,
                src_port: Some(src_port),
                mtu,
                quoted_ttl: Some(quoted_ttl),
                original_dest,
            })
        }
        IPPROTO_UDP => {
            if original_payload.len() < 8 + 6 {
                return None;
            }
            let src_port = u16::from_be_bytes([original_payload[0], original_payload[1]]);
            let udp_payload = &original_payload[8..];
            let probe_id = extract_probe_id_from_udp_payload(udp_payload)?;

            Some(ParsedResponse {
                responder,
                probe_id,
                response_type,
                mpls_labels,
                src_port: Some(src_port),
                mtu,
                quoted_ttl: Some(quoted_ttl),
                original_dest,
            })
        }
        _ => None,
    }
}

/// Parse IPv6 ICMPv6 from DGRAM socket (no IP header)
fn parse_icmp_response_v6_dgram(
    icmp_data: &[u8],
    responder: IpAddr,
    our_identifier: u16,
) -> Option<ParsedResponse> {
    if icmp_data.len() < 8 {
        return None;
    }

    let icmp_type = icmp_data[0];
    let icmp_code = icmp_data[1];

    match icmp_type {
        ICMPV6_ECHO_REPLY => {
            let identifier = u16::from_be_bytes([icmp_data[4], icmp_data[5]]);
            let sequence = u16::from_be_bytes([icmp_data[6], icmp_data[7]]);

            if identifier == our_identifier {
                return Some(ParsedResponse {
                    responder,
                    probe_id: ProbeId::from_sequence(sequence),
                    response_type: IcmpResponseType::EchoReply,
                    mpls_labels: None,
                    src_port: None,
                    mtu: None,
                    quoted_ttl: None,
                    // For Echo Reply, responder IS the target
                    original_dest: Some(responder),
                });
            }

            // Fallback: check payload
            if icmp_data.len() >= 12
                && let Some((_, payload_seq)) =
                    extract_id_from_payload(&icmp_data[8..], our_identifier)
            {
                return Some(ParsedResponse {
                    responder,
                    probe_id: ProbeId::from_sequence(payload_seq),
                    response_type: IcmpResponseType::EchoReply,
                    mpls_labels: None,
                    src_port: None,
                    mtu: None,
                    quoted_ttl: None,
                    // For Echo Reply, responder IS the target
                    original_dest: Some(responder),
                });
            }
            None
        }
        ICMPV6_PACKET_TOO_BIG => {
            let mtu = if icmp_data.len() >= 8 {
                let mtu_val =
                    u32::from_be_bytes([icmp_data[4], icmp_data[5], icmp_data[6], icmp_data[7]]);
                if mtu_val > 0 && mtu_val <= 65535 {
                    Some(mtu_val as u16)
                } else {
                    None
                }
            } else {
                None
            };
            parse_icmp_error_payload_v6_dgram(
                icmp_data,
                responder,
                our_identifier,
                IcmpResponseType::PacketTooBig,
                mtu,
            )
        }
        ICMPV6_TIME_EXCEEDED => parse_icmp_error_payload_v6_dgram(
            icmp_data,
            responder,
            our_identifier,
            IcmpResponseType::TimeExceeded(icmp_code),
            None,
        ),
        ICMPV6_DEST_UNREACHABLE => parse_icmp_error_payload_v6_dgram(
            icmp_data,
            responder,
            our_identifier,
            IcmpResponseType::DestUnreachable(icmp_code),
            None,
        ),
        _ => None,
    }
}

/// Parse ICMPv6 error payload from DGRAM socket
fn parse_icmp_error_payload_v6_dgram(
    icmp_data: &[u8],
    responder: IpAddr,
    our_identifier: u16,
    response_type: IcmpResponseType,
    mtu: Option<u16>,
) -> Option<ParsedResponse> {
    const IPV6_HEADER_LEN: usize = 40;

    // Require: 8 (ICMPv6 header) + 40 (IPv6 header) + 8 (original ICMP/UDP header) = 56 bytes
    // Some routers send shorter payloads; log when this happens for debugging
    if icmp_data.len() < 8 + IPV6_HEADER_LEN + 8 {
        #[cfg(debug_assertions)]
        eprintln!(
            "ICMPv6 error dropped (dgram): payload too short ({} bytes, need 56) from {:?}",
            icmp_data.len(),
            responder
        );
        return None;
    }

    let icmp_length = icmp_data[5];
    let original_ipv6_data = &icmp_data[8..];
    let next_header = original_ipv6_data[6];
    let quoted_ttl = original_ipv6_data[7]; // Hop limit
    // Extract original destination for multi-target disambiguation (bytes 24-39)
    let original_dest = Some(IpAddr::V6(std::net::Ipv6Addr::new(
        u16::from_be_bytes([original_ipv6_data[24], original_ipv6_data[25]]),
        u16::from_be_bytes([original_ipv6_data[26], original_ipv6_data[27]]),
        u16::from_be_bytes([original_ipv6_data[28], original_ipv6_data[29]]),
        u16::from_be_bytes([original_ipv6_data[30], original_ipv6_data[31]]),
        u16::from_be_bytes([original_ipv6_data[32], original_ipv6_data[33]]),
        u16::from_be_bytes([original_ipv6_data[34], original_ipv6_data[35]]),
        u16::from_be_bytes([original_ipv6_data[36], original_ipv6_data[37]]),
        u16::from_be_bytes([original_ipv6_data[38], original_ipv6_data[39]]),
    )));
    let original_payload = &original_ipv6_data[IPV6_HEADER_LEN..];

    let mpls_labels = parse_icmp_extensions_with_length(&icmp_data[8..], icmp_length);

    match next_header {
        IPPROTO_ICMPV6 => {
            if original_payload[0] != ICMPV6_ECHO_REQUEST {
                return None;
            }

            let identifier = u16::from_be_bytes([original_payload[4], original_payload[5]]);
            let sequence = u16::from_be_bytes([original_payload[6], original_payload[7]]);

            if identifier == our_identifier {
                return Some(ParsedResponse {
                    responder,
                    probe_id: ProbeId::from_sequence(sequence),
                    response_type,
                    mpls_labels,
                    src_port: None,
                    mtu,
                    quoted_ttl: Some(quoted_ttl),
                    original_dest,
                });
            }

            // Fallback: check quoted ICMPv6 payload
            if original_payload.len() >= 12
                && let Some((_, payload_seq)) =
                    extract_id_from_payload(&original_payload[8..], our_identifier)
            {
                return Some(ParsedResponse {
                    responder,
                    probe_id: ProbeId::from_sequence(payload_seq),
                    response_type,
                    mpls_labels,
                    src_port: None,
                    mtu,
                    quoted_ttl: Some(quoted_ttl),
                    original_dest,
                });
            }
            None
        }
        IPPROTO_TCP => {
            if original_payload.len() < 8 {
                return None;
            }
            let src_port = u16::from_be_bytes([original_payload[0], original_payload[1]]);
            let probe_id = extract_probe_id_from_tcp(original_payload)?;

            Some(ParsedResponse {
                responder,
                probe_id,
                response_type,
                mpls_labels,
                src_port: Some(src_port),
                mtu,
                quoted_ttl: Some(quoted_ttl),
                original_dest,
            })
        }
        IPPROTO_UDP => {
            if original_payload.len() < 8 + 6 {
                return None;
            }
            let src_port = u16::from_be_bytes([original_payload[0], original_payload[1]]);
            let udp_payload = &original_payload[8..];
            let probe_id = extract_probe_id_from_udp_payload(udp_payload)?;

            Some(ParsedResponse {
                responder,
                probe_id,
                response_type,
                mpls_labels,
                src_port: Some(src_port),
                mtu,
                quoted_ttl: Some(quoted_ttl),
                original_dest,
            })
        }
        _ => None,
    }
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
        assert!(parse_icmp_response(&[], responder, 0x1234, false).is_none());
    }

    #[test]
    fn test_truncated_packet_returns_none() {
        let responder = IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1));
        // Just an IP version nibble, nothing else
        let truncated = [0x45]; // IPv4, IHL=5
        assert!(parse_icmp_response(&truncated, responder, 0x1234, false).is_none());
    }

    #[test]
    fn test_invalid_ip_version_returns_none() {
        let responder = IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1));
        // IP version 3 doesn't exist
        let invalid = [0x30, 0x00, 0x00, 0x00];
        assert!(parse_icmp_response(&invalid, responder, 0x1234, false).is_none());
    }

    #[test]
    fn test_identifier_mismatch_returns_none() {
        let responder = IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1));
        // Build a valid-looking Echo Reply packet with wrong identifier
        // IPv4 header (20 bytes minimum with IHL=5) + ICMP header (8 bytes)
        let mut packet = vec![0u8; 28];

        // IPv4 header
        packet[0] = 0x45; // Version 4, IHL 5
        packet[9] = 1; // Protocol: ICMP

        // ICMP Echo Reply
        packet[20] = 0; // Type: Echo Reply
        packet[21] = 0; // Code: 0
        // Identifier: 0x5678 (wrong - we're looking for 0x1234)
        packet[24] = 0x56;
        packet[25] = 0x78;
        // Sequence
        packet[26] = 0x00;
        packet[27] = 0x01;

        assert!(parse_icmp_response(&packet, responder, 0x1234, false).is_none());
    }

    #[test]
    fn test_parse_echo_reply_v4() {
        let responder = IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8));
        let our_id = 0x1234;

        // Build Echo Reply packet
        let mut packet = vec![0u8; 28];

        // IPv4 header
        packet[0] = 0x45; // Version 4, IHL 5 (20 bytes)
        packet[9] = 1; // Protocol: ICMP

        // ICMP Echo Reply
        packet[20] = 0; // Type: Echo Reply
        packet[21] = 0; // Code: 0
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

        let result = parse_icmp_response(&packet, responder, our_id, false);
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
        packet[20] = 11; // Type: Time Exceeded
        packet[21] = 0; // Code: TTL exceeded

        // Original IP header (inside ICMP payload at offset 28)
        packet[28] = 0x45; // Version 4, IHL 5
        packet[37] = 1; // Protocol: ICMP

        // Original ICMP Echo Request (at offset 48)
        packet[48] = 8; // Type: Echo Request
        packet[49] = 0; // Code: 0
        // Identifier
        packet[52] = 0xAB;
        packet[53] = 0xCD;
        // Sequence (TTL=5, seq=3)
        let probe_id = ProbeId::new(5, 3);
        let seq = probe_id.to_sequence();
        packet[54] = (seq >> 8) as u8;
        packet[55] = (seq & 0xFF) as u8;

        let result = parse_icmp_response(&packet, responder, our_id, false);
        assert!(result.is_some());

        let parsed = result.unwrap();
        assert_eq!(parsed.probe_id.ttl, 5);
        assert_eq!(parsed.probe_id.seq, 3);
        assert_eq!(parsed.response_type, IcmpResponseType::TimeExceeded(0));
    }

    #[test]
    fn test_variable_ihl_v4() {
        let responder = IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8));
        let our_id = 0x1234;

        // Build Echo Reply with IHL=6 (24 byte IP header with options)
        let mut packet = vec![0u8; 32]; // 24 IP + 8 ICMP

        // IPv4 header with IHL=6
        packet[0] = 0x46; // Version 4, IHL 6 (24 bytes)
        packet[9] = 1; // Protocol: ICMP

        // ICMP Echo Reply at offset 24
        packet[24] = 0; // Type: Echo Reply
        packet[25] = 0; // Code: 0
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

        let result = parse_icmp_response(&packet, responder, our_id, false);
        assert!(result.is_some());

        let parsed = result.unwrap();
        assert_eq!(parsed.probe_id.ttl, 7);
        assert_eq!(parsed.probe_id.seq, 2);
    }

    #[test]
    fn test_parse_echo_reply_v6() {
        let responder = IpAddr::V6(std::net::Ipv6Addr::new(
            0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888,
        ));
        let our_id = 0x1234;

        // Build ICMPv6 Echo Reply packet (no IPv6 header - kernel strips it on Linux)
        // ICMPv6 Echo Reply: 8 bytes header + payload
        let mut packet = vec![0u8; 12]; // 8 header + 4 payload for identifier backup

        // ICMPv6 Echo Reply
        packet[0] = 129; // Type: Echo Reply
        packet[1] = 0; // Code: 0
        // Checksum (bytes 2-3, kernel validates)
        // Identifier
        packet[4] = 0x12;
        packet[5] = 0x34;
        // Sequence (TTL=8, seq=4)
        let probe_id = ProbeId::new(8, 4);
        let seq = probe_id.to_sequence();
        packet[6] = (seq >> 8) as u8;
        packet[7] = (seq & 0xFF) as u8;

        let result = parse_icmp_response(&packet, responder, our_id, false);
        assert!(result.is_some());

        let parsed = result.unwrap();
        assert_eq!(parsed.responder, responder);
        assert_eq!(parsed.probe_id.ttl, 8);
        assert_eq!(parsed.probe_id.seq, 4);
        assert_eq!(parsed.response_type, IcmpResponseType::EchoReply);
    }

    #[test]
    fn test_parse_time_exceeded_v6() {
        let responder = IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let our_id = 0xABCD;

        // Build ICMPv6 Time Exceeded packet (no outer IPv6 header - kernel strips it)
        // ICMPv6 header (8) + Original IPv6 (40) + Original ICMPv6 (8) = 56 bytes
        let mut packet = vec![0u8; 56];

        // ICMPv6 Time Exceeded
        packet[0] = 3; // Type: Time Exceeded
        packet[1] = 0; // Code: Hop limit exceeded
        // Checksum (bytes 2-3)
        // Unused (bytes 4-7)

        // Original IPv6 header (inside ICMPv6 payload at offset 8)
        packet[8] = 0x60; // Version 6
        packet[14] = 58; // Next Header: ICMPv6

        // Original ICMPv6 Echo Request (at offset 48 = 8 + 40)
        packet[48] = 128; // Type: Echo Request
        packet[49] = 0; // Code: 0
        // Identifier
        packet[52] = 0xAB;
        packet[53] = 0xCD;
        // Sequence (TTL=6, seq=2)
        let probe_id = ProbeId::new(6, 2);
        let seq = probe_id.to_sequence();
        packet[54] = (seq >> 8) as u8;
        packet[55] = (seq & 0xFF) as u8;

        let result = parse_icmp_response(&packet, responder, our_id, false);
        assert!(result.is_some());

        let parsed = result.unwrap();
        assert_eq!(parsed.probe_id.ttl, 6);
        assert_eq!(parsed.probe_id.seq, 2);
        assert_eq!(parsed.response_type, IcmpResponseType::TimeExceeded(0));
    }

    // Note: IPv6 extension header tests removed.
    // Linux kernel strips outer IPv6 header before delivering to raw ICMPv6 sockets,
    // so we never see extension headers in the outer packet. Extension header parsing
    // code (parse_icmp_response_v6, skip_ipv6_extension_headers) is now unused.

    #[test]
    fn test_ipv6_fragment_header_rejected() {
        let responder = IpAddr::V6(std::net::Ipv6Addr::new(
            0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888,
        ));
        let our_id = 0x1234;

        // Build IPv6 with Fragment header - should be rejected
        let mut packet = vec![0u8; 56];

        // IPv6 header
        packet[0] = 0x60;
        packet[6] = 44; // Next Header: Fragment

        // Fragment header at offset 40
        packet[40] = 58; // Next Header: ICMPv6
        // Fragment header is 8 bytes

        // ICMPv6 at offset 48
        packet[48] = 129; // Echo Reply
        packet[52] = 0x12;
        packet[53] = 0x34;

        // Fragments are rejected (we don't handle reassembly)
        let result = parse_icmp_response(&packet, responder, our_id, false);
        assert!(result.is_none());
    }

    #[test]
    fn test_invalid_icmp_checksum_rejected() {
        let responder = IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8));
        let our_id = 0x1234;

        // Build Echo Reply with invalid checksum
        let mut packet = vec![0u8; 28];

        // IPv4 header
        packet[0] = 0x45;
        packet[9] = 1; // ICMP

        // ICMP Echo Reply with bad checksum
        packet[20] = 0; // Type: Echo Reply
        packet[21] = 0; // Code: 0
        packet[22] = 0xFF; // Invalid checksum
        packet[23] = 0xFF;
        packet[24] = 0x12;
        packet[25] = 0x34;
        let probe_id = ProbeId::new(1, 1);
        let seq = probe_id.to_sequence();
        packet[26] = (seq >> 8) as u8;
        packet[27] = (seq & 0xFF) as u8;

        // Should be rejected due to invalid checksum
        let result = parse_icmp_response(&packet, responder, our_id, false);
        assert!(result.is_none());
    }

    #[test]
    fn test_dest_unreachable_v4() {
        let responder = IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1));
        let our_id = 0xDEAD;

        // Build Destination Unreachable packet (similar structure to Time Exceeded)
        let mut packet = vec![0u8; 56];

        // Outer IPv4 header
        packet[0] = 0x45;
        packet[9] = 1;

        // ICMP Destination Unreachable
        packet[20] = 3; // Type: Destination Unreachable
        packet[21] = 1; // Code: Host Unreachable

        // Original IP header at offset 28
        packet[28] = 0x45;
        packet[37] = 1;

        // Original ICMP at offset 48
        packet[48] = 8; // Echo Request
        packet[52] = 0xDE;
        packet[53] = 0xAD;
        let probe_id = ProbeId::new(12, 3);
        let seq = probe_id.to_sequence();
        packet[54] = (seq >> 8) as u8;
        packet[55] = (seq & 0xFF) as u8;

        let result = parse_icmp_response(&packet, responder, our_id, false);
        assert!(result.is_some());

        let parsed = result.unwrap();
        assert_eq!(parsed.probe_id.ttl, 12);
        assert_eq!(parsed.probe_id.seq, 3);
        assert!(matches!(
            parsed.response_type,
            IcmpResponseType::DestUnreachable(1)
        ));
    }

    #[test]
    fn test_mpls_label_parsing() {
        // Test MplsLabel::from_bytes parsing
        // Label = 24000 (0x5DC0), Exp = 3, Bottom = true, TTL = 62
        // Binary: 0000 0101 1101 1100 0000 0111 0011 1110
        //         |------- label (20) ------||exp||S|TTL|
        let bytes: [u8; 4] = [0x05, 0xDC, 0x07, 0x3E];
        let label = MplsLabel::from_bytes(&bytes);
        assert_eq!(label.label, 24000);
        assert_eq!(label.exp, 3);
        assert!(label.bottom);
        assert_eq!(label.ttl, 62);
    }

    #[test]
    fn test_mpls_label_stack_parsing() {
        // Test parsing MPLS label stack from ICMP extension
        // Label 1: 16000, Exp=0, S=0, TTL=64
        // Label 2: 24000, Exp=3, S=1, TTL=62
        let label1 = MplsLabel {
            label: 16000,
            exp: 0,
            bottom: false,
            ttl: 64,
        };
        let label2 = MplsLabel {
            label: 24000,
            exp: 3,
            bottom: true,
            ttl: 62,
        };

        // Encode labels
        fn encode_label(l: &MplsLabel) -> [u8; 4] {
            let word = (l.label << 12)
                | ((l.exp as u32) << 9)
                | (if l.bottom { 1 << 8 } else { 0 })
                | (l.ttl as u32);
            word.to_be_bytes()
        }

        let l1_bytes = encode_label(&label1);
        let l2_bytes = encode_label(&label2);

        // Verify parsing roundtrip
        let parsed1 = MplsLabel::from_bytes(&l1_bytes);
        assert_eq!(parsed1.label, 16000);
        assert_eq!(parsed1.exp, 0);
        assert!(!parsed1.bottom);
        assert_eq!(parsed1.ttl, 64);

        let parsed2 = MplsLabel::from_bytes(&l2_bytes);
        assert_eq!(parsed2.label, 24000);
        assert_eq!(parsed2.exp, 3);
        assert!(parsed2.bottom);
        assert_eq!(parsed2.ttl, 62);
    }

    #[test]
    fn test_time_exceeded_with_mpls_extension() {
        let responder = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1));
        let our_id = 0x1234;

        // Build Time Exceeded with MPLS extension
        // Layout:
        // [0-19]   Outer IPv4 header (20 bytes)
        // [20-27]  ICMP header (8 bytes: type, code, checksum, unused)
        // [28-155] Original datagram (padded to 128 bytes for extensions)
        // [156-159] Extension header (4 bytes: version, reserved, checksum)
        // [160-163] MPLS object header (4 bytes: length, class, type)
        // [164-167] MPLS label entry (4 bytes)

        let mut packet = vec![0u8; 168];

        // Outer IPv4 header
        packet[0] = 0x45;
        packet[9] = 1; // ICMP

        // ICMP Time Exceeded
        packet[20] = 11; // Type: Time Exceeded
        packet[21] = 0; // Code: TTL exceeded

        // Original IP header (at offset 28)
        packet[28] = 0x45;
        packet[37] = 1; // Protocol: ICMP

        // Original ICMP Echo Request (at offset 48)
        packet[48] = 8; // Type: Echo Request
        packet[49] = 0; // Code: 0
        packet[52] = 0x12; // Identifier
        packet[53] = 0x34;
        let probe_id = ProbeId::new(5, 1);
        let seq = probe_id.to_sequence();
        packet[54] = (seq >> 8) as u8;
        packet[55] = (seq & 0xFF) as u8;

        // ICMP Extension header (at offset 156 = 28 + 128)
        // Version 2, reserved, checksum (we skip checksum validation)
        packet[156] = 0x20; // Version 2 in high nibble
        packet[157] = 0x00;
        packet[158] = 0x00; // Checksum (not validated)
        packet[159] = 0x00;

        // MPLS extension object header (at offset 160)
        packet[160] = 0x00; // Length high byte
        packet[161] = 0x08; // Length = 8 (header + 1 label)
        packet[162] = 0x01; // Class = 1 (MPLS)
        packet[163] = 0x01; // Type = 1 (Label Stack)

        // MPLS label: label=24000, exp=3, S=1, TTL=62
        // word = (24000 << 12) | (3 << 9) | (1 << 8) | 62
        let label_word: u32 = (24000 << 12) | (3 << 9) | (1 << 8) | 62;
        let label_bytes = label_word.to_be_bytes();
        packet[164..168].copy_from_slice(&label_bytes);

        let result = parse_icmp_response(&packet, responder, our_id, false);
        assert!(result.is_some());

        let parsed = result.unwrap();
        assert_eq!(parsed.probe_id.ttl, 5);
        assert_eq!(parsed.probe_id.seq, 1);
        assert_eq!(parsed.response_type, IcmpResponseType::TimeExceeded(0));

        // Verify MPLS labels were parsed
        assert!(parsed.mpls_labels.is_some());
        let labels = parsed.mpls_labels.unwrap();
        assert_eq!(labels.len(), 1);
        assert_eq!(labels[0].label, 24000);
        assert_eq!(labels[0].exp, 3);
        assert!(labels[0].bottom);
        assert_eq!(labels[0].ttl, 62);
    }

    #[test]
    fn test_time_exceeded_with_mpls_rfc4884_length() {
        // Test RFC 4884 compliant packet with non-zero length field
        let responder = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1));
        let our_id = 0x1234;

        // Layout with RFC 4884 length field:
        // Original datagram = 48 bytes (12 * 4), so length field = 12
        // Extensions start at offset 28 + 48 = 76
        let mut packet = vec![0u8; 100];

        // Outer IPv4 header
        packet[0] = 0x45;
        packet[9] = 1; // ICMP

        // ICMP Time Exceeded with RFC 4884 length field
        packet[20] = 11; // Type: Time Exceeded
        packet[21] = 0; // Code: TTL exceeded
        packet[25] = 12; // Length = 12 (48 bytes of original datagram)

        // Original IP header (at offset 28)
        packet[28] = 0x45;
        packet[37] = 1; // Protocol: ICMP

        // Original ICMP Echo Request (at offset 48)
        packet[48] = 8; // Type: Echo Request
        packet[52] = 0x12; // Identifier
        packet[53] = 0x34;
        let probe_id = ProbeId::new(3, 2);
        let seq = probe_id.to_sequence();
        packet[54] = (seq >> 8) as u8;
        packet[55] = (seq & 0xFF) as u8;

        // Extension header at offset 76 (28 + 48)
        packet[76] = 0x20; // Version 2
        packet[77] = 0x00;
        packet[78] = 0x00; // Checksum
        packet[79] = 0x00;

        // MPLS object header at offset 80
        packet[80] = 0x00;
        packet[81] = 0x08; // Length = 8
        packet[82] = 0x01; // Class = 1 (MPLS)
        packet[83] = 0x01; // Type = 1

        // MPLS label: label=16000, exp=0, S=1, TTL=64
        let label_word: u32 = (16000 << 12) | (1 << 8) | 64;
        let label_bytes = label_word.to_be_bytes();
        packet[84..88].copy_from_slice(&label_bytes);

        let result = parse_icmp_response(&packet, responder, our_id, false);
        assert!(result.is_some());

        let parsed = result.unwrap();
        assert_eq!(parsed.probe_id.ttl, 3);
        assert_eq!(parsed.probe_id.seq, 2);

        // Verify MPLS labels were parsed using RFC 4884 length field
        assert!(parsed.mpls_labels.is_some());
        let labels = parsed.mpls_labels.unwrap();
        assert_eq!(labels.len(), 1);
        assert_eq!(labels[0].label, 16000);
        assert_eq!(labels[0].ttl, 64);
    }

    #[test]
    fn test_time_exceeded_without_extension() {
        // Same test as test_parse_time_exceeded_v4 but verify no MPLS labels
        let responder = IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1));
        let our_id = 0xABCD;

        // Packet without extensions (too short for extensions)
        let mut packet = vec![0u8; 56];

        packet[0] = 0x45;
        packet[9] = 1;
        packet[20] = 11;
        packet[21] = 0;
        packet[28] = 0x45;
        packet[37] = 1;
        packet[48] = 8;
        packet[52] = 0xAB;
        packet[53] = 0xCD;
        let probe_id = ProbeId::new(5, 3);
        let seq = probe_id.to_sequence();
        packet[54] = (seq >> 8) as u8;
        packet[55] = (seq & 0xFF) as u8;

        let result = parse_icmp_response(&packet, responder, our_id, false);
        assert!(result.is_some());

        let parsed = result.unwrap();
        // Should have no MPLS labels (packet too short)
        assert!(parsed.mpls_labels.is_none());
    }

    // ========================================================================
    // DGRAM socket tests (macOS - no IP header in packets)
    // ========================================================================

    #[test]
    fn test_parse_echo_reply_dgram() {
        // DGRAM sockets don't include IP header - packet starts at ICMP
        let responder = IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8));
        let our_id = 0x1234;

        // ICMP Echo Reply (no IP header): 8 bytes header + 8 bytes payload
        let mut packet = vec![0u8; 16];

        // ICMP header
        packet[0] = 0; // Type: Echo Reply
        packet[1] = 0; // Code: 0
        // Checksum will be set below
        packet[4] = 0x12; // Identifier high byte
        packet[5] = 0x34; // Identifier low byte

        // Sequence (TTL=10, seq=5)
        let probe_id = ProbeId::new(10, 5);
        let seq = probe_id.to_sequence();
        packet[6] = (seq >> 8) as u8;
        packet[7] = (seq & 0xFF) as u8;

        // Payload: embedded ProbeId at bytes 0-3 (for macOS DGRAM fallback)
        packet[8] = 0x12; // Identifier high byte
        packet[9] = 0x34; // Identifier low byte
        packet[10] = (seq >> 8) as u8; // Sequence high byte
        packet[11] = (seq & 0xFF) as u8; // Sequence low byte

        // Set valid ICMP checksum
        set_icmp_checksum(&mut packet);

        let result = parse_icmp_response(&packet, responder, our_id, true); // is_dgram=true
        assert!(result.is_some());

        let parsed = result.unwrap();
        assert_eq!(parsed.responder, responder);
        assert_eq!(parsed.probe_id.ttl, 10);
        assert_eq!(parsed.probe_id.seq, 5);
        assert_eq!(parsed.response_type, IcmpResponseType::EchoReply);
    }

    #[test]
    fn test_parse_time_exceeded_dgram() {
        // DGRAM sockets don't include outer IP header - packet starts at ICMP
        let responder = IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1));
        let our_id = 0xABCD;

        // ICMP Time Exceeded (8) + Original IPv4 (20) + Original ICMP (12) = 40 bytes
        // Note: 12 bytes of original ICMP to include payload for fallback test
        let mut packet = vec![0u8; 40];

        // ICMP Time Exceeded header
        packet[0] = 11; // Type: Time Exceeded
        packet[1] = 0; // Code: TTL exceeded
        // Checksum at [2-3] - not validated for error messages
        // Unused at [4-7]

        // Original IP header (inside ICMP payload at offset 8)
        packet[8] = 0x45; // Version 4, IHL 5
        packet[17] = 1; // Protocol: ICMP

        // Original ICMP Echo Request (at offset 28 = 8 + 20)
        packet[28] = 8; // Type: Echo Request
        packet[29] = 0; // Code: 0
        // Checksum at [30-31]
        packet[32] = 0xAB; // Identifier high byte
        packet[33] = 0xCD; // Identifier low byte

        // Sequence (TTL=5, seq=3)
        let probe_id = ProbeId::new(5, 3);
        let seq = probe_id.to_sequence();
        packet[34] = (seq >> 8) as u8;
        packet[35] = (seq & 0xFF) as u8;

        // Original ICMP payload: embedded ProbeId at bytes 0-3 (offset 36-39)
        packet[36] = 0xAB; // Identifier high byte
        packet[37] = 0xCD; // Identifier low byte
        packet[38] = (seq >> 8) as u8;
        packet[39] = (seq & 0xFF) as u8;

        let result = parse_icmp_response(&packet, responder, our_id, true); // is_dgram=true
        assert!(result.is_some());

        let parsed = result.unwrap();
        assert_eq!(parsed.probe_id.ttl, 5);
        assert_eq!(parsed.probe_id.seq, 3);
        assert!(matches!(
            parsed.response_type,
            IcmpResponseType::TimeExceeded(0)
        ));
    }

    #[test]
    fn test_parse_echo_reply_dgram_payload_fallback() {
        // Test the payload-based identifier fallback when ICMP header identifier differs
        let responder = IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8));
        let our_id = 0x1234;

        let mut packet = vec![0u8; 16];

        // ICMP header with DIFFERENT identifier (simulating macOS override)
        packet[0] = 0; // Type: Echo Reply
        packet[1] = 0; // Code: 0
        packet[4] = 0xFF; // Wrong identifier high byte
        packet[5] = 0xFF; // Wrong identifier low byte

        let probe_id = ProbeId::new(10, 5);
        let seq = probe_id.to_sequence();
        packet[6] = (seq >> 8) as u8;
        packet[7] = (seq & 0xFF) as u8;

        // Payload: CORRECT identifier (fallback should find this)
        packet[8] = 0x12; // Identifier high byte
        packet[9] = 0x34; // Identifier low byte
        packet[10] = (seq >> 8) as u8;
        packet[11] = (seq & 0xFF) as u8;

        set_icmp_checksum(&mut packet);

        let result = parse_icmp_response(&packet, responder, our_id, true);
        assert!(result.is_some());

        let parsed = result.unwrap();
        assert_eq!(parsed.probe_id.ttl, 10);
        assert_eq!(parsed.probe_id.seq, 5);
    }

    #[test]
    fn test_parse_echo_reply_raw_payload_fallback() {
        // Test RAW socket payload fallback when ICMP header identifier differs
        // This happens on macOS when send uses DGRAM (kernel may modify ID) but recv uses RAW
        let responder = IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8));
        let our_id = 0x1234;

        // RAW packet: 20 IP + 8 ICMP header + 8 payload = 36 bytes
        let mut packet = vec![0u8; 36];

        // IPv4 header
        packet[0] = 0x45; // Version 4, IHL 5 (20 bytes)
        packet[9] = 1; // Protocol: ICMP

        // ICMP Echo Reply with WRONG identifier (offset 20)
        packet[20] = 0; // Type: Echo Reply
        packet[21] = 0; // Code: 0
        packet[24] = 0xFF; // Wrong ID high
        packet[25] = 0xFF; // Wrong ID low

        let probe_id = ProbeId::new(10, 5);
        let seq = probe_id.to_sequence();
        packet[26] = (seq >> 8) as u8;
        packet[27] = (seq & 0xFF) as u8;

        // Payload with CORRECT identifier (offset 28)
        packet[28] = 0x12; // our_id high
        packet[29] = 0x34; // our_id low
        packet[30] = (seq >> 8) as u8;
        packet[31] = (seq & 0xFF) as u8;

        // Set valid ICMP checksum (ICMP starts at offset 20)
        set_icmp_checksum(&mut packet[20..]);

        let result = parse_icmp_response(&packet, responder, our_id, false); // is_dgram=false (RAW)
        assert!(result.is_some());

        let parsed = result.unwrap();
        assert_eq!(parsed.probe_id.ttl, 10);
        assert_eq!(parsed.probe_id.seq, 5);
        assert_eq!(parsed.response_type, IcmpResponseType::EchoReply);
    }

    #[test]
    fn test_parse_time_exceeded_raw_payload_fallback() {
        // Test RAW socket Time Exceeded payload fallback when ICMP header identifier differs
        // This is the intermediate router case - the actual traceroute hops
        let responder = IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1));
        let our_id = 0x1234;

        // RAW Time Exceeded packet structure:
        // [0-19]   Outer IP header (20 bytes)
        // [20-27]  ICMP Time Exceeded header (8 bytes): type=11, code=0, checksum, unused
        // [28-47]  Original IP header (20 bytes)
        // [48-63]  Original ICMP Echo Request (8 header + 8 payload = 16 bytes)
        let mut packet = vec![0u8; 64];

        // Outer IPv4 header
        packet[0] = 0x45; // Version 4, IHL 5 (20 bytes)
        packet[9] = 1; // Protocol: ICMP

        // ICMP Time Exceeded header (offset 20)
        packet[20] = 11; // Type: Time Exceeded
        packet[21] = 0; // Code: TTL exceeded in transit

        // Original IP header (offset 28)
        packet[28] = 0x45; // Version 4, IHL 5
        packet[37] = 1; // Protocol: ICMP

        // Original ICMP Echo Request (offset 48)
        packet[48] = 8; // Type: Echo Request
        packet[49] = 0; // Code: 0
        // Wrong identifier in ICMP header
        packet[52] = 0xFF; // Wrong ID high
        packet[53] = 0xFF; // Wrong ID low

        let probe_id = ProbeId::new(3, 1); // TTL 3, seq 1
        let seq = probe_id.to_sequence();
        packet[54] = (seq >> 8) as u8;
        packet[55] = (seq & 0xFF) as u8;

        // Payload with CORRECT identifier (offset 56 = 48 + 8)
        packet[56] = 0x12; // our_id high
        packet[57] = 0x34; // our_id low
        packet[58] = (seq >> 8) as u8;
        packet[59] = (seq & 0xFF) as u8;

        // Set ICMP checksum for outer Time Exceeded (offset 20, length 44)
        set_icmp_checksum(&mut packet[20..]);

        let result = parse_icmp_response(&packet, responder, our_id, false); // is_dgram=false (RAW)
        assert!(result.is_some());

        let parsed = result.unwrap();
        assert_eq!(parsed.probe_id.ttl, 3);
        assert_eq!(parsed.probe_id.seq, 1);
        assert!(matches!(
            parsed.response_type,
            IcmpResponseType::TimeExceeded(0)
        ));
    }

    // ========================================================================
    // Property-based tests (proptest)
    // ========================================================================

    use proptest::prelude::*;

    proptest! {
        /// ProbeId should roundtrip through sequence encoding for all values
        #[test]
        fn proptest_probe_id_roundtrip(ttl in 0u8..=255, seq in 0u8..=255) {
            let original = ProbeId::new(ttl, seq);
            let encoded = original.to_sequence();
            let decoded = ProbeId::from_sequence(encoded);

            prop_assert_eq!(decoded.ttl, original.ttl);
            prop_assert_eq!(decoded.seq, original.seq);
        }

        /// Any u16 sequence should decode and re-encode to the same value
        #[test]
        fn proptest_probe_id_from_any_sequence(seq in 0u16..=65535) {
            let decoded = ProbeId::from_sequence(seq);
            let re_encoded = decoded.to_sequence();

            prop_assert_eq!(re_encoded, seq);
        }

        /// MplsLabel should correctly parse label, exp, bottom, and ttl fields
        #[test]
        fn proptest_mpls_label_parsing(
            label in 0u32..=0xFFFFF,  // 20 bits
            exp in 0u8..=7,           // 3 bits
            bottom in prop::bool::ANY,
            ttl in 0u8..=255          // 8 bits
        ) {
            let bottom_bit = if bottom { 1u32 } else { 0u32 };
            let word = (label << 12) | ((exp as u32) << 9) | (bottom_bit << 8) | (ttl as u32);
            let bytes = word.to_be_bytes();

            let parsed = MplsLabel::from_bytes(&bytes);

            prop_assert_eq!(parsed.label, label);
            prop_assert_eq!(parsed.exp, exp);
            prop_assert_eq!(parsed.bottom, bottom);
            prop_assert_eq!(parsed.ttl, ttl);
        }

        /// Any 4 bytes should parse as MplsLabel without panicking
        #[test]
        fn proptest_mpls_label_no_panic(b0 in 0u8..=255, b1 in 0u8..=255, b2 in 0u8..=255, b3 in 0u8..=255) {
            let bytes = [b0, b1, b2, b3];
            let _ = MplsLabel::from_bytes(&bytes);
        }

        /// Random bytes should not panic when parsed as ICMP
        #[test]
        fn proptest_parse_icmp_no_panic(data in prop::collection::vec(0u8..=255, 0..1500)) {
            let responder = IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1));
            let _ = parse_icmp_response(&data, responder, 0x1234, false);
        }

        /// Packets with random IP version nibbles should not panic
        #[test]
        fn proptest_parse_icmp_random_version(version in 0u8..=15, rest in prop::collection::vec(0u8..=255, 20..100)) {
            let mut data = rest;
            if !data.is_empty() {
                data[0] = (version << 4) | (data[0] & 0x0F);
            }

            let responder = IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8));
            let _ = parse_icmp_response(&data, responder, 0x5678, false);
        }

        /// IPv4 packets with various IHL values should not panic
        #[test]
        fn proptest_parse_ipv4_variable_ihl(
            ihl in 5u8..=15,
            payload in prop::collection::vec(0u8..=255, 0..200)
        ) {
            let header_len = (ihl as usize) * 4;
            let mut data = vec![0u8; header_len.max(20) + payload.len()];

            data[0] = 0x40 | ihl;
            let len = data.len() as u16;
            data[2] = (len >> 8) as u8;
            data[3] = len as u8;
            data[9] = 1; // ICMP

            if header_len < data.len() {
                let copy_len = payload.len().min(data.len() - header_len);
                data[header_len..header_len + copy_len].copy_from_slice(&payload[..copy_len]);
            }

            let responder = IpAddr::V4(std::net::Ipv4Addr::new(172, 16, 0, 1));
            let _ = parse_icmp_response(&data, responder, 0x9999, false);
        }

        /// ICMP checksum validation should handle all byte patterns
        #[test]
        fn proptest_checksum_no_panic(data in prop::collection::vec(0u8..=255, 0..100)) {
            let _ = validate_icmp_checksum(&data);
        }

        /// Valid checksums should validate correctly
        #[test]
        fn proptest_valid_checksum_validates(
            identifier in 0u16..=65535,
            sequence in 0u16..=65535
        ) {
            // Build Echo Reply with correct checksum
            let mut packet = vec![
                0,    // Type: Echo Reply
                0,    // Code
                0, 0, // Checksum (placeholder)
                (identifier >> 8) as u8,
                identifier as u8,
                (sequence >> 8) as u8,
                sequence as u8,
            ];

            set_icmp_checksum(&mut packet);
            prop_assert!(validate_icmp_checksum(&packet));
        }

        /// Packets too short for valid IP headers should return None
        #[test]
        fn proptest_short_packets_return_none(size in 0usize..20) {
            let data = vec![0x45u8; size]; // IPv4 version nibble but too short
            let responder = IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1));
            prop_assert!(parse_icmp_response(&data, responder, 0x1234, false).is_none());
        }
    }
}
