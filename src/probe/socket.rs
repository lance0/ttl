use anyhow::{anyhow, Result};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::mem::MaybeUninit;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

/// Socket capability level
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketCapability {
    /// Full raw socket access - can send/receive with custom IP headers
    Raw,
    /// Unprivileged ICMP socket (limited functionality)
    Dgram,
}

/// Check socket permissions and return capability level
pub fn check_permissions() -> Result<SocketCapability> {
    // Try raw socket first
    if create_raw_icmp_socket(false).is_ok() {
        return Ok(SocketCapability::Raw);
    }

    // Try unprivileged ICMP (SOCK_DGRAM with IPPROTO_ICMP)
    if create_dgram_icmp_socket().is_ok() {
        eprintln!(
            "Warning: Using unprivileged ICMP sockets. Some features may be limited."
        );
        return Ok(SocketCapability::Dgram);
    }

    let binary_path = std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "ttl".to_string());

    Err(anyhow!(
        "Insufficient permissions for raw sockets.\n\n\
         Fix options:\n\
         \u{2022} Run with sudo: sudo ttl <target>\n\
         \u{2022} Add capability: sudo setcap cap_net_raw+ep {}\n\
         \u{2022} Enable unprivileged ICMP: sudo sysctl -w net.ipv4.ping_group_range='0 65534'",
        binary_path
    ))
}

/// Create a raw ICMP socket
pub fn create_raw_icmp_socket(ipv6: bool) -> Result<Socket> {
    let domain = if ipv6 { Domain::IPV6 } else { Domain::IPV4 };
    let protocol = if ipv6 {
        Protocol::ICMPV6
    } else {
        Protocol::ICMPV4
    };

    let socket = Socket::new(domain, Type::RAW, Some(protocol))?;

    // Set socket options
    socket.set_nonblocking(false)?;
    socket.set_read_timeout(Some(Duration::from_secs(1)))?;

    // Enable IP_HDRINCL for sending (we build the full IP header)
    // Note: Not needed for ICMP, kernel handles IP header
    // socket.set_header_included(true)?;

    Ok(socket)
}

/// Create an unprivileged ICMP socket (SOCK_DGRAM)
pub fn create_dgram_icmp_socket() -> Result<Socket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4))?;
    socket.set_nonblocking(false)?;
    socket.set_read_timeout(Some(Duration::from_secs(1)))?;
    Ok(socket)
}

/// Create a socket for sending ICMP probes with configurable TTL
pub fn create_send_socket(ipv6: bool) -> Result<Socket> {
    let socket = create_raw_icmp_socket(ipv6)?;

    // We'll set TTL per-packet before sending
    Ok(socket)
}

/// Create a socket for receiving ICMP responses
pub fn create_recv_socket(ipv6: bool) -> Result<Socket> {
    let socket = create_raw_icmp_socket(ipv6)?;

    // Increase receive buffer size for high probe rates
    socket.set_recv_buffer_size(1024 * 1024)?; // 1MB

    Ok(socket)
}

/// Set TTL on a socket
pub fn set_ttl(socket: &Socket, ttl: u8) -> Result<()> {
    socket.set_ttl(ttl as u32)?;
    Ok(())
}

/// Send ICMP packet to target
pub fn send_icmp(socket: &Socket, packet: &[u8], target: IpAddr) -> Result<usize> {
    let addr = SocketAddr::new(target, 0);
    let sock_addr = SockAddr::from(addr);
    let sent = socket.send_to(packet, &sock_addr)?;
    Ok(sent)
}

/// Receive ICMP packet
pub fn recv_icmp(socket: &Socket, buffer: &mut [u8]) -> Result<(usize, IpAddr)> {
    // Convert buffer to MaybeUninit slice for socket2
    let uninit_buf: &mut [MaybeUninit<u8>] = unsafe {
        std::slice::from_raw_parts_mut(buffer.as_mut_ptr() as *mut MaybeUninit<u8>, buffer.len())
    };

    let (len, addr) = socket.recv_from(uninit_buf)?;
    let ip = addr
        .as_socket()
        .map(|s| s.ip())
        .ok_or_else(|| anyhow!("Invalid source address"))?;
    Ok((len, ip))
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_probe_id_encoding() {
        use crate::state::ProbeId;

        let id = ProbeId::new(15, 42);
        let seq = id.to_sequence();
        let decoded = ProbeId::from_sequence(seq);

        assert_eq!(decoded.ttl, 15);
        assert_eq!(decoded.seq, 42);
    }
}
