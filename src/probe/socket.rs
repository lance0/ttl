use anyhow::{Result, anyhow};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
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

/// Socket with metadata about type (for DGRAM-aware parsing)
#[derive(Debug)]
pub struct SocketInfo {
    pub socket: Socket,
    /// True if SOCK_DGRAM (no IP header in received packets)
    pub is_dgram: bool,
}

/// Check socket permissions and return capability level
/// On macOS, requires RAW socket for receiving ICMP Time Exceeded messages
/// (DGRAM sockets only receive Echo Reply, not error messages from routers)
#[cfg(target_os = "macos")]
pub fn check_permissions() -> Result<SocketCapability> {
    // On macOS:
    // - Send socket uses DGRAM (supports IP_TTL for per-probe TTL control)
    // - Receive socket must use RAW (DGRAM can't receive Time Exceeded from routers)
    //
    // Since RAW sockets require root, traceroute on macOS needs sudo.

    // Check if we can create RAW socket (needed for receiving)
    if create_raw_icmp_socket(false).is_err() {
        return Err(anyhow!(
            "Insufficient permissions for ICMP sockets.\n\n\
             On macOS, raw sockets are required to receive ICMP Time Exceeded\n\
             messages from intermediate routers.\n\n\
             Fix: Run with sudo: sudo ttl <target>"
        ));
    }

    // Also verify DGRAM works for sending (should always work if RAW works)
    if create_dgram_icmp_socket().is_err() {
        return Err(anyhow!(
            "Failed to create ICMP socket for sending.\n\n\
             Fix: Run with sudo: sudo ttl <target>"
        ));
    }

    // Check IPv6 DGRAM and warn if unavailable
    if create_dgram_icmpv6_socket().is_err() {
        eprintln!("Note: IPv6 DGRAM sockets unavailable; IPv6 traceroute may not work correctly.");
    }

    // Return Raw capability since we're using RAW for receiving
    Ok(SocketCapability::Raw)
}

/// Check socket permissions and return capability level
/// On Linux, prefers RAW for full functionality
#[cfg(not(target_os = "macos"))]
pub fn check_permissions() -> Result<SocketCapability> {
    // Try raw socket first (full functionality)
    if create_raw_icmp_socket(false).is_ok() {
        return Ok(SocketCapability::Raw);
    }

    // Try unprivileged ICMP (SOCK_DGRAM with IPPROTO_ICMP)
    if create_dgram_icmp_socket().is_ok() {
        eprintln!("Warning: Using unprivileged ICMP sockets. Some features may be limited.");
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

/// Create an unprivileged IPv4 ICMP socket (SOCK_DGRAM)
/// This socket type allows IP_TTL to be set on macOS
pub fn create_dgram_icmp_socket() -> Result<Socket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4))?;
    socket.set_nonblocking(false)?;
    socket.set_read_timeout(Some(Duration::from_secs(1)))?;
    Ok(socket)
}

/// Create an unprivileged IPv6 ICMPv6 socket (SOCK_DGRAM)
/// Used on macOS for IP_TTL support, and on Linux for unprivileged ICMP fallback
pub fn create_dgram_icmpv6_socket() -> Result<Socket> {
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::ICMPV6))?;
    socket.set_nonblocking(false)?;
    socket.set_read_timeout(Some(Duration::from_secs(1)))?;
    Ok(socket)
}

/// Create DGRAM ICMP socket for either IPv4 or IPv6
/// Used on macOS for IP_TTL support, and on Linux for unprivileged ICMP fallback
pub fn create_dgram_icmp_socket_any(ipv6: bool) -> Result<Socket> {
    if ipv6 {
        create_dgram_icmpv6_socket()
    } else {
        create_dgram_icmp_socket()
    }
}

/// Create a socket for sending ICMP probes with configurable TTL
/// On macOS, uses DGRAM socket because RAW sockets don't support IP_TTL
/// On Linux, prefers RAW, falls back to DGRAM for unprivileged ICMP
pub fn create_send_socket(ipv6: bool) -> Result<SocketInfo> {
    #[cfg(target_os = "macos")]
    {
        // macOS: Prefer DGRAM (supports IP_TTL)
        if let Ok(socket) = create_dgram_icmp_socket_any(ipv6) {
            return Ok(SocketInfo {
                socket,
                is_dgram: true,
            });
        }
        // Fall back to RAW (won't support TTL but might work for something)
        let socket = create_raw_icmp_socket(ipv6)?;
        return Ok(SocketInfo {
            socket,
            is_dgram: false,
        });
    }

    #[cfg(not(target_os = "macos"))]
    {
        // Linux: Prefer RAW, fall back to DGRAM for unprivileged
        if let Ok(socket) = create_raw_icmp_socket(ipv6) {
            return Ok(SocketInfo {
                socket,
                is_dgram: false,
            });
        }
        // DGRAM fallback - don't try RAW again, just error if DGRAM fails
        let socket = create_dgram_icmp_socket_any(ipv6)?;
        Ok(SocketInfo {
            socket,
            is_dgram: true,
        })
    }
}

/// Create a socket for receiving ICMP responses
/// On macOS, must use RAW socket to receive ICMP Time Exceeded messages
/// (DGRAM sockets only receive Echo Reply, not error messages from intermediate routers)
/// On Linux, tries RAW first, falls back to DGRAM for unprivileged ICMP
pub fn create_recv_socket(ipv6: bool) -> Result<SocketInfo> {
    #[cfg(target_os = "macos")]
    {
        // macOS: Must use RAW (DGRAM can't receive Time Exceeded from routers)
        let socket = create_raw_icmp_socket(ipv6)?;
        if let Err(e) = socket.set_recv_buffer_size(1024 * 1024) {
            eprintln!("Warning: Could not set receive buffer to 1MB: {}", e);
        }
        return Ok(SocketInfo {
            socket,
            is_dgram: false,
        });
    }

    #[cfg(not(target_os = "macos"))]
    {
        // Linux: Try RAW first, fall back to DGRAM for unprivileged ICMP
        if let Ok(socket) = create_raw_icmp_socket(ipv6) {
            let _ = socket.set_recv_buffer_size(1024 * 1024);
            return Ok(SocketInfo {
                socket,
                is_dgram: false,
            });
        }
        // DGRAM fallback for unprivileged users (ping_group_range)
        let socket = create_dgram_icmp_socket_any(ipv6)?;
        let _ = socket.set_recv_buffer_size(1024 * 1024);
        Ok(SocketInfo {
            socket,
            is_dgram: true,
        })
    }
}

/// Set TTL on a socket
pub fn set_ttl(socket: &Socket, ttl: u8) -> Result<()> {
    socket.set_ttl(ttl as u32)?;
    Ok(())
}

/// Set DSCP/ToS value on socket for QoS testing
/// DSCP occupies upper 6 bits of TOS byte, so shift left by 2
pub fn set_dscp(socket: &Socket, dscp: u8, ipv6: bool) -> Result<()> {
    let tos = (dscp as u32) << 2;
    if ipv6 {
        socket.set_tclass_v6(tos)?;
    } else {
        socket.set_tos(tos)?;
    }
    Ok(())
}

/// Bind socket to a specific source IP address
/// Call this after interface binding (if any) to force a specific source address
pub fn bind_to_source_ip(socket: &Socket, ip: IpAddr) -> Result<()> {
    let addr = SocketAddr::new(ip, 0);
    socket.bind(&SockAddr::from(addr))?;
    Ok(())
}

/// Set Don't Fragment flag for Path MTU Discovery
/// - IPv4: Sets IP_MTU_DISCOVER = IP_PMTUDISC_DO (always set DF bit)
/// - IPv6: Sets IPV6_DONTFRAG = 1 (prevent source fragmentation)
#[cfg(target_os = "linux")]
pub fn set_dont_fragment(socket: &Socket, ipv6: bool) -> Result<()> {
    use std::os::unix::io::AsRawFd;

    if ipv6 {
        // IPV6_DONTFRAG = 62 on Linux
        const IPV6_DONTFRAG: libc::c_int = 62;
        let val: libc::c_int = 1;
        let ret = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_IPV6,
                IPV6_DONTFRAG,
                &val as *const _ as *const libc::c_void,
                std::mem::size_of_val(&val) as libc::socklen_t,
            )
        };
        if ret != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
    } else {
        // IP_MTU_DISCOVER = 10, IP_PMTUDISC_DO = 2 on Linux
        const IP_MTU_DISCOVER: libc::c_int = 10;
        const IP_PMTUDISC_DO: libc::c_int = 2;
        let val: libc::c_int = IP_PMTUDISC_DO;
        let ret = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_IP,
                IP_MTU_DISCOVER,
                &val as *const _ as *const libc::c_void,
                std::mem::size_of_val(&val) as libc::socklen_t,
            )
        };
        if ret != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
    }
    Ok(())
}

/// Set Don't Fragment flag for Path MTU Discovery (macOS)
/// - IPv4: Sets IP_DONTFRAG = 1
/// - IPv6: Sets IPV6_DONTFRAG = 1
#[cfg(target_os = "macos")]
pub fn set_dont_fragment(socket: &Socket, ipv6: bool) -> Result<()> {
    use std::os::unix::io::AsRawFd;

    if ipv6 {
        // IPV6_DONTFRAG = 62 on macOS
        const IPV6_DONTFRAG: libc::c_int = 62;
        let val: libc::c_int = 1;
        let ret = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_IPV6,
                IPV6_DONTFRAG,
                &val as *const _ as *const libc::c_void,
                std::mem::size_of_val(&val) as libc::socklen_t,
            )
        };
        if ret != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
    } else {
        // IP_DONTFRAG = 28 on macOS
        const IP_DONTFRAG: libc::c_int = 28;
        let val: libc::c_int = 1;
        let ret = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_IP,
                IP_DONTFRAG,
                &val as *const _ as *const libc::c_void,
                std::mem::size_of_val(&val) as libc::socklen_t,
            )
        };
        if ret != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
    }
    Ok(())
}

/// Send ICMP packet to target
pub fn send_icmp(socket: &Socket, packet: &[u8], target: IpAddr) -> Result<usize> {
    let addr = SocketAddr::new(target, 0);
    let sock_addr = SockAddr::from(addr);
    let sent = socket.send_to(packet, &sock_addr)?;
    Ok(sent)
}

// ============================================================================
// Response TTL extraction for asymmetric routing detection
// ============================================================================

/// Result of receiving an ICMP packet with TTL info
#[derive(Debug)]
pub struct RecvResult {
    pub len: usize,
    pub source: IpAddr,
    /// TTL/hop-limit from the IP header of the response packet
    pub response_ttl: Option<u8>,
}

/// Enable IP_RECVTTL/IPV6_RECVHOPLIMIT socket option
/// This allows recvmsg() to return the TTL of received packets in ancillary data
#[cfg(unix)]
pub fn enable_recv_ttl(socket: &Socket, ipv6: bool) -> Result<()> {
    use std::os::unix::io::AsRawFd;

    // Platform-specific constants
    #[cfg(target_os = "linux")]
    const IP_RECVTTL: libc::c_int = 12;
    #[cfg(target_os = "linux")]
    const IPV6_RECVHOPLIMIT: libc::c_int = 51;
    #[cfg(target_os = "macos")]
    const IP_RECVTTL: libc::c_int = 24;
    #[cfg(target_os = "macos")]
    const IPV6_RECVHOPLIMIT: libc::c_int = 37;

    let (level, optname) = if ipv6 {
        (libc::IPPROTO_IPV6, IPV6_RECVHOPLIMIT)
    } else {
        (libc::IPPROTO_IP, IP_RECVTTL)
    };

    let val: libc::c_int = 1;
    let ret = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            level,
            optname,
            &val as *const _ as *const libc::c_void,
            std::mem::size_of_val(&val) as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

/// Receive ICMP packet with response TTL from control message
/// Uses recvmsg() to access ancillary data containing TTL/hop-limit
#[cfg(unix)]
pub fn recv_icmp_with_ttl(socket: &Socket, buffer: &mut [u8], ipv6: bool) -> Result<RecvResult> {
    use std::os::unix::io::AsRawFd;

    // Set up iovec for the data buffer
    let mut iov = libc::iovec {
        iov_base: buffer.as_mut_ptr() as *mut libc::c_void,
        iov_len: buffer.len(),
    };

    // Allocate control message buffer (for TTL)
    let mut cmsg_buf = [0u8; 64];

    // Source address storage
    let mut src_storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };

    // Set up msghdr
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = &mut src_storage as *mut _ as *mut libc::c_void;
    msg.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    // msg_controllen type differs: usize on Linux, u32 on macOS
    msg.msg_controllen = cmsg_buf.len() as _;

    // Receive the packet
    let len = unsafe { libc::recvmsg(socket.as_raw_fd(), &mut msg, 0) };

    if len < 0 {
        return Err(std::io::Error::last_os_error().into());
    }

    // Parse source address
    let source = parse_sockaddr_storage(&src_storage)?;

    // Extract TTL from control message
    let response_ttl = extract_ttl_from_cmsg(&msg, ipv6);

    Ok(RecvResult {
        len: len as usize,
        source,
        response_ttl,
    })
}

/// Extract TTL/hop limit from control message
#[cfg(unix)]
fn extract_ttl_from_cmsg(msg: &libc::msghdr, ipv6: bool) -> Option<u8> {
    // Platform-specific cmsg type values for IP_TTL
    // Linux: IP_TTL = 2
    // macOS: IP_TTL = 4, but IP_RECVTTL = 24 - accept both to be safe
    #[cfg(target_os = "linux")]
    fn is_ip_ttl_type(cmsg_type: libc::c_int) -> bool {
        cmsg_type == 2 // IP_TTL
    }
    #[cfg(target_os = "macos")]
    fn is_ip_ttl_type(cmsg_type: libc::c_int) -> bool {
        // Accept both IP_TTL (4) and IP_RECVTTL (24) since macOS may deliver either
        cmsg_type == 4 || cmsg_type == 24
    }

    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(msg);
        while !cmsg.is_null() {
            let hdr = &*cmsg;

            if ipv6 {
                // IPV6_HOPLIMIT
                if hdr.cmsg_level == libc::IPPROTO_IPV6 && hdr.cmsg_type == libc::IPV6_HOPLIMIT {
                    let data_ptr = libc::CMSG_DATA(cmsg);
                    let ttl = *(data_ptr as *const i32);
                    return Some(ttl as u8);
                }
            } else {
                // IP_TTL - check platform-specific type(s)
                if hdr.cmsg_level == libc::IPPROTO_IP && is_ip_ttl_type(hdr.cmsg_type) {
                    let data_ptr = libc::CMSG_DATA(cmsg);
                    let ttl = *(data_ptr as *const i32);
                    return Some(ttl as u8);
                }
            }

            cmsg = libc::CMSG_NXTHDR(msg, cmsg);
        }
    }
    None
}

/// Parse sockaddr_storage to IpAddr
#[cfg(unix)]
fn parse_sockaddr_storage(storage: &libc::sockaddr_storage) -> Result<IpAddr> {
    match storage.ss_family as libc::c_int {
        libc::AF_INET => {
            let addr: &libc::sockaddr_in = unsafe { &*(storage as *const _ as *const _) };
            let ip = std::net::Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
            Ok(IpAddr::V4(ip))
        }
        libc::AF_INET6 => {
            let addr: &libc::sockaddr_in6 = unsafe { &*(storage as *const _ as *const _) };
            let ip = std::net::Ipv6Addr::from(addr.sin6_addr.s6_addr);
            Ok(IpAddr::V6(ip))
        }
        _ => Err(anyhow!("Unknown address family: {}", storage.ss_family)),
    }
}

// ============================================================================
// Interface-aware socket creation variants
// ============================================================================

use crate::probe::interface::{InterfaceInfo, bind_socket_to_interface};

/// Create a socket for sending ICMP probes, optionally bound to an interface
pub fn create_send_socket_with_interface(
    ipv6: bool,
    interface: Option<&InterfaceInfo>,
) -> Result<SocketInfo> {
    let socket_info = create_send_socket(ipv6)?;
    if let Some(info) = interface {
        bind_socket_to_interface(&socket_info.socket, info)?;
    }
    Ok(socket_info)
}

/// Create a socket for receiving ICMP responses, optionally bound to an interface
pub fn create_recv_socket_with_interface(
    ipv6: bool,
    interface: Option<&InterfaceInfo>,
) -> Result<SocketInfo> {
    let socket_info = create_recv_socket(ipv6)?;
    if let Some(info) = interface {
        bind_socket_to_interface(&socket_info.socket, info)?;
    }

    // Enable TTL reception for asymmetric routing detection
    // This is best-effort - continue without if it fails
    #[cfg(unix)]
    if let Err(e) = enable_recv_ttl(&socket_info.socket, ipv6) {
        // Only warn in debug mode - this is expected to fail in some environments
        #[cfg(debug_assertions)]
        eprintln!("Note: Could not enable TTL reception: {}", e);
        let _ = e; // Silence unused warning in release
    }

    Ok(socket_info)
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
