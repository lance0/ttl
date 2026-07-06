use anyhow::{Result, anyhow};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::net::{IpAddr, SocketAddr, SocketAddrV6};
use std::time::Duration;

/// Socket capability level
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketCapability {
    /// Full raw socket access - can send/receive with custom IP headers
    Raw,
    /// Unprivileged ICMP socket (limited functionality)
    /// Note: Only used on Linux; macOS always requires Raw for receiving ICMP errors
    #[allow(dead_code)]
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
/// On macOS, requires RAW socket for receiving and DGRAM for sending (IP_TTL support)
#[cfg(target_os = "macos")]
pub fn check_permissions() -> Result<SocketCapability> {
    // On macOS:
    // - Send socket uses DGRAM (supports IP_TTL for per-probe TTL control)
    // - Receive socket must use RAW (DGRAM can't receive Time Exceeded from routers)
    //
    // Since RAW sockets require root, traceroute on macOS needs sudo.

    // Check if we can create RAW IPv4 socket (needed for receiving)
    if create_raw_icmp_socket(false).is_err() {
        return Err(anyhow!(
            "Insufficient permissions for ICMP sockets.\n\n\
             On macOS, raw sockets are required to receive ICMP Time Exceeded\n\
             messages from intermediate routers.\n\n\
             Fix: Run with sudo: sudo ttl <target>"
        ));
    }

    // Check RAW IPv6 and warn if unavailable
    if create_raw_icmp_socket(true).is_err() {
        eprintln!("Note: IPv6 raw sockets unavailable; IPv6 traceroute will not work.");
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
/// On FreeBSD/NetBSD, uses RAW sockets for both sending and receiving
/// (these BSDs do not support SOCK_DGRAM + IPPROTO_ICMP)
#[cfg(any(target_os = "freebsd", target_os = "netbsd"))]
pub fn check_permissions() -> Result<SocketCapability> {
    if create_raw_icmp_socket(false).is_err() {
        return Err(anyhow!(
            "Insufficient permissions for ICMP sockets.\n\n\
             Raw sockets are required for traceroute.\n\n\
             Fix: Run with sudo: sudo ttl <target>"
        ));
    }

    if create_raw_icmp_socket(true).is_err() {
        eprintln!("Note: IPv6 raw sockets unavailable; IPv6 traceroute will not work.");
    }

    Ok(SocketCapability::Raw)
}

/// Check socket permissions and return capability level
/// On Linux, requires RAW sockets for traceroute functionality
#[cfg(not(any(target_os = "macos", target_os = "freebsd", target_os = "netbsd")))]
pub fn check_permissions() -> Result<SocketCapability> {
    // RAW sockets required - DGRAM can't receive Time Exceeded from intermediate routers
    if create_raw_icmp_socket(false).is_ok() {
        // Also check IPv6 RAW - warn if unavailable
        if create_raw_icmp_socket(true).is_err() {
            eprintln!("Note: IPv6 raw sockets unavailable; IPv6 traceroute will not work.");
        }
        return Ok(SocketCapability::Raw);
    }

    let binary_path = std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "ttl".to_string());

    Err(anyhow!(
        "Insufficient permissions for raw sockets.\n\n\
         Fix (one-time):\n\
         \u{2022} sudo setcap cap_net_raw+ep {}\n\n\
         Or run with sudo:\n\
         \u{2022} sudo ttl <target>",
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
#[cfg(not(any(target_os = "freebsd", target_os = "netbsd")))]
pub fn create_dgram_icmp_socket() -> Result<Socket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4))?;
    socket.set_nonblocking(false)?;
    socket.set_read_timeout(Some(Duration::from_secs(1)))?;
    Ok(socket)
}

/// Create an unprivileged IPv6 ICMPv6 socket (SOCK_DGRAM)
/// Used on macOS for IP_TTL support, and on Linux for unprivileged ICMP fallback
#[cfg(not(any(target_os = "freebsd", target_os = "netbsd")))]
pub fn create_dgram_icmpv6_socket() -> Result<Socket> {
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::ICMPV6))?;
    socket.set_nonblocking(false)?;
    socket.set_read_timeout(Some(Duration::from_secs(1)))?;
    Ok(socket)
}

/// Create DGRAM ICMP socket for either IPv4 or IPv6
/// Used on macOS for IP_TTL support, and on Linux for unprivileged ICMP fallback
#[cfg(not(any(target_os = "freebsd", target_os = "netbsd")))]
pub fn create_dgram_icmp_socket_any(ipv6: bool) -> Result<Socket> {
    if ipv6 {
        create_dgram_icmpv6_socket()
    } else {
        create_dgram_icmp_socket()
    }
}

/// Create a socket for sending ICMP probes with configurable TTL
/// On macOS, uses DGRAM socket because RAW sockets don't support IP_TTL
/// On FreeBSD, uses RAW socket directly (DGRAM+ICMP not supported)
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
        eprintln!("Warning: DGRAM socket failed, using RAW. Per-probe TTL control may not work.");
        let socket = create_raw_icmp_socket(ipv6)?;
        Ok(SocketInfo {
            socket,
            is_dgram: false,
        })
    }

    #[cfg(any(target_os = "freebsd", target_os = "netbsd"))]
    {
        // FreeBSD/NetBSD: Use RAW directly (SOCK_DGRAM + IPPROTO_ICMP not supported)
        let socket = create_raw_icmp_socket(ipv6)?;
        Ok(SocketInfo {
            socket,
            is_dgram: false,
        })
    }

    #[cfg(not(any(target_os = "macos", target_os = "freebsd", target_os = "netbsd")))]
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
/// On macOS/FreeBSD, must use RAW socket to receive ICMP Time Exceeded messages
/// (DGRAM sockets only receive Echo Reply, not error messages from intermediate routers)
/// On Linux, tries RAW first, falls back to DGRAM for unprivileged ICMP
pub fn create_recv_socket(ipv6: bool) -> Result<SocketInfo> {
    #[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "netbsd"))]
    {
        // macOS/FreeBSD/NetBSD: Must use RAW (DGRAM can't receive Time Exceeded from routers)
        let socket = create_raw_icmp_socket(ipv6)?;
        if let Err(e) = socket.set_recv_buffer_size(1024 * 1024) {
            eprintln!("Warning: Could not set receive buffer to 1MB: {}", e);
        }
        Ok(SocketInfo {
            socket,
            is_dgram: false,
        })
    }

    #[cfg(not(any(target_os = "macos", target_os = "freebsd", target_os = "netbsd")))]
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

/// Set TTL on a socket (IPv4) or hop limit (IPv6)
pub fn set_ttl(socket: &Socket, ttl: u8, ipv6: bool) -> Result<()> {
    if ipv6 {
        socket.set_unicast_hops_v6(ttl as u32)?;
    } else {
        socket.set_ttl_v4(ttl as u32)?;
    }
    Ok(())
}

/// Set DSCP/ToS value on socket for QoS testing
/// DSCP occupies upper 6 bits of TOS byte, so shift left by 2
pub fn set_dscp(socket: &Socket, dscp: u8, ipv6: bool) -> Result<()> {
    let tos = (dscp as u32) << 2;
    if ipv6 {
        socket.set_tclass_v6(tos)?;
    } else {
        socket.set_tos_v4(tos)?;
    }
    Ok(())
}

/// Bind socket to a specific source IP address.
///
/// Call this after interface binding (if any) to force a specific source address.
/// For IPv6 link-local addresses, `scope_id` identifies the interface and must be
/// provided for the bind to succeed (LAN-143).
pub fn bind_to_source_ip(socket: &Socket, ip: IpAddr, scope_id: Option<u32>) -> Result<()> {
    let addr = match (ip, scope_id) {
        (IpAddr::V6(v6), Some(scope)) => SocketAddr::V6(SocketAddrV6::new(v6, 0, 0, scope)),
        (ip, _) => SocketAddr::new(ip, 0),
    };
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

/// Set Don't Fragment flag for Path MTU Discovery (NetBSD)
/// - IPv4: Returns error (NetBSD lacks IP_DONTFRAG; PMTUD unsupported for IPv4)
/// - IPv6: Sets IPV6_DONTFRAG = 1
#[cfg(target_os = "netbsd")]
pub fn set_dont_fragment(socket: &Socket, ipv6: bool) -> Result<()> {
    use std::os::unix::io::AsRawFd;

    if ipv6 {
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
        Ok(())
    } else {
        // IPv4: NetBSD has no IP_DONTFRAG — return error so PMTUD callers don't
        // proceed thinking DF is set (packets would fragment instead of triggering
        // ICMP Frag Needed, producing bogus MTU results)
        Err(anyhow!(
            "IP_DONTFRAG not supported on NetBSD; IPv4 PMTUD unavailable"
        ))
    }
}

/// Set Don't Fragment flag for Path MTU Discovery (macOS/FreeBSD)
/// - IPv4: Sets IP_DONTFRAG = 1
/// - IPv6: Sets IPV6_DONTFRAG = 1
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub fn set_dont_fragment(socket: &Socket, ipv6: bool) -> Result<()> {
    use std::os::unix::io::AsRawFd;

    // Platform-specific constants
    #[cfg(target_os = "macos")]
    const IP_DONTFRAG: libc::c_int = 28;
    #[cfg(target_os = "freebsd")]
    const IP_DONTFRAG: libc::c_int = 67;
    // IPV6_DONTFRAG = 62 on both macOS and FreeBSD
    const IPV6_DONTFRAG: libc::c_int = 62;

    if ipv6 {
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
    /// IPv6 scope ID from the source address (non-zero for link-local responders)
    pub scope_id: Option<u32>,
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
    #[cfg(target_os = "freebsd")]
    const IP_RECVTTL: libc::c_int = 65;
    #[cfg(target_os = "freebsd")]
    const IPV6_RECVHOPLIMIT: libc::c_int = 37;
    #[cfg(target_os = "netbsd")]
    const IP_RECVTTL: libc::c_int = 23;
    #[cfg(target_os = "netbsd")]
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

    // Allocate control message buffer (for TTL).
    // cmsghdr requires alignment: 8-byte on Linux/FreeBSD, 4-byte on macOS/NetBSD.
    // Using #[repr(align(8))] ensures the buffer is suitably aligned on all platforms.
    #[repr(align(8))]
    struct AlignedBuf([u8; 64]);
    let mut cmsg_buf = AlignedBuf([0u8; 64]);

    // Source address storage
    let mut src_storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };

    // Set up msghdr
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = &mut src_storage as *mut _ as *mut libc::c_void;
    msg.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.0.as_mut_ptr() as *mut libc::c_void;
    // msg_controllen type differs: usize on Linux, u32 on macOS
    msg.msg_controllen = cmsg_buf.0.len() as _;

    // Receive the packet
    let len = unsafe { libc::recvmsg(socket.as_raw_fd(), &mut msg, 0) };

    if len < 0 {
        return Err(std::io::Error::last_os_error().into());
    }

    // Parse source address (and IPv6 scope ID for link-local responders)
    let (source, scope_id) = parse_sockaddr_storage(&src_storage)?;

    // Check for MSG_CTRUNC - control message truncated, TTL may be unreliable
    let response_ttl = if msg.msg_flags & libc::MSG_CTRUNC != 0 {
        // Control buffer was too small, TTL extraction may fail
        None
    } else {
        extract_ttl_from_cmsg(&msg, ipv6)
    };

    Ok(RecvResult {
        len: len as usize,
        source,
        scope_id,
        response_ttl,
    })
}

/// Read a TTL / hop-limit value out of a cmsg data buffer, handling both
/// encodings seen in the wild: a 4-byte `int` (Linux IPv4 `IP_TTL`, and the
/// IPv6 hop-limit on every platform per RFC 3542) and a single `u_char` (the
/// BSD/macOS IPv4 `IP_RECVTTL`). `data_len` is the cmsg payload length in bytes.
///
/// # Safety
/// `data_ptr` must be valid for reads of `data_len` bytes, and `data_len >= 1`.
#[cfg(unix)]
unsafe fn read_cmsg_ttl(data_ptr: *const libc::c_uchar, data_len: usize) -> u8 {
    if data_len >= std::mem::size_of::<libc::c_int>() {
        // Native-endian int; `as u8` keeps the numerically low byte (the TTL)
        // on both little- and big-endian hosts.
        unsafe { std::ptr::read_unaligned(data_ptr as *const libc::c_int) as u8 }
    } else {
        unsafe { std::ptr::read_unaligned(data_ptr) }
    }
}

/// Extract TTL/hop limit from control message
#[cfg(unix)]
fn extract_ttl_from_cmsg(msg: &libc::msghdr, ipv6: bool) -> Option<u8> {
    // Platform-specific cmsg type values for IP_TTL
    // Linux: IP_TTL = 2
    // macOS: IP_TTL = 4, but IP_RECVTTL = 24 - accept both to be safe
    // FreeBSD: IP_TTL = 4, IP_RECVTTL = 65
    #[cfg(target_os = "linux")]
    fn is_ip_ttl_type(cmsg_type: libc::c_int) -> bool {
        cmsg_type == 2 // IP_TTL
    }
    #[cfg(target_os = "macos")]
    fn is_ip_ttl_type(cmsg_type: libc::c_int) -> bool {
        // Accept both IP_TTL (4) and IP_RECVTTL (24) since macOS may deliver either
        cmsg_type == 4 || cmsg_type == 24
    }
    #[cfg(target_os = "freebsd")]
    fn is_ip_ttl_type(cmsg_type: libc::c_int) -> bool {
        // Accept both IP_TTL (4) and IP_RECVTTL (65) since FreeBSD may deliver either
        cmsg_type == 4 || cmsg_type == 65
    }
    #[cfg(target_os = "netbsd")]
    fn is_ip_ttl_type(cmsg_type: libc::c_int) -> bool {
        // Accept both IP_TTL (4) and IP_RECVTTL (23) since NetBSD may deliver either
        cmsg_type == 4 || cmsg_type == 23
    }

    // IPV6_HOPLIMIT: use libc where available, define locally for NetBSD
    #[cfg(not(target_os = "netbsd"))]
    let ipv6_hoplimit = libc::IPV6_HOPLIMIT;
    #[cfg(target_os = "netbsd")]
    let ipv6_hoplimit: libc::c_int = 47;
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(msg);
        while !cmsg.is_null() {
            // Read header fields with read_unaligned — CMSG pointers may not be
            // suitably aligned for a direct reference on all platforms.
            let cmsg_level = std::ptr::addr_of!((*cmsg).cmsg_level).read_unaligned();
            let cmsg_type = std::ptr::addr_of!((*cmsg).cmsg_type).read_unaligned();
            let cmsg_len = std::ptr::addr_of!((*cmsg).cmsg_len).read_unaligned() as usize;

            // Require at least one data byte, then pick the read width by the
            // actual payload length (see read_cmsg_ttl). Gating on CMSG_LEN(int)
            // as before would wrongly drop the BSD/macOS 1-byte IPv4 IP_RECVTTL
            // cmsg; gating on one byte keeps the over-read protection (#102) while
            // still populating response TTL on those platforms.
            let header_len = libc::CMSG_LEN(0) as usize;
            if cmsg_len < header_len + 1 {
                cmsg = libc::CMSG_NXTHDR(msg, cmsg);
                continue;
            }
            let data_len = cmsg_len - header_len;

            if ipv6 {
                // IPV6_HOPLIMIT (always a 4-byte int per RFC 3542)
                if cmsg_level == libc::IPPROTO_IPV6 && cmsg_type == ipv6_hoplimit {
                    return Some(read_cmsg_ttl(libc::CMSG_DATA(cmsg), data_len));
                }
            } else {
                // IP_TTL / IP_RECVTTL - check platform-specific type(s)
                if cmsg_level == libc::IPPROTO_IP && is_ip_ttl_type(cmsg_type) {
                    return Some(read_cmsg_ttl(libc::CMSG_DATA(cmsg), data_len));
                }
            }

            cmsg = libc::CMSG_NXTHDR(msg, cmsg);
        }
    }
    None
}

/// Parse sockaddr_storage to IpAddr and (for IPv6) the scope ID.
///
/// For link-local IPv6 responders, `sin6_scope_id` identifies the interface the
/// response arrived on. Dropping it makes the address ambiguous when multiple
/// interfaces have link-local routers (LAN-143).
#[cfg(unix)]
fn parse_sockaddr_storage(storage: &libc::sockaddr_storage) -> Result<(IpAddr, Option<u32>)> {
    match storage.ss_family as libc::c_int {
        libc::AF_INET => {
            let addr: &libc::sockaddr_in = unsafe { &*(storage as *const _ as *const _) };
            let ip = std::net::Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
            Ok((IpAddr::V4(ip), None))
        }
        libc::AF_INET6 => {
            let addr: &libc::sockaddr_in6 = unsafe { &*(storage as *const _ as *const _) };
            let ip = std::net::Ipv6Addr::from(addr.sin6_addr.s6_addr);
            // sin6_scope_id is 0 for non-link-local addresses; preserve it so
            // link-local responders can be disambiguated.
            let scope_id = if addr.sin6_scope_id != 0 {
                Some(addr.sin6_scope_id)
            } else {
                None
            };
            Ok((IpAddr::V6(ip), scope_id))
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
        bind_socket_to_interface(&socket_info.socket, info, ipv6)?;
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
        bind_socket_to_interface(&socket_info.socket, info, ipv6)?;
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
    use super::*;

    #[test]
    fn test_probe_id_encoding() {
        use crate::state::ProbeId;

        let id = ProbeId::new(15, 42);
        let seq = id.to_sequence();
        let decoded = ProbeId::from_sequence(seq);

        assert_eq!(decoded.ttl, 15);
        assert_eq!(decoded.seq, 42);
    }

    #[test]
    fn test_parse_sockaddr_storage_ipv6_scope_id() {
        use std::mem;

        // Build a sockaddr_in6 with a link-local address and scope_id=3
        let mut storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
        let sin6: &mut libc::sockaddr_in6 =
            unsafe { &mut *(&mut storage as *mut _ as *mut libc::sockaddr_in6) };
        sin6.sin6_family = libc::AF_INET6 as _;
        sin6.sin6_addr.s6_addr = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        sin6.sin6_scope_id = 3;

        let (ip, scope_id) = parse_sockaddr_storage(&storage).unwrap();
        assert!(ip.is_ipv6());
        assert_eq!(scope_id, Some(3));
    }

    #[test]
    fn test_parse_sockaddr_storage_ipv6_no_scope_id() {
        use std::mem;

        // Global IPv6 address — scope_id should be None (sin6_scope_id == 0)
        let mut storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
        let sin6: &mut libc::sockaddr_in6 =
            unsafe { &mut *(&mut storage as *mut _ as *mut libc::sockaddr_in6) };
        sin6.sin6_family = libc::AF_INET6 as _;
        sin6.sin6_addr.s6_addr = [
            0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0x88,
        ];
        sin6.sin6_scope_id = 0;

        let (ip, scope_id) = parse_sockaddr_storage(&storage).unwrap();
        assert!(ip.is_ipv6());
        assert_eq!(scope_id, None);
    }

    #[test]
    fn test_parse_sockaddr_storage_ipv4() {
        use std::mem;

        let mut storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
        let sin: &mut libc::sockaddr_in =
            unsafe { &mut *(&mut storage as *mut _ as *mut libc::sockaddr_in) };
        sin.sin_family = libc::AF_INET as _;
        sin.sin_addr.s_addr = u32::from_be_bytes([8, 8, 8, 8]).to_be();

        let (ip, scope_id) = parse_sockaddr_storage(&storage).unwrap();
        assert_eq!(
            ip,
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8))
        );
        assert_eq!(scope_id, None);
    }

    // Run extract_ttl_from_cmsg over a single synthetic cmsg (level/type/payload).
    #[cfg(unix)]
    fn extract_one_cmsg(
        level: libc::c_int,
        ctype: libc::c_int,
        data: &[u8],
        ipv6: bool,
    ) -> Option<u8> {
        #[repr(align(8))]
        struct Buf([u8; 64]);
        let mut buf = Buf([0u8; 64]);
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_control = buf.0.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = buf.0.len() as _;
        unsafe {
            let cmsg = libc::CMSG_FIRSTHDR(&msg);
            assert!(!cmsg.is_null());
            (*cmsg).cmsg_level = level;
            (*cmsg).cmsg_type = ctype;
            (*cmsg).cmsg_len = libc::CMSG_LEN(data.len() as u32) as _;
            std::ptr::copy_nonoverlapping(data.as_ptr(), libc::CMSG_DATA(cmsg), data.len());
            // Trim controllen to exactly this cmsg so CMSG_NXTHDR terminates.
            msg.msg_controllen = libc::CMSG_SPACE(data.len() as u32) as _;
        }
        extract_ttl_from_cmsg(&msg, ipv6)
    }

    // Regression: BSD/macOS deliver the IPv4 IP_RECVTTL value as a single u_char.
    // A cmsg-length gate of CMSG_LEN(sizeof(int)) wrongly dropped it, blanking
    // response-TTL / return-hop estimation on those platforms. The read must be
    // width-aware: 1-byte u_char and 4-byte int both yield the TTL.
    #[test]
    #[cfg(unix)]
    fn test_extract_ttl_single_byte_and_int_widths() {
        // IPv4 IP_TTL / IP_RECVTTL cmsg_type this build accepts.
        #[cfg(target_os = "linux")]
        let ip_ttl_type = 2;
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        let ip_ttl_type = 24;
        #[cfg(target_os = "freebsd")]
        let ip_ttl_type = 65;
        #[cfg(target_os = "netbsd")]
        let ip_ttl_type = 23;
        #[cfg(not(any(
            target_os = "linux",
            target_os = "macos",
            target_os = "ios",
            target_os = "freebsd",
            target_os = "netbsd"
        )))]
        let ip_ttl_type = 2;

        // 1-byte u_char (BSD/macOS IPv4) — the regression case.
        assert_eq!(
            extract_one_cmsg(libc::IPPROTO_IP, ip_ttl_type, &[57u8], false),
            Some(57)
        );
        // 4-byte int (Linux IPv4) — must still work.
        assert_eq!(
            extract_one_cmsg(libc::IPPROTO_IP, ip_ttl_type, &57i32.to_ne_bytes(), false),
            Some(57)
        );

        // IPv6 hop-limit is always a 4-byte int.
        #[cfg(not(target_os = "netbsd"))]
        let hoplimit = libc::IPV6_HOPLIMIT;
        #[cfg(target_os = "netbsd")]
        let hoplimit = 47;
        assert_eq!(
            extract_one_cmsg(libc::IPPROTO_IPV6, hoplimit, &42i32.to_ne_bytes(), true),
            Some(42)
        );

        // Empty payload (data_len == 0) must be skipped, not over-read.
        assert_eq!(
            extract_one_cmsg(libc::IPPROTO_IP, ip_ttl_type, &[], false),
            None
        );
    }
}
