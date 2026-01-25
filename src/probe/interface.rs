//! Network interface binding utilities for socket creation
//!
//! Provides cross-platform interface validation and socket binding.
//! - Linux: Uses SO_BINDTODEVICE via socket2::bind_device()
//! - macOS: Uses IP_BOUND_IF via socket2::bind_device_by_index()

use anyhow::{Result, anyhow};
use pnet::datalink;
use socket2::Socket;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Check if an IPv6 address is link-local (fe80::/10)
///
/// Link-local addresses have the first 10 bits set to 1111111010,
/// which means the first segment is in the range 0xfe80-0xfebf.
pub fn is_link_local_ipv6(addr: &Ipv6Addr) -> bool {
    let first_seg = addr.segments()[0];
    (0xfe80..=0xfebf).contains(&first_seg)
}

/// Validated interface information
#[derive(Debug, Clone)]
pub struct InterfaceInfo {
    /// Interface name (e.g., "eth0", "wlan0")
    pub name: String,
    /// Interface index (used for macOS binding)
    #[allow(dead_code)]
    pub index: u32,
    /// First IPv4 address on the interface (if any)
    pub ipv4: Option<Ipv4Addr>,
    /// First IPv6 address on the interface (if any)
    pub ipv6: Option<Ipv6Addr>,
    /// Default gateway IPv4 address (if detected)
    pub gateway_ipv4: Option<Ipv4Addr>,
    /// Default gateway IPv6 address (if detected)
    pub gateway_ipv6: Option<Ipv6Addr>,
}

/// Detect the default IPv4 gateway for an interface using kernel APIs
///
/// Uses getifs which queries netlink (Linux) or sysctl (macOS) directly,
/// avoiding subprocess calls that can hang on systems with large routing tables.
fn detect_gateway_ipv4(interface: &str) -> Option<Ipv4Addr> {
    getifs::gateway_addrs()
        .ok()?
        .into_iter()
        .find(|gw| gw.name().ok().as_deref() == Some(interface))
        .and_then(|gw| match gw.addr() {
            IpAddr::V4(v4) => Some(v4),
            _ => None,
        })
}

/// Detect the default IPv6 gateway for an interface using kernel APIs
fn detect_gateway_ipv6(interface: &str) -> Option<Ipv6Addr> {
    getifs::gateway_addrs()
        .ok()?
        .into_iter()
        .find(|gw| gw.name().ok().as_deref() == Some(interface))
        .and_then(|gw| match gw.addr() {
            IpAddr::V6(v6) => Some(v6),
            _ => None,
        })
}

/// Detect default gateway without specifying an interface
///
/// Useful when no --interface flag is provided but we still want to show
/// which gateway will be used.
pub fn detect_default_gateway(ipv6: bool) -> Option<IpAddr> {
    let gateways = getifs::gateway_addrs().ok()?;

    if ipv6 {
        gateways
            .into_iter()
            .find(|gw| gw.addr().is_ipv6())
            .map(|gw| gw.addr())
    } else {
        gateways
            .into_iter()
            .find(|gw| gw.addr().is_ipv4())
            .map(|gw| gw.addr())
    }
}

/// Validate that an interface exists and get its information
///
/// Returns error if:
/// - Interface does not exist
/// - Interface has no usable IP addresses (link-local only on non-loopback)
pub fn validate_interface(name: &str) -> Result<InterfaceInfo> {
    for iface in datalink::interfaces() {
        if iface.name == name {
            let mut ipv4 = None;
            let mut ipv6 = None;
            let is_loopback = iface.is_loopback();

            for addr in &iface.ips {
                match addr.ip() {
                    IpAddr::V4(v4) if ipv4.is_none() && !v4.is_loopback() => {
                        ipv4 = Some(v4);
                    }
                    IpAddr::V6(v6) if ipv6.is_none() && !v6.is_loopback() => {
                        // Skip link-local addresses for non-loopback interfaces
                        // (they require scope IDs and can't reach Internet targets)
                        if !is_link_local_ipv6(&v6) {
                            ipv6 = Some(v6);
                        }
                    }
                    _ => {}
                }
            }

            // For loopback interface only, allow loopback and link-local addresses
            if is_loopback && ipv4.is_none() && ipv6.is_none() {
                for addr in &iface.ips {
                    match addr.ip() {
                        IpAddr::V4(v4) if ipv4.is_none() => ipv4 = Some(v4),
                        IpAddr::V6(v6) if ipv6.is_none() => ipv6 = Some(v6),
                        _ => {}
                    }
                }
            }

            // Reject non-loopback interfaces with only link-local addresses
            if !is_loopback && ipv4.is_none() && ipv6.is_none() {
                // Check if there are any addresses at all (vs link-local only)
                let has_any_addr = iface.ips.iter().any(|a| match a.ip() {
                    IpAddr::V4(_) => true,
                    IpAddr::V6(v6) => !v6.is_loopback(),
                });
                if has_any_addr {
                    return Err(anyhow!(
                        "Interface '{}' has only link-local IPv6 addresses. \
                         Link-local addresses cannot reach Internet targets. \
                         Assign a global IPv4 or IPv6 address to this interface.",
                        name
                    ));
                }
            }

            // Detect gateway addresses for this interface
            let gateway_ipv4 = detect_gateway_ipv4(name);
            let gateway_ipv6 = detect_gateway_ipv6(name);

            return Ok(InterfaceInfo {
                name: name.to_string(),
                index: iface.index,
                ipv4,
                ipv6,
                gateway_ipv4,
                gateway_ipv6,
            });
        }
    }

    // Interface not found - list available interfaces
    let available: Vec<_> = datalink::interfaces()
        .iter()
        .filter(|i| !i.ips.is_empty())
        .map(|i| i.name.clone())
        .collect();

    Err(anyhow!(
        "Interface '{}' not found. Available interfaces: {}",
        name,
        if available.is_empty() {
            "(none with IP addresses)".to_string()
        } else {
            available.join(", ")
        }
    ))
}

/// Bind a socket to a specific network interface
///
/// On Linux, uses SO_BINDTODEVICE which requires CAP_NET_RAW or root.
/// On macOS, uses IP_BOUND_IF with the interface index.
pub fn bind_socket_to_interface(socket: &Socket, info: &InterfaceInfo) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        socket.bind_device(Some(info.name.as_bytes())).map_err(|e| {
            anyhow!(
                "Failed to bind socket to interface '{}': {}. \
                 This requires CAP_NET_RAW capability or root privileges.",
                info.name,
                e
            )
        })
    }

    #[cfg(target_os = "macos")]
    {
        use std::num::NonZeroU32;
        // macOS uses interface index binding
        socket
            .bind_device_by_index_v4(NonZeroU32::new(info.index))
            .map_err(|e| {
                anyhow!(
                    "Failed to bind socket to interface '{}' (index {}): {}",
                    info.name,
                    info.index,
                    e
                )
            })
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (socket, info); // Suppress unused warnings
        Err(anyhow!(
            "Interface binding is not supported on this platform. \
             It is only available on Linux and macOS."
        ))
    }
}

/// Get the source IP address from an interface for a given IP family
///
/// Returns the first address of the requested family, or an error if none exists.
#[allow(dead_code)]
pub fn get_interface_source_ip(info: &InterfaceInfo, ipv6: bool) -> Result<IpAddr> {
    if ipv6 {
        info.ipv6.map(IpAddr::V6).ok_or_else(|| {
            anyhow!(
                "Interface '{}' has no IPv6 address. Use -4 to force IPv4.",
                info.name
            )
        })
    } else {
        info.ipv4.map(IpAddr::V4).ok_or_else(|| {
            anyhow!(
                "Interface '{}' has no IPv4 address. Use -6 to force IPv6.",
                info.name
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nonexistent_interface() {
        let result = validate_interface("nonexistent_interface_12345");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_loopback_interface() {
        let interfaces = datalink::interfaces();
        let loopback_name = match interfaces.iter().find(|iface| iface.is_loopback()) {
            Some(iface) => iface.name.clone(),
            None => {
                eprintln!("Skipping loopback interface test: no loopback interface visible.");
                return;
            }
        };

        let result = validate_interface(&loopback_name);
        assert!(result.is_ok());

        let info = result.unwrap();
        assert_eq!(info.name, loopback_name);
        assert!(info.ipv4.is_some() || info.ipv6.is_some());
    }

    #[test]
    fn test_ipv6_link_local_detection() {
        // Test the shared is_link_local_ipv6 function
        // Link-local addresses (fe80::/10) should be detected
        let link_local: Ipv6Addr = "fe80::1".parse().unwrap();
        assert!(is_link_local_ipv6(&link_local));

        let link_local_2: Ipv6Addr = "fe80::dead:beef:cafe:1234".parse().unwrap();
        assert!(is_link_local_ipv6(&link_local_2));

        // Edge of link-local range (febf::)
        let link_local_edge: Ipv6Addr = "febf::1".parse().unwrap();
        assert!(is_link_local_ipv6(&link_local_edge));

        // Global unicast (2000::/3) should NOT be link-local
        let global: Ipv6Addr = "2001:db8::1".parse().unwrap();
        assert!(!is_link_local_ipv6(&global));

        let google_dns: Ipv6Addr = "2001:4860:4860::8888".parse().unwrap();
        assert!(!is_link_local_ipv6(&google_dns));

        // Unique local (fc00::/7) should NOT be link-local
        let ula: Ipv6Addr = "fd00::1".parse().unwrap();
        assert!(!is_link_local_ipv6(&ula));

        // Loopback should NOT be link-local
        let loopback: Ipv6Addr = "::1".parse().unwrap();
        assert!(!is_link_local_ipv6(&loopback));

        // Just outside link-local range (fe7f and fec0)
        let below_range: Ipv6Addr = "fe7f::1".parse().unwrap();
        assert!(!is_link_local_ipv6(&below_range));

        let above_range: Ipv6Addr = "fec0::1".parse().unwrap();
        assert!(!is_link_local_ipv6(&above_range));
    }
}
