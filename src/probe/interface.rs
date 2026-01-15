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

/// Detect the default IPv4 gateway for an interface from the routing table
///
/// Returns None if gateway cannot be determined (command fails, no default route, etc.)
fn detect_gateway_ipv4(interface: &str) -> Option<Ipv4Addr> {
    #[cfg(target_os = "linux")]
    {
        // Parse output of: ip route show default dev <interface>
        // Format: "default via 192.168.1.1 dev eth0 ..."
        let output = std::process::Command::new("ip")
            .args(["route", "show", "default", "dev", interface])
            .output()
            .ok()?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        parse_linux_route_gateway(&stdout)
    }

    #[cfg(target_os = "macos")]
    {
        // Parse output of: route -n get default
        // Then filter by interface
        let output = std::process::Command::new("route")
            .args(["-n", "get", "default"])
            .output()
            .ok()?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        parse_macos_route_gateway(&stdout, interface)
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = interface;
        None
    }
}

/// Detect the default IPv6 gateway for an interface from the routing table
fn detect_gateway_ipv6(interface: &str) -> Option<Ipv6Addr> {
    #[cfg(target_os = "linux")]
    {
        // Parse output of: ip -6 route show default dev <interface>
        // Format: "default via fe80::1 dev eth0 ..."
        let output = std::process::Command::new("ip")
            .args(["-6", "route", "show", "default", "dev", interface])
            .output()
            .ok()?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        parse_linux_route_gateway_v6(&stdout)
    }

    #[cfg(target_os = "macos")]
    {
        // Parse output of: route -n get -inet6 default
        let output = std::process::Command::new("route")
            .args(["-n", "get", "-inet6", "default"])
            .output()
            .ok()?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        parse_macos_route_gateway_v6(&stdout, interface)
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = interface;
        None
    }
}

/// Parse Linux `ip route show` output for gateway address
/// Example: "default via 192.168.1.1 dev eth0 proto dhcp metric 100"
#[cfg(target_os = "linux")]
fn parse_linux_route_gateway(output: &str) -> Option<Ipv4Addr> {
    for line in output.lines() {
        if line.starts_with("default") {
            // Look for "via <ip>" pattern
            let parts: Vec<&str> = line.split_whitespace().collect();
            if let Some(pos) = parts.iter().position(|&p| p == "via")
                && let Some(ip_str) = parts.get(pos + 1)
            {
                return ip_str.parse().ok();
            }
        }
    }
    None
}

/// Parse Linux `ip -6 route show` output for gateway address
#[cfg(target_os = "linux")]
fn parse_linux_route_gateway_v6(output: &str) -> Option<Ipv6Addr> {
    for line in output.lines() {
        if line.starts_with("default") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if let Some(pos) = parts.iter().position(|&p| p == "via")
                && let Some(ip_str) = parts.get(pos + 1)
            {
                // IPv6 gateway might have %interface suffix, strip it
                let clean = ip_str.split('%').next().unwrap_or(ip_str);
                return clean.parse().ok();
            }
        }
    }
    None
}

/// Parse macOS `route -n get default` output for gateway address
/// Example output:
///    route to: default
/// destination: default
///        mask: default
///     gateway: 192.168.1.1
///   interface: en0
#[cfg(target_os = "macos")]
fn parse_macos_route_gateway(output: &str, expected_interface: &str) -> Option<Ipv4Addr> {
    let mut gateway: Option<Ipv4Addr> = None;
    let mut interface: Option<&str> = None;

    for line in output.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("gateway:") {
            gateway = rest.trim().parse().ok();
        } else if let Some(rest) = line.strip_prefix("interface:") {
            interface = Some(rest.trim());
        }
    }

    // Only return gateway if it's for the expected interface
    if interface == Some(expected_interface) {
        gateway
    } else {
        None
    }
}

/// Parse macOS `route -n get -inet6 default` output for IPv6 gateway
#[cfg(target_os = "macos")]
fn parse_macos_route_gateway_v6(output: &str, expected_interface: &str) -> Option<Ipv6Addr> {
    let mut gateway: Option<Ipv6Addr> = None;
    let mut interface: Option<&str> = None;

    for line in output.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("gateway:") {
            let clean = rest.trim().split('%').next().unwrap_or(rest.trim());
            gateway = clean.parse().ok();
        } else if let Some(rest) = line.strip_prefix("interface:") {
            interface = Some(rest.trim());
        }
    }

    if interface == Some(expected_interface) {
        gateway
    } else {
        None
    }
}

/// Detect default gateway without specifying an interface
///
/// Useful when no --interface flag is provided but we still want to show
/// which gateway will be used.
pub fn detect_default_gateway(ipv6: bool) -> Option<IpAddr> {
    #[cfg(target_os = "linux")]
    {
        if ipv6 {
            let output = std::process::Command::new("ip")
                .args(["-6", "route", "show", "default"])
                .output()
                .ok()?;
            let stdout = String::from_utf8_lossy(&output.stdout);
            parse_linux_route_gateway_v6(&stdout).map(IpAddr::V6)
        } else {
            let output = std::process::Command::new("ip")
                .args(["route", "show", "default"])
                .output()
                .ok()?;
            let stdout = String::from_utf8_lossy(&output.stdout);
            parse_linux_route_gateway(&stdout).map(IpAddr::V4)
        }
    }

    #[cfg(target_os = "macos")]
    {
        if ipv6 {
            let output = std::process::Command::new("route")
                .args(["-n", "get", "-inet6", "default"])
                .output()
                .ok()?;
            let stdout = String::from_utf8_lossy(&output.stdout);
            // For default gateway without interface filter, just extract gateway
            for line in stdout.lines() {
                let line = line.trim();
                if let Some(rest) = line.strip_prefix("gateway:") {
                    let clean = rest.trim().split('%').next().unwrap_or(rest.trim());
                    if let Ok(addr) = clean.parse::<Ipv6Addr>() {
                        return Some(IpAddr::V6(addr));
                    }
                }
            }
            None
        } else {
            let output = std::process::Command::new("route")
                .args(["-n", "get", "default"])
                .output()
                .ok()?;
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let line = line.trim();
                if let Some(rest) = line.strip_prefix("gateway:") {
                    if let Ok(addr) = rest.trim().parse::<Ipv4Addr>() {
                        return Some(IpAddr::V4(addr));
                    }
                }
            }
            None
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = ipv6;
        None
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

    #[test]
    #[cfg(target_os = "linux")]
    fn test_parse_linux_route_gateway_ipv4() {
        // Standard DHCP route
        let output = "default via 192.168.1.1 dev eth0 proto dhcp src 192.168.1.100 metric 100";
        assert_eq!(
            parse_linux_route_gateway(output),
            Some("192.168.1.1".parse().unwrap())
        );

        // Minimal route
        let output = "default via 10.0.0.1 dev wlan0";
        assert_eq!(
            parse_linux_route_gateway(output),
            Some("10.0.0.1".parse().unwrap())
        );

        // No default route
        let output = "192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.100";
        assert_eq!(parse_linux_route_gateway(output), None);

        // Empty output
        assert_eq!(parse_linux_route_gateway(""), None);

        // Default without via (directly connected)
        let output = "default dev ppp0 scope link";
        assert_eq!(parse_linux_route_gateway(output), None);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_parse_linux_route_gateway_ipv6() {
        // Standard IPv6 default route
        let output = "default via fe80::1 dev eth0 proto ra metric 100 pref medium";
        assert_eq!(
            parse_linux_route_gateway_v6(output),
            Some("fe80::1".parse().unwrap())
        );

        // Full link-local gateway address
        let output = "default via fe80::fe3d:73ff:fe5d:7fd2 dev eno1 proto ra metric 100";
        assert_eq!(
            parse_linux_route_gateway_v6(output),
            Some("fe80::fe3d:73ff:fe5d:7fd2".parse().unwrap())
        );

        // No default route
        let output = "2001:db8::/32 dev eth0 proto kernel metric 256";
        assert_eq!(parse_linux_route_gateway_v6(output), None);

        // Empty output
        assert_eq!(parse_linux_route_gateway_v6(""), None);
    }
}
