use crate::cli::Args;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::time::Duration;

/// Probe protocol type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum ProbeProtocol {
    /// Auto-detect: try ICMP, fallback to UDP, then TCP
    #[default]
    Auto,
    Icmp,
    Udp,
    Tcp,
}

/// Runtime configuration derived from CLI args
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Number of probes to send (None = infinite)
    pub count: Option<u64>,
    /// Interval between probes
    #[serde(with = "duration_serde")]
    pub interval: Duration,
    /// Maximum TTL
    pub max_ttl: u8,
    /// Probe timeout
    #[serde(with = "duration_serde")]
    pub timeout: Duration,
    /// Probe protocol
    pub protocol: ProbeProtocol,
    /// Port for UDP/TCP probes
    pub port: Option<u16>,
    /// Use fixed port (disable per-TTL variation)
    pub port_fixed: bool,
    /// Number of flows for multi-path ECMP detection
    #[serde(default = "default_flows")]
    pub flows: u8,
    /// Base source port for flow identification
    #[serde(default = "default_src_port")]
    pub src_port_base: u16,
    /// Enable reverse DNS lookups
    pub dns_enabled: bool,
    /// Enable ASN enrichment
    pub asn_enabled: bool,
    /// Enable geolocation
    pub geo_enabled: bool,
    /// Enable IX detection (PeeringDB)
    pub ix_enabled: bool,
    /// Network interface to bind sockets to
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
    /// Don't bind receiver to interface (for asymmetric routing)
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub recv_any: bool,
    /// DSCP value for QoS testing (0-63)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dscp: Option<u8>,
    /// Probe packet size in bytes (includes IP+ICMP headers)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub packet_size: Option<u16>,
    /// Enable Path MTU discovery mode
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub pmtud: bool,
    /// Enable jumbo frame detection for PMTUD
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub jumbo: bool,
    /// Maximum probes per second (None = unlimited)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate: Option<u32>,
    /// Source IP address for probes
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_ip: Option<IpAddr>,
}

fn default_flows() -> u8 {
    1
}
fn default_src_port() -> u16 {
    50000
}

impl Default for Config {
    fn default() -> Self {
        Self {
            count: None,
            interval: Duration::from_secs(1),
            max_ttl: 30,
            timeout: Duration::from_secs(3),
            protocol: ProbeProtocol::Icmp,
            port: None,
            port_fixed: false,
            flows: 1,
            src_port_base: 50000,
            dns_enabled: true,
            asn_enabled: true,
            geo_enabled: true,
            ix_enabled: true,
            interface: None,
            recv_any: false,
            dscp: None,
            packet_size: None,
            pmtud: false,
            jumbo: false,
            rate: None,
            source_ip: None,
        }
    }
}

impl From<&Args> for Config {
    fn from(args: &Args) -> Self {
        let protocol = match args.protocol.to_lowercase().as_str() {
            "icmp" => ProbeProtocol::Icmp,
            "udp" => ProbeProtocol::Udp,
            "tcp" => ProbeProtocol::Tcp,
            _ => ProbeProtocol::Auto,
        };

        let port = args.port.or(match protocol {
            ProbeProtocol::Auto => None, // Determined at runtime based on detected protocol
            ProbeProtocol::Udp => Some(33434),
            ProbeProtocol::Tcp => Some(80),
            ProbeProtocol::Icmp => None,
        });

        Self {
            count: if args.count == 0 {
                None
            } else {
                Some(args.count)
            },
            interval: args.interval_duration(),
            max_ttl: args.max_ttl,
            timeout: args.timeout_duration(),
            protocol,
            port,
            port_fixed: args.port_fixed,
            flows: args.flows,
            src_port_base: args.src_port,
            dns_enabled: !args.no_dns,
            asn_enabled: !args.no_asn,
            geo_enabled: !args.no_geo,
            ix_enabled: !args.no_ix,
            interface: args.interface.clone(),
            recv_any: args.recv_any,
            dscp: args.dscp,
            packet_size: args.size,
            pmtud: args.pmtud,
            jumbo: args.jumbo,
            rate: args.rate,
            source_ip: args.source_ip,
        }
    }
}

/// Serde helper for Duration
mod duration_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::time::Duration;

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        duration.as_secs_f64().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let secs = f64::deserialize(deserializer)?;
        Ok(Duration::from_secs_f64(secs))
    }
}
