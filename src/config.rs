use std::time::Duration;
use serde::{Deserialize, Serialize};
use crate::cli::Args;

/// Probe protocol type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum ProbeProtocol {
    #[default]
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
    /// Enable reverse DNS lookups
    pub dns_enabled: bool,
    /// Enable ASN enrichment
    pub asn_enabled: bool,
    /// Enable geolocation
    pub geo_enabled: bool,
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
            dns_enabled: true,
            asn_enabled: true,
            geo_enabled: true,
        }
    }
}

impl From<&Args> for Config {
    fn from(args: &Args) -> Self {
        let protocol = match args.protocol.to_lowercase().as_str() {
            "udp" => ProbeProtocol::Udp,
            "tcp" => ProbeProtocol::Tcp,
            _ => ProbeProtocol::Icmp,
        };

        let port = args.port.or(match protocol {
            ProbeProtocol::Udp => Some(33434),
            ProbeProtocol::Tcp => Some(80),
            ProbeProtocol::Icmp => None,
        });

        Self {
            count: if args.count == 0 { None } else { Some(args.count) },
            interval: args.interval_duration(),
            max_ttl: args.max_ttl,
            timeout: args.timeout_duration(),
            protocol,
            port,
            dns_enabled: !args.no_dns,
            asn_enabled: !args.no_asn,
            geo_enabled: !args.no_geo,
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
