use clap::Parser;
use std::time::Duration;

/// Modern traceroute/mtr-style TUI with hop stats and optional ASN/geo enrichment
#[derive(Parser, Debug, Clone)]
#[command(name = "ttl")]
#[command(author, version, about, long_about = None)]
#[command(after_help = "\
EXAMPLES:
    Basic tracing:
        ttl 8.8.8.8
        ttl google.com cloudflare.com    # Multiple targets

    Protocol selection:
        ttl -p udp google.com            # UDP probes
        ttl -p tcp --port 443 host       # TCP to HTTPS

    ECMP path discovery:
        ttl --flows 4 host               # Discover load-balanced paths

    Path MTU discovery:
        ttl --pmtud 8.8.8.8              # Find max packet size

    QoS testing:
        ttl --dscp 46 host               # Test VoIP traffic class

    Export results:
        ttl -c 100 --json host > out.json

DETECTION INDICATORS:
    [NAT]  - Source port rewriting detected (affects multi-flow accuracy)
    [RL?]  - Router rate-limiting ICMP (loss may be artificial)
    [ASYM] - Asymmetric routing detected (return path differs)
    [TTL!] - TTL manipulation detected (middlebox modifying TTL)
    !      - Route flap at this hop (path instability)
    ~      - Asymmetric routing suspected at this hop
    ^      - TTL manipulation suspected at this hop

For detailed documentation: https://github.com/lance0/ttl/blob/master/docs/FEATURES.md
")]
pub struct Args {
    /// Target hosts to trace (IP address or hostname)
    #[arg(required_unless_present_any = ["completions", "replay"])]
    pub targets: Vec<String>,

    /// Number of probe rounds (0 = infinite). Each round sends probes to all TTLs.
    #[arg(short = 'c', long = "count", default_value = "0")]
    pub count: u64,

    /// Probe interval in seconds
    #[arg(short = 'i', long = "interval", default_value = "1.0")]
    pub interval: f64,

    /// Maximum TTL (hops)
    #[arg(short = 'm', long = "max-ttl", default_value = "30")]
    pub max_ttl: u8,

    /// Probe protocol (auto, icmp, udp, tcp)
    #[arg(short = 'p', long = "protocol", default_value = "auto")]
    pub protocol: String,

    /// Port for UDP/TCP probes
    #[arg(long = "port")]
    pub port: Option<u16>,

    /// Use fixed port (disable per-TTL port variation)
    #[arg(long = "fixed-port")]
    pub port_fixed: bool,

    /// Number of flows for multi-path ECMP detection (1 = classic mode)
    #[arg(long = "flows", default_value = "1")]
    pub flows: u8,

    /// Base source port for flow identification
    #[arg(long = "src-port", default_value = "50000")]
    pub src_port: u16,

    /// Probe timeout in seconds
    #[arg(long = "timeout", default_value = "3")]
    pub timeout: f64,

    /// Force IPv4
    #[arg(short = '4', long = "ipv4")]
    pub ipv4: bool,

    /// Force IPv6
    #[arg(short = '6', long = "ipv6")]
    pub ipv6: bool,

    /// Trace all resolved IP addresses for hostnames (round-robin DNS, dual-stack)
    #[arg(long = "resolve-all")]
    pub resolve_all: bool,

    /// Skip reverse DNS lookups
    #[arg(long = "no-dns")]
    pub no_dns: bool,

    /// Skip ASN enrichment
    #[arg(long = "no-asn")]
    pub no_asn: bool,

    /// Skip geolocation
    #[arg(long = "no-geo")]
    pub no_geo: bool,

    /// Skip IX detection (PeeringDB)
    #[arg(long = "no-ix")]
    pub no_ix: bool,

    /// Path to MaxMind GeoLite2 database file
    #[arg(long = "geoip-db")]
    pub geoip_db: Option<String>,

    /// Disable TUI (streaming output mode)
    #[arg(long = "no-tui")]
    pub no_tui: bool,

    /// Output JSON (batch mode, requires -c)
    #[arg(long = "json")]
    pub json: bool,

    /// Output CSV (batch mode, requires -c)
    #[arg(long = "csv")]
    pub csv: bool,

    /// Report mode (batch, requires -c)
    #[arg(long = "report")]
    pub report: bool,

    /// Replay a saved session
    #[arg(long = "replay")]
    pub replay: Option<String>,

    /// Color theme (default, kawaii, cyber, dracula, monochrome, matrix, nord, gruvbox, catppuccin, tokyo_night, solarized)
    #[arg(long = "theme", default_value = "default")]
    pub theme: String,

    /// Wide mode: expand columns for wider terminals
    #[arg(long = "wide")]
    pub wide: bool,

    /// Bind probes to specific network interface (e.g., eth0, wlan0)
    #[arg(long = "interface")]
    pub interface: Option<String>,

    /// Don't bind receiver socket to interface (allows asymmetric routing)
    #[arg(long = "recv-any", requires = "interface")]
    pub recv_any: bool,

    /// DSCP value for QoS testing (0-63)
    #[arg(long = "dscp", value_parser = clap::value_parser!(u8).range(0..=63))]
    pub dscp: Option<u8>,

    /// Probe packet size in bytes (36-1500 for IPv4, 56-1500 for IPv6)
    /// Includes IP + protocol headers. Smaller values are clamped to minimum.
    #[arg(long = "size", value_parser = clap::value_parser!(u16).range(36..=1500), conflicts_with = "pmtud")]
    pub size: Option<u16>,

    /// Enable Path MTU discovery mode (binary search for max unfragmented size)
    #[arg(long = "pmtud")]
    pub pmtud: bool,

    /// Maximum probes per second (0 = unlimited)
    #[arg(long = "rate", value_parser = clap::value_parser!(u32).range(0..=10000))]
    pub rate: Option<u32>,

    /// Source IP address for probes
    #[arg(long = "source-ip", value_name = "IP")]
    pub source_ip: Option<std::net::IpAddr>,

    /// Generate shell completions and exit
    #[arg(long, value_name = "SHELL", value_parser = ["bash", "zsh", "fish", "powershell"])]
    pub completions: Option<String>,
}

impl Args {
    /// Get probe interval as Duration
    pub fn interval_duration(&self) -> Duration {
        Duration::from_secs_f64(self.interval)
    }

    /// Get timeout as Duration
    pub fn timeout_duration(&self) -> Duration {
        Duration::from_secs_f64(self.timeout)
    }

    /// Check if running in batch mode (non-interactive)
    pub fn is_batch_mode(&self) -> bool {
        self.json || self.csv || self.report
    }

    /// Validate arguments
    pub fn validate(&self) -> Result<(), String> {
        if self.is_batch_mode() && self.count == 0 {
            return Err("Batch output modes (--json, --csv, --report) require -c to be set".into());
        }

        if self.ipv4 && self.ipv6 {
            return Err("Cannot specify both -4 and -6".into());
        }

        let protocol = self.protocol.to_lowercase();
        if !["auto", "icmp", "udp", "tcp"].contains(&protocol.as_str()) {
            return Err(format!(
                "Unknown protocol: {}. Use auto, icmp, udp, or tcp",
                self.protocol
            ));
        }

        if self.interval <= 0.0 {
            return Err("Interval must be positive".into());
        }

        if self.timeout <= 0.0 {
            return Err("Timeout must be positive".into());
        }

        if self.max_ttl == 0 {
            return Err("Max TTL must be at least 1".into());
        }

        // Upper bound to prevent resource exhaustion (255 TTLs = 255 probes/sec)
        const MAX_SAFE_TTL: u8 = 64;
        if self.max_ttl > MAX_SAFE_TTL {
            return Err(format!("Max TTL cannot exceed {}", MAX_SAFE_TTL));
        }

        // Validate flows count
        if self.flows == 0 {
            return Err("Flows must be at least 1".into());
        }
        const MAX_FLOWS: u8 = 16;
        if self.flows > MAX_FLOWS {
            return Err(format!(
                "Flows cannot exceed {} (resource limit)",
                MAX_FLOWS
            ));
        }

        // Validate src_port + (flows - 1) doesn't overflow u16
        // Ports used are src_port, src_port+1, ..., src_port+(flows-1)
        let max_port = self.src_port as u32 + (self.flows as u32 - 1);
        if max_port > u16::MAX as u32 {
            return Err(format!(
                "src_port ({}) + flows ({}) would use port {} (max 65535)",
                self.src_port, self.flows, max_port
            ));
        }

        // Validate timeout vs interval to prevent probe sequence wrap
        // ProbeId.seq is u8 (0-255), so sequence wraps every 256 intervals
        // If timeout > 256 * interval, old probes may still be pending when seq wraps
        if self.timeout > 256.0 * self.interval {
            return Err(format!(
                "Timeout ({:.1}s) cannot exceed 256 × interval ({:.1}s = {:.1}s) to prevent sequence wrap",
                self.timeout,
                self.interval,
                256.0 * self.interval
            ));
        }

        // Validate interface name
        if let Some(ref iface) = self.interface {
            if iface.is_empty() {
                return Err("Interface name cannot be empty".into());
            }
            // IFNAMSIZ on Linux is 16 including null terminator
            if iface.len() > 15 {
                return Err(format!("Interface name too long: {} (max 15 chars)", iface));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_args(overrides: impl FnOnce(&mut Args)) -> Args {
        let mut args = Args {
            targets: vec!["8.8.8.8".to_string()],
            count: 0,
            interval: 1.0,
            max_ttl: 30,
            protocol: "auto".to_string(),
            port: None,
            port_fixed: false,
            flows: 1,
            src_port: 50000,
            timeout: 3.0,
            ipv4: false,
            ipv6: false,
            resolve_all: false,
            no_dns: false,
            no_asn: false,
            no_geo: false,
            no_ix: false,
            geoip_db: None,
            no_tui: false,
            json: false,
            csv: false,
            report: false,
            replay: None,
            theme: "default".to_string(),
            wide: false,
            interface: None,
            recv_any: false,
            dscp: None,
            size: None,
            pmtud: false,
            rate: None,
            source_ip: None,
            completions: None,
        };
        overrides(&mut args);
        args
    }

    #[test]
    fn test_src_port_flows_valid_at_max() {
        // src_port=65520, flows=16 uses ports 65520..65535 (valid)
        let args = make_args(|a| {
            a.src_port = 65520;
            a.flows = 16;
        });
        assert!(args.validate().is_ok());
    }

    #[test]
    fn test_src_port_flows_overflow() {
        // src_port=65521, flows=16 would use port 65536 (invalid)
        let args = make_args(|a| {
            a.src_port = 65521;
            a.flows = 16;
        });
        let err = args.validate().unwrap_err();
        assert!(err.contains("65536"));
    }

    #[test]
    fn test_timeout_interval_valid() {
        // timeout=256s with interval=1s is exactly at the limit
        let args = make_args(|a| {
            a.timeout = 256.0;
            a.interval = 1.0;
        });
        assert!(args.validate().is_ok());
    }

    #[test]
    fn test_timeout_interval_wrap_rejected() {
        // timeout=257s with interval=1s exceeds 256 × interval
        let args = make_args(|a| {
            a.timeout = 257.0;
            a.interval = 1.0;
        });
        let err = args.validate().unwrap_err();
        assert!(err.contains("sequence wrap"));
    }

    #[test]
    fn test_timeout_interval_fast_probes() {
        // With 0.1s interval, timeout must be <= 25.6s
        let args = make_args(|a| {
            a.timeout = 30.0;
            a.interval = 0.1;
        });
        let err = args.validate().unwrap_err();
        assert!(err.contains("sequence wrap"));
    }
}
