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
        ttl                              # Empty session; press 'o' to add targets

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

    Stream and compare:
        ttl --stream-json host | jq .   # Line-delimited JSON events
        ttl --diff before.json after.json

    Continuous monitoring:
        ttl --daemon --prometheus :9090 host   # Headless + metrics endpoint

DETECTION INDICATORS:
    [NAT]  - Source port rewriting detected (affects multi-flow accuracy)
    [RL?]  - Router rate-limiting ICMP (loss may be artificial)
    [ASYM] - Asymmetric routing detected (return path differs)
    [TTL!] - TTL manipulation detected (middlebox modifying TTL)
    E      - ECMP detected at this hop (single-flow marker; see Paths in multi-flow)
    !      - Route flap at this hop (path instability, when ECMP not indicated)
    ~      - Asymmetric routing suspected at this hop
    ^      - TTL manipulation suspected at this hop

For detailed documentation: https://github.com/lance0/ttl/blob/master/docs/FEATURES.md
")]
pub struct Args {
    /// Target hosts to trace (IP address or hostname).
    /// With no targets, opens an interactive empty session (press 'o' to add).
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

    /// Animate replay showing probe-by-probe discovery
    #[arg(long = "animate", requires = "replay")]
    pub animate: bool,

    /// Replay speed multiplier (1.0 = realtime, 10.0 = 10x faster)
    #[arg(long = "speed", default_value = "10.0", requires = "animate")]
    pub speed: f32,

    /// Compare two saved sessions: show added/removed hops, path and latency changes
    #[arg(long = "diff", num_args = 2, value_names = ["BEFORE", "AFTER"], conflicts_with_all = ["targets", "replay"])]
    pub diff: Option<Vec<String>>,

    /// Stream probe events as line-delimited JSON to stdout (implies --no-tui)
    #[arg(long = "stream-json", conflicts_with_all = ["json", "csv", "report", "replay", "diff"])]
    pub stream_json: bool,

    /// Daemon mode: headless, no per-hop output (combine with --prometheus or --stream-json)
    #[arg(long = "daemon", conflicts_with_all = ["json", "csv", "report", "replay", "diff"])]
    pub daemon: bool,

    /// Serve Prometheus/OpenMetrics on this address (e.g. :9090 or 127.0.0.1:9090; implies --no-tui)
    #[arg(long = "prometheus", value_name = "ADDR", conflicts_with_all = ["json", "csv", "report", "replay", "diff"])]
    pub prometheus: Option<String>,

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

    /// Probe packet size in bytes (36-9216 for IPv4, 56-9216 for IPv6)
    /// Includes IP + protocol headers. Smaller values are clamped to minimum.
    /// Supports jumbo frames up to 9216 bytes.
    #[arg(long = "size", value_parser = clap::value_parser!(u16).range(36..=9216), conflicts_with = "pmtud")]
    pub size: Option<u16>,

    /// Enable Path MTU discovery mode (binary search for max unfragmented size)
    #[arg(long = "pmtud")]
    pub pmtud: bool,

    /// Enable jumbo frame detection (9216 byte max) for PMTUD
    /// Without this flag, PMTUD uses standard ethernet max (1500 bytes)
    #[arg(long = "jumbo", requires = "pmtud")]
    pub jumbo: bool,

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

    fn validate_duration_arg(name: &str, value: f64) -> Result<(), String> {
        if !value.is_finite() || value <= 0.0 {
            return Err(format!("{name} must be a positive, finite number"));
        }
        Duration::try_from_secs_f64(value)
            .map(|_| ())
            .map_err(|_| format!("{name} is too large to represent as a duration"))
    }

    fn default_destination_port(protocol: &str) -> u16 {
        if protocol == "tcp" { 80 } else { 33434 }
    }

    /// Check if running in batch mode (non-interactive)
    pub fn is_batch_mode(&self) -> bool {
        self.json || self.csv || self.report
    }

    /// Check if running headless (no TUI)
    pub fn is_headless(&self) -> bool {
        self.no_tui || self.stream_json || self.daemon || self.prometheus.is_some()
    }

    /// Parse the --prometheus listen address; ":9090" binds all interfaces
    pub fn prometheus_addr(&self) -> Option<std::net::SocketAddr> {
        let addr = self.prometheus.as_deref()?;
        let full = if addr.starts_with(':') {
            format!("0.0.0.0{}", addr)
        } else {
            addr.to_string()
        };
        full.parse().ok()
    }

    /// Validate arguments
    pub fn validate(&self) -> Result<(), String> {
        // Interactive TUI mode supports starting empty (add targets with 'o');
        // every other mode needs at least one target up front
        if self.targets.is_empty() && (self.is_batch_mode() || self.is_headless()) {
            return Err("No targets specified (required for non-interactive modes)".into());
        }

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

        Self::validate_duration_arg("Interval", self.interval)?;
        Self::validate_duration_arg("Timeout", self.timeout)?;

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
                "src_port ({}) + flows - 1 ({}) would use port {} (max 65535)",
                self.src_port,
                self.flows - 1,
                max_port
            ));
        }
        // Validate destination port + max_ttl doesn't overflow u16 (UDP/TCP modes)
        // The engine sends probes to ports base_port..base_port+max_ttl (unless --fixed-port)
        let uses_port = matches!(protocol.as_str(), "udp" | "tcp")
            || (protocol == "auto" && self.port.is_some());
        if uses_port && !self.port_fixed {
            let default_port = Self::default_destination_port(&protocol);
            let base = self.port.unwrap_or(default_port) as u32;
            let max_dst_port = base + self.max_ttl as u32;
            if max_dst_port > u16::MAX as u32 {
                return Err(format!(
                    "port ({}) + max-ttl ({}) would use port {} (max 65535); use --fixed-port or lower --port",
                    base, self.max_ttl, max_dst_port
                ));
            }
        }

        // Validate timeout vs interval to prevent probe sequence wrap
        // ProbeId.seq is u8 (0-255), so sequence wraps every 256 intervals.
        // Use >= so the exact boundary is also rejected — at timeout == 256 * interval
        // the oldest probes expire at the precise moment the sequence wraps, risking collision.
        if self.timeout >= 256.0 * self.interval {
            return Err(format!(
                "Timeout ({:.1}s) must be less than 256 × interval ({:.1}s = {:.1}s) to prevent sequence wrap",
                self.timeout,
                self.interval,
                256.0 * self.interval
            ));
        }

        // Validate replay speed
        if self.speed < 0.1 || self.speed > 1000.0 {
            return Err("Replay speed must be between 0.1 and 1000.0".into());
        }

        // Validate prometheus listen address early (":9090" means all interfaces)
        if let Some(addr) = &self.prometheus
            && self.prometheus_addr().is_none()
        {
            return Err(format!(
                "Invalid --prometheus address: {addr} (use :9090 or 127.0.0.1:9090)"
            ));
        }

        // Validate interface name
        if let Some(iface) = &self.interface {
            if iface.is_empty() {
                return Err("Interface name cannot be empty".into());
            }
            // IFNAMSIZ on Linux is 16 including null terminator
            if iface.len() > 15 {
                return Err(format!("Interface name too long: {iface} (max 15 chars)"));
            }
            // Interface binding is not supported on FreeBSD/NetBSD (no SO_BINDTODEVICE / IP_BOUND_IF).
            // Reject early rather than failing on every probe send at runtime.
            #[cfg(any(target_os = "freebsd", target_os = "netbsd"))]
            {
                return Err("Interface binding (-i) is not supported on this platform. \
                     Use --source-ip or run on Linux/macOS for interface binding."
                    .to_string());
            }
            #[cfg(not(any(target_os = "freebsd", target_os = "netbsd")))]
            {
                let _ = iface; // validated above; binding checked later
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
            animate: false,
            speed: 10.0,
            diff: None,
            stream_json: false,
            daemon: false,
            prometheus: None,
            theme: "default".to_string(),
            wide: false,
            interface: None,
            recv_any: false,
            dscp: None,
            size: None,
            pmtud: false,
            jumbo: false,
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
    fn test_nan_interval_rejected() {
        let args = make_args(|a| {
            a.interval = f64::NAN;
        });
        assert!(args.validate().unwrap_err().contains("positive, finite"));
    }

    #[test]
    fn test_inf_timeout_rejected() {
        let args = make_args(|a| {
            a.timeout = f64::INFINITY;
        });
        assert!(args.validate().unwrap_err().contains("positive, finite"));
    }

    #[test]
    fn test_huge_interval_rejected() {
        let args = make_args(|a| {
            a.interval = 1e300;
        });
        assert!(args.validate().unwrap_err().contains("too large"));
    }

    #[test]
    fn test_huge_timeout_rejected() {
        let args = make_args(|a| {
            a.timeout = 1e300;
        });
        assert!(args.validate().unwrap_err().contains("too large"));
    }

    #[test]
    fn test_port_max_ttl_overflow_rejected() {
        // port=65530, max_ttl=30 → max port 65560 (overflows u16) unless --fixed-port
        let args = make_args(|a| {
            a.protocol = "udp".to_string();
            a.port = Some(65530);
            a.max_ttl = 30;
        });
        assert!(args.validate().unwrap_err().contains("max 65535"));
    }

    #[test]
    fn test_port_max_ttl_valid_at_boundary() {
        // port=65505, max_ttl=30 → max port 65535 (valid)
        let args = make_args(|a| {
            a.protocol = "udp".to_string();
            a.port = Some(65505);
            a.max_ttl = 30;
        });
        assert!(args.validate().is_ok());
    }

    #[test]
    fn test_default_destination_port_matches_protocol_defaults() {
        assert_eq!(Args::default_destination_port("tcp"), 80);
        assert_eq!(Args::default_destination_port("udp"), 33434);
        assert_eq!(Args::default_destination_port("auto"), 33434);
    }

    #[test]
    fn test_port_max_ttl_fixed_port_skips_check() {
        // With --fixed-port, the per-TTL port variation is disabled
        let args = make_args(|a| {
            a.protocol = "udp".to_string();
            a.port = Some(65530);
            a.max_ttl = 30;
            a.port_fixed = true;
        });
        assert!(args.validate().is_ok());
    }

    #[test]
    fn test_timeout_interval_valid() {
        // timeout=255s with interval=1s is just under the limit (must be < 256 × interval)
        let args = make_args(|a| {
            a.timeout = 255.0;
            a.interval = 1.0;
        });
        assert!(args.validate().is_ok());
    }

    #[test]
    fn test_timeout_interval_boundary_rejected() {
        // timeout=256s with interval=1s is exactly at the limit — now rejected
        let args = make_args(|a| {
            a.timeout = 256.0;
            a.interval = 1.0;
        });
        assert!(args.validate().unwrap_err().contains("sequence wrap"));
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

    #[test]
    fn test_diff_parses_two_files_without_targets() {
        let args = Args::try_parse_from(["ttl", "--diff", "before.json", "after.json"]).unwrap();
        assert_eq!(
            args.diff,
            Some(vec!["before.json".to_string(), "after.json".to_string()])
        );
        assert!(args.targets.is_empty());
    }

    #[test]
    fn test_diff_requires_exactly_two_files() {
        assert!(Args::try_parse_from(["ttl", "--diff", "only-one.json"]).is_err());
    }

    #[test]
    fn test_diff_conflicts_with_targets() {
        assert!(Args::try_parse_from(["ttl", "--diff", "a.json", "b.json", "8.8.8.8"]).is_err());
    }

    #[test]
    fn test_stream_json_parses_with_target() {
        let args = Args::try_parse_from(["ttl", "--stream-json", "8.8.8.8"]).unwrap();
        assert!(args.stream_json);
    }

    #[test]
    fn test_stream_json_conflicts_with_batch_output() {
        assert!(Args::try_parse_from(["ttl", "--stream-json", "--json", "8.8.8.8"]).is_err());
        assert!(Args::try_parse_from(["ttl", "--stream-json", "--csv", "8.8.8.8"]).is_err());
        assert!(Args::try_parse_from(["ttl", "--stream-json", "--report", "8.8.8.8"]).is_err());
    }

    #[test]
    fn test_empty_targets_interactive_ok() {
        let args = make_args(|a| a.targets = vec![]);
        assert!(args.validate().is_ok());
    }

    #[test]
    fn test_empty_targets_rejected_for_non_interactive_modes() {
        let no_tui = make_args(|a| {
            a.targets = vec![];
            a.no_tui = true;
        });
        assert!(no_tui.validate().unwrap_err().contains("No targets"));

        let batch = make_args(|a| {
            a.targets = vec![];
            a.json = true;
            a.count = 5;
        });
        assert!(batch.validate().is_err());

        let daemon = make_args(|a| {
            a.targets = vec![];
            a.daemon = true;
        });
        assert!(daemon.validate().is_err());

        let stream = make_args(|a| {
            a.targets = vec![];
            a.stream_json = true;
        });
        assert!(stream.validate().is_err());

        let prom = make_args(|a| {
            a.targets = vec![];
            a.prometheus = Some(":9090".to_string());
        });
        assert!(prom.validate().is_err());
    }

    #[test]
    fn test_prometheus_addr_shorthand() {
        let args = make_args(|a| a.prometheus = Some(":9090".to_string()));
        assert_eq!(
            args.prometheus_addr(),
            Some("0.0.0.0:9090".parse().unwrap())
        );
        assert!(args.validate().is_ok());
        assert!(args.is_headless());
    }

    #[test]
    fn test_prometheus_addr_full() {
        let args = make_args(|a| a.prometheus = Some("127.0.0.1:9100".to_string()));
        assert_eq!(
            args.prometheus_addr(),
            Some("127.0.0.1:9100".parse().unwrap())
        );
    }

    #[test]
    fn test_prometheus_addr_invalid() {
        let args = make_args(|a| a.prometheus = Some("not-an-addr".to_string()));
        assert!(args.prometheus_addr().is_none());
        assert!(args.validate().unwrap_err().contains("--prometheus"));
    }

    #[test]
    fn test_daemon_conflicts_with_batch_output() {
        assert!(Args::try_parse_from(["ttl", "--daemon", "--json", "8.8.8.8"]).is_err());
        assert!(Args::try_parse_from(["ttl", "--daemon", "--replay", "x.json"]).is_err());
    }

    #[test]
    fn test_daemon_composes_with_stream_json_and_prometheus() {
        let args = Args::try_parse_from([
            "ttl",
            "--daemon",
            "--stream-json",
            "--prometheus",
            ":9090",
            "8.8.8.8",
        ])
        .unwrap();
        assert!(args.daemon && args.stream_json);
        assert!(args.is_headless());
    }
}
