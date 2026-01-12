use clap::Parser;
use std::time::Duration;

/// Modern traceroute/mtr-style TUI with hop stats and optional ASN/geo enrichment
#[derive(Parser, Debug, Clone)]
#[command(name = "ttl")]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// Target hosts to trace (IP address or hostname)
    #[arg(required = true)]
    pub targets: Vec<String>,

    /// Number of probes to send (0 = infinite)
    #[arg(short = 'c', long = "count", default_value = "0")]
    pub count: u64,

    /// Probe interval in seconds
    #[arg(short = 'i', long = "interval", default_value = "1.0")]
    pub interval: f64,

    /// Maximum TTL (hops)
    #[arg(short = 'm', long = "max-ttl", default_value = "30")]
    pub max_ttl: u8,

    /// Probe protocol
    #[arg(short = 'p', long = "protocol", default_value = "icmp")]
    pub protocol: String,

    /// Port for UDP/TCP probes
    #[arg(long = "port")]
    pub port: Option<u16>,

    /// Probe timeout in seconds
    #[arg(long = "timeout", default_value = "3")]
    pub timeout: f64,

    /// Force IPv4
    #[arg(short = '4', long = "ipv4")]
    pub ipv4: bool,

    /// Force IPv6
    #[arg(short = '6', long = "ipv6")]
    pub ipv6: bool,

    /// Skip reverse DNS lookups
    #[arg(long = "no-dns")]
    pub no_dns: bool,

    /// Skip ASN enrichment
    #[arg(long = "no-asn")]
    pub no_asn: bool,

    /// Skip geolocation
    #[arg(long = "no-geo")]
    pub no_geo: bool,

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
        if !["icmp", "udp", "tcp"].contains(&protocol.as_str()) {
            return Err(format!("Unknown protocol: {}. Use icmp, udp, or tcp", self.protocol));
        }

        if protocol != "icmp" {
            return Err(format!("Protocol '{}' not yet implemented. Only ICMP is supported in MVP.", protocol));
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
            return Err(format!("Max TTL cannot exceed {}", MAX_SAFE_TTL).into());
        }

        Ok(())
    }
}
