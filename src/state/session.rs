use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::time::Duration;

use crate::config::Config;

/// Identifies a specific probe for correlation
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub struct ProbeId {
    pub ttl: u8,
    pub seq: u8,
}

impl ProbeId {
    pub fn new(ttl: u8, seq: u8) -> Self {
        Self { ttl, seq }
    }

    /// Encode TTL and sequence into a 16-bit value for ICMP sequence field
    pub fn to_sequence(self) -> u16 {
        ((self.ttl as u16) << 8) | (self.seq as u16)
    }

    /// Decode from a 16-bit ICMP sequence field
    pub fn from_sequence(seq: u16) -> Self {
        Self {
            ttl: (seq >> 8) as u8,
            seq: (seq & 0xFF) as u8,
        }
    }
}

/// ICMP response type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IcmpResponseType {
    EchoReply,
    TimeExceeded,
    DestUnreachable(u8),
    /// ICMPv6 Type 2 - Packet Too Big (for PMTUD)
    PacketTooBig,
}

/// MPLS label from ICMP extension (RFC 4950)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MplsLabel {
    /// Label value (20 bits, 0-1048575)
    pub label: u32,
    /// Traffic Class / Experimental bits (3 bits, 0-7)
    pub exp: u8,
    /// Bottom of stack flag
    pub bottom: bool,
    /// TTL value (8 bits)
    pub ttl: u8,
}

impl MplsLabel {
    /// Parse a 4-byte MPLS label entry
    pub fn from_bytes(data: &[u8; 4]) -> Self {
        // MPLS label format (32 bits):
        // [Label (20 bits)][Exp (3 bits)][S (1 bit)][TTL (8 bits)]
        let word = u32::from_be_bytes(*data);
        Self {
            label: word >> 12,
            exp: ((word >> 9) & 0x7) as u8,
            bottom: ((word >> 8) & 0x1) == 1,
            ttl: (word & 0xFF) as u8,
        }
    }
}

/// Result of a single probe
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct ProbeResult {
    pub id: ProbeId,
    pub rtt: Option<Duration>,
    pub responder: Option<IpAddr>,
    pub icmp_type: Option<IcmpResponseType>,
}

/// ASN information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsnInfo {
    pub number: u32,
    pub name: String,
    pub prefix: Option<String>,
}

/// Geolocation information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoInfo {
    pub city: Option<String>,
    pub region: Option<String>,
    pub country: String,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
}

/// Internet Exchange information (from PeeringDB)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IxInfo {
    /// IX name (e.g., "DE-CIX Frankfurt", "Equinix Ashburn")
    pub name: String,
    /// City where the IX is located
    pub city: Option<String>,
    /// Country code
    pub country: Option<String>,
}

/// Stats for a single responder at a given TTL
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponderStats {
    pub ip: IpAddr,
    pub hostname: Option<String>,
    pub asn: Option<AsnInfo>,
    pub geo: Option<GeoInfo>,
    /// Internet Exchange info (from PeeringDB)
    pub ix: Option<IxInfo>,

    /// MPLS labels from ICMP extensions (RFC 4950)
    pub mpls_labels: Option<Vec<MplsLabel>>,

    // Counters
    pub sent: u64,
    pub received: u64,

    // Latency stats (Welford's online algorithm)
    #[serde(with = "duration_serde")]
    pub min_rtt: Duration,
    #[serde(with = "duration_serde")]
    pub max_rtt: Duration,
    pub mean_rtt: f64, // microseconds
    pub m2: f64,       // for stddev calculation

    // Jitter (RFC 3550)
    pub jitter: f64,     // microseconds (smoothed)
    pub jitter_avg: f64, // microseconds (running average)
    pub jitter_max: f64, // microseconds (maximum observed)
    #[serde(skip)]
    pub last_rtt: Option<Duration>,

    // Rolling window for sparkline
    #[serde(skip)]
    pub recent: VecDeque<Option<Duration>>,

    // Sample history for percentile calculations
    #[serde(skip)]
    pub samples: VecDeque<Duration>,
}

impl ResponderStats {
    pub fn new(ip: IpAddr) -> Self {
        Self {
            ip,
            hostname: None,
            asn: None,
            geo: None,
            ix: None,
            mpls_labels: None,
            sent: 0,
            received: 0,
            min_rtt: Duration::MAX,
            max_rtt: Duration::ZERO,
            mean_rtt: 0.0,
            m2: 0.0,
            jitter: 0.0,
            jitter_avg: 0.0,
            jitter_max: 0.0,
            last_rtt: None,
            recent: VecDeque::with_capacity(60),
            samples: VecDeque::with_capacity(256),
        }
    }

    /// Maximum samples to keep for percentile calculations
    const MAX_SAMPLES: usize = 256;

    /// Update stats with a new RTT sample
    pub fn record_response(&mut self, rtt: Duration) {
        self.received += 1;

        let rtt_micros = rtt.as_micros() as f64;

        // Update min/max
        if rtt < self.min_rtt {
            self.min_rtt = rtt;
        }
        if rtt > self.max_rtt {
            self.max_rtt = rtt;
        }

        // Welford's online algorithm for mean and variance
        let delta = rtt_micros - self.mean_rtt;
        self.mean_rtt += delta / self.received as f64;
        let delta2 = rtt_micros - self.mean_rtt;
        self.m2 += delta * delta2;

        // Jitter calculation uses RFC 3550-inspired smoothed variance:
        //
        // What we measure: RTT variance (|RTT_n - RTT_n-1|), the absolute difference
        // between consecutive round-trip times. This is NOT inter-packet arrival
        // jitter (which would measure timing between received packets).
        //
        // Three metrics tracked:
        // - jitter (smoothed): EWMA with 1/16 factor per RFC 3550
        //   Formula: jitter += (|RTT_diff| - jitter) / 16
        //   Smooths out spikes while tracking trends
        //
        // - jitter_avg: Running mean of all jitter observations (Welford-style)
        //   Shows overall average RTT variance across session
        //
        // - jitter_max: Largest single RTT change observed
        //   Captures worst-case latency spike
        //
        // Interpretation: High jitter indicates network path instability from
        // congestion, route changes, bufferbloat, or load balancing. Stable
        // paths typically show jitter < 5-10% of average RTT.
        if let Some(last) = self.last_rtt {
            let diff = (rtt_micros - last.as_micros() as f64).abs();
            // Smoothed jitter (RFC 3550)
            self.jitter += (diff - self.jitter) / 16.0;
            // Maximum jitter
            if diff > self.jitter_max {
                self.jitter_max = diff;
            }
            // Average jitter (running mean using Welford-style update)
            // Note: jitter samples start at received=2, so use (received-1) for count
            let jitter_count = (self.received - 1) as f64;
            self.jitter_avg += (diff - self.jitter_avg) / jitter_count;
        }
        self.last_rtt = Some(rtt);

        // Rolling window for sparkline
        self.recent.push_back(Some(rtt));
        if self.recent.len() > 60 {
            self.recent.pop_front();
        }

        // Sample history for percentiles
        self.samples.push_back(rtt);
        if self.samples.len() > Self::MAX_SAMPLES {
            self.samples.pop_front();
        }
    }

    /// Record a timeout (no response) - updates sparkline only
    #[allow(dead_code)]
    pub fn record_timeout(&mut self) {
        self.recent.push_back(None);
        if self.recent.len() > 60 {
            self.recent.pop_front();
        }
    }

    /// Loss percentage
    pub fn loss_pct(&self) -> f64 {
        if self.sent == 0 {
            0.0
        } else {
            (1.0 - (self.received as f64 / self.sent as f64)) * 100.0
        }
    }

    /// Average RTT
    pub fn avg_rtt(&self) -> Duration {
        Duration::from_micros(self.mean_rtt as u64)
    }

    /// Standard deviation
    pub fn stddev(&self) -> Duration {
        if self.received < 2 {
            return Duration::ZERO;
        }
        let variance = self.m2 / self.received as f64;
        Duration::from_micros(variance.sqrt() as u64)
    }

    /// Smoothed jitter (RFC 3550)
    pub fn jitter(&self) -> Duration {
        Duration::from_micros(self.jitter as u64)
    }

    /// Average jitter
    pub fn jitter_avg(&self) -> Duration {
        Duration::from_micros(self.jitter_avg as u64)
    }

    /// Maximum jitter
    pub fn jitter_max(&self) -> Duration {
        Duration::from_micros(self.jitter_max as u64)
    }

    /// Last observed RTT
    pub fn last_rtt(&self) -> Option<Duration> {
        self.last_rtt
    }

    /// Calculate a percentile from sample history
    /// p should be in range 0.0-100.0
    pub fn percentile(&self, p: f64) -> Option<Duration> {
        if self.samples.is_empty() {
            return None;
        }
        let mut sorted: Vec<_> = self.samples.iter().copied().collect();
        sorted.sort();
        let idx = ((p / 100.0) * (sorted.len() - 1) as f64).round() as usize;
        Some(sorted[idx.min(sorted.len() - 1)])
    }

    /// 50th percentile (median)
    pub fn p50(&self) -> Option<Duration> {
        self.percentile(50.0)
    }

    /// 95th percentile
    pub fn p95(&self) -> Option<Duration> {
        self.percentile(95.0)
    }

    /// 99th percentile
    pub fn p99(&self) -> Option<Duration> {
        self.percentile(99.0)
    }
}

/// Per-flow path statistics at a hop (for Paris/Dublin traceroute ECMP detection)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FlowPathStats {
    /// Probes sent on this flow
    pub sent: u64,
    /// Responses received on this flow
    pub received: u64,
    /// Timed-out probes on this flow
    #[serde(default)]
    pub timeouts: u64,
    /// Primary responder seen on this flow (most common)
    pub primary_responder: Option<IpAddr>,
    /// Count of responses per responder IP on this flow
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub responder_counts: HashMap<IpAddr, u64>,
}

impl FlowPathStats {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a probe was sent on this flow
    pub fn record_sent(&mut self) {
        self.sent += 1;
    }

    /// Record a response from a responder on this flow
    pub fn record_response(&mut self, responder: IpAddr) {
        self.received += 1;
        let count = self.responder_counts.entry(responder).or_insert(0);
        *count += 1;

        // Update primary responder (most frequent)
        self.primary_responder = self
            .responder_counts
            .iter()
            .max_by_key(|(_, c)| *c)
            .map(|(ip, _)| *ip);
    }

    /// Record a timeout on this flow
    pub fn record_timeout(&mut self) {
        self.timeouts += 1;
    }

    /// Loss percentage for this flow (based on completed probes only)
    #[allow(dead_code)]
    pub fn loss_pct(&self) -> f64 {
        let completed = self.received + self.timeouts;
        if completed == 0 {
            0.0
        } else {
            (self.timeouts as f64 / completed as f64) * 100.0
        }
    }
}

/// NAT detection information for a hop
///
/// Tracks source port matches and rewrites to detect NAT devices.
/// When NAT rewrites source ports, multi-flow ECMP detection may be affected.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NatInfo {
    /// Number of probes where source port matched (no NAT)
    pub port_matched: u64,
    /// Number of probes where source port was rewritten (NAT detected)
    pub port_rewritten: u64,
    /// Sample of rewritten ports: (original, returned) - limited to MAX_SAMPLES
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rewrite_samples: Vec<(u16, u16)>,
}

impl NatInfo {
    /// Maximum number of rewrite samples to store
    const MAX_SAMPLES: usize = 10;

    /// Record a port match (no NAT)
    pub fn record_match(&mut self) {
        self.port_matched += 1;
    }

    /// Record a port rewrite (NAT detected)
    pub fn record_rewrite(&mut self, original: u16, returned: u16) {
        self.port_rewritten += 1;
        if self.rewrite_samples.len() < Self::MAX_SAMPLES {
            self.rewrite_samples.push((original, returned));
        }
    }

    /// True if NAT is detected (any port rewrite observed)
    pub fn has_nat(&self) -> bool {
        self.port_rewritten > 0
    }

    /// NAT detection confidence (percentage of probes with rewritten ports)
    pub fn nat_percentage(&self) -> f64 {
        let total = self.port_matched + self.port_rewritten;
        if total == 0 {
            0.0
        } else {
            (self.port_rewritten as f64 / total as f64) * 100.0
        }
    }

    /// Total number of NAT checks performed
    pub fn total_checks(&self) -> u64 {
        self.port_matched + self.port_rewritten
    }
}

/// A detected route change (flap) at a hop
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteChange {
    /// Previous primary responder IP
    pub from_ip: IpAddr,
    /// New primary responder IP
    pub to_ip: IpAddr,
    /// Response count when change was detected
    pub at_seq: u64,
}

/// Rate limit detection info for a hop
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RateLimitInfo {
    /// Whether rate limiting is suspected
    pub suspected: bool,
    /// Confidence level (0.0 - 1.0)
    pub confidence: f64,
    /// Detection reason (human-readable explanation)
    pub reason: Option<String>,
    /// Loss percentage at this hop
    pub hop_loss: f64,
    /// Loss percentage at next responding hop (for comparison)
    pub downstream_loss: Option<f64>,
    /// Consecutive negative detection checks (for hysteresis)
    #[serde(default)]
    pub negative_checks: u8,
}

/// PMTUD (Path MTU Discovery) phase
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum PmtudPhase {
    /// Phase 1: Normal traceroute to find destination TTL
    #[default]
    WaitingForDestination,
    /// Phase 2: Binary search for MTU
    Searching,
    /// PMTUD complete
    Complete,
}

/// PMTUD (Path MTU Discovery) binary search state
///
/// Uses binary search with DF (Don't Fragment) flag to discover the maximum
/// packet size that can reach the destination without fragmentation.
/// RFC 1191 (IPv4), RFC 8201 (IPv6).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PmtudState {
    /// Lower bound - known to work (responses received at this size)
    pub min_size: u16,
    /// Upper bound - known to fail or untested
    pub max_size: u16,
    /// Currently testing this size
    pub current_size: u16,
    /// Consecutive successes at current_size (need 2 to confirm)
    pub successes: u8,
    /// Consecutive failures at current_size (need 2 to confirm)
    pub failures: u8,
    /// Final discovered MTU (set when phase == Complete)
    pub discovered_mtu: Option<u16>,
    /// Current phase of PMTUD
    pub phase: PmtudPhase,
}

impl PmtudState {
    /// Create new PMTUD state with appropriate bounds for IPv4 or IPv6
    ///
    /// - IPv4: min=68 (RFC 791), max=1500
    /// - IPv6: min=1280 (RFC 8200), max=1500
    pub fn new(ipv6: bool) -> Self {
        let min = if ipv6 { 1280 } else { 68 };
        Self {
            min_size: min,
            max_size: 1500,
            current_size: 1500, // Start high, binary search down
            successes: 0,
            failures: 0,
            discovered_mtu: None,
            phase: PmtudPhase::WaitingForDestination,
        }
    }

    /// Check if binary search has converged (within 8 bytes)
    pub fn is_converged(&self) -> bool {
        self.max_size.saturating_sub(self.min_size) < 8
    }

    /// Get the next probe size (midpoint of current range)
    pub fn next_probe_size(&self) -> u16 {
        (self.min_size + self.max_size) / 2
    }

    /// Record a successful probe at the current size
    pub fn record_success(&mut self) {
        if self.failures > 0 {
            // Direction change (was failing, now succeeding) - restart count
            self.failures = 0;
            self.successes = 1;
        } else {
            self.successes += 1;
            if self.successes >= 2 {
                // Confirmed working at this size - raise lower bound
                self.min_size = self.current_size;
                self.successes = 0;
                self.failures = 0;
                self.advance();
            }
        }
    }

    /// Record a failed probe at the current size (timeout or Frag Needed without MTU)
    pub fn record_failure(&mut self) {
        if self.successes > 0 {
            // Direction change (was succeeding, now failing) - restart count
            self.successes = 0;
            self.failures = 1;
        } else {
            self.failures += 1;
            if self.failures >= 2 {
                // Confirmed failing at this size - lower upper bound
                self.max_size = self.current_size.saturating_sub(1);
                self.successes = 0;
                self.failures = 0;
                self.advance();
            }
        }
    }

    /// Record ICMP Fragmentation Needed with reported MTU
    /// Immediately clamps max_size to the reported MTU
    pub fn record_frag_needed(&mut self, reported_mtu: u16) {
        // Clamp immediately - no need for multiple confirmations
        self.max_size = self.max_size.min(reported_mtu);
        self.successes = 0;
        self.failures = 0;
        self.advance();
    }

    /// Advance to next probe size or complete if converged
    fn advance(&mut self) {
        if self.is_converged() {
            self.discovered_mtu = Some(self.min_size);
            self.phase = PmtudPhase::Complete;
        } else {
            self.current_size = self.next_probe_size();
        }
    }

    /// Start the searching phase (called when destination is found)
    pub fn start_search(&mut self) {
        self.phase = PmtudPhase::Searching;
        self.current_size = self.max_size; // Start at max
    }
}

/// A single hop (TTL level) in the path
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hop {
    pub ttl: u8,
    pub sent: u64,
    pub received: u64,
    /// Number of timed-out probes (used for accurate loss calculation)
    #[serde(default)]
    pub timeouts: u64,
    pub responders: HashMap<IpAddr, ResponderStats>,
    pub primary: Option<IpAddr>, // most frequently seen responder
    /// Rolling window of recent probe results for hop-level loss sparkline
    /// true = response received, false = timeout
    #[serde(skip)]
    pub recent_results: VecDeque<bool>,
    /// Per-flow path statistics for ECMP detection (Paris/Dublin traceroute)
    /// Maps flow_id (0-255) to per-flow stats
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub flow_paths: HashMap<u8, FlowPathStats>,
    /// NAT detection information for this hop
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nat_info: Option<NatInfo>,
    /// Rate limit detection information for this hop
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<RateLimitInfo>,
    /// Route changes (flaps) detected at this hop (single-flow mode only)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub route_changes: Vec<RouteChange>,
    /// Internal: tracks primary with hysteresis for flap detection only
    /// (separate from `primary` which always reflects true most-frequent)
    #[serde(skip)]
    flap_tracking_primary: Option<IpAddr>,
}

impl Hop {
    /// Margin required for primary to change (avoids per-packet LB noise)
    const PRIMARY_CHANGE_MARGIN: u64 = 2;
    /// Minimum responses before tracking route changes
    const MIN_RESPONSES_FOR_FLAP: u64 = 5;
    /// Maximum route changes to store
    const MAX_ROUTE_CHANGES: usize = 50;

    pub fn new(ttl: u8) -> Self {
        Self {
            ttl,
            sent: 0,
            received: 0,
            timeouts: 0,
            responders: HashMap::new(),
            primary: None,
            recent_results: VecDeque::with_capacity(60),
            flow_paths: HashMap::new(),
            nat_info: None,
            rate_limit: None,
            route_changes: Vec::new(),
            flap_tracking_primary: None,
        }
    }

    /// Record a probe was sent for this TTL
    pub fn record_sent(&mut self) {
        self.sent += 1;
    }

    /// Record a response from a responder
    #[allow(dead_code)]
    pub fn record_response(&mut self, ip: IpAddr, rtt: Duration) {
        self.record_response_with_mpls(ip, rtt, None);
    }

    /// Record a response from a responder with optional MPLS labels
    pub fn record_response_with_mpls(
        &mut self,
        ip: IpAddr,
        rtt: Duration,
        mpls_labels: Option<Vec<MplsLabel>>,
    ) {
        self.received += 1;

        let stats = self
            .responders
            .entry(ip)
            .or_insert_with(|| ResponderStats::new(ip));
        // Note: We use hop-level loss calculation (Hop::loss_pct), not per-responder.
        // ResponderStats tracks response count for display purposes only.
        stats.record_response(rtt);

        // Store MPLS labels if present (only update if we got labels)
        if mpls_labels.is_some() {
            stats.mpls_labels = mpls_labels;
        }

        // Track in hop-level sparkline
        self.recent_results.push_back(true);
        if self.recent_results.len() > 60 {
            self.recent_results.pop_front();
        }

        self.update_primary();
    }

    /// Record a response and detect route changes (single-flow mode only)
    ///
    /// This is the same as `record_response_with_mpls` but also tracks when
    /// the primary responder changes, indicating route instability.
    ///
    /// Uses a separate `flap_tracking_primary` with hysteresis (margin of 2)
    /// to avoid false flaps from per-packet load balancing noise, while keeping
    /// `self.primary` as the true most-frequent responder for UI/export.
    pub fn record_response_detecting_flaps(
        &mut self,
        ip: IpAddr,
        rtt: Duration,
        mpls_labels: Option<Vec<MplsLabel>>,
    ) {
        let old_flap_primary = self.flap_tracking_primary;
        self.record_response_with_mpls(ip, rtt, mpls_labels);

        // Update flap_tracking_primary with hysteresis
        let current_count = self
            .flap_tracking_primary
            .and_then(|ip| self.responders.get(&ip))
            .map(|s| s.received)
            .unwrap_or(0);

        if let Some((new_ip, stats)) = self.responders.iter().max_by_key(|(_, s)| s.received) {
            // Only change if: no current tracking primary, OR new leader exceeds by margin
            if self.flap_tracking_primary.is_none()
                || stats.received >= current_count + Self::PRIMARY_CHANGE_MARGIN
            {
                self.flap_tracking_primary = Some(*new_ip);
            }
        }

        // Check for route change (only after minimum responses)
        if self.received >= Self::MIN_RESPONSES_FOR_FLAP
            && let (Some(old), Some(new)) = (old_flap_primary, self.flap_tracking_primary)
            && old != new
        {
            self.route_changes.push(RouteChange {
                from_ip: old,
                to_ip: new,
                at_seq: self.received,
            });
            // Cap history size
            if self.route_changes.len() > Self::MAX_ROUTE_CHANGES {
                self.route_changes.remove(0);
            }
        }
    }

    /// Record a timeout - updates hop-level stats only
    ///
    /// Timeouts are tracked in `recent_results` for hop-level loss visualization.
    /// Per-responder sparklines only show RTT for actual responses, not timeouts,
    /// to avoid ECMP distortion (we can't know which responder "timed out").
    /// Hop-level loss percentage (`loss_pct()`) uses completed probes only.
    pub fn record_timeout(&mut self) {
        self.timeouts += 1;

        // Track in hop-level sparkline (false = timeout/loss)
        self.recent_results.push_back(false);
        if self.recent_results.len() > 60 {
            self.recent_results.pop_front();
        }
    }

    /// Update primary responder based on response count
    ///
    /// Simple max: primary is always the responder with the most responses.
    /// For flap detection with hysteresis, see `record_response_detecting_flaps()`.
    pub fn update_primary(&mut self) {
        self.primary = self
            .responders
            .iter()
            .max_by_key(|(_, s)| s.received)
            .map(|(ip, _)| *ip);
    }

    /// Get primary responder stats
    pub fn primary_stats(&self) -> Option<&ResponderStats> {
        self.primary.and_then(|ip| self.responders.get(&ip))
    }

    /// Loss percentage for this hop (based on completed probes only)
    ///
    /// Uses `timeouts / (received + timeouts)` to avoid counting in-flight
    /// probes as losses, which would cause "pulsing" in the UI.
    pub fn loss_pct(&self) -> f64 {
        let completed = self.received + self.timeouts;
        if completed == 0 {
            0.0
        } else {
            (self.timeouts as f64 / completed as f64) * 100.0
        }
    }

    /// Record a probe was sent on a specific flow
    pub fn record_flow_sent(&mut self, flow_id: u8) {
        self.flow_paths.entry(flow_id).or_default().record_sent();
    }

    /// Record a response from a responder on a specific flow
    pub fn record_flow_response(&mut self, flow_id: u8, responder: IpAddr, rtt: Duration) {
        // Update flow-specific stats
        self.flow_paths
            .entry(flow_id)
            .or_default()
            .record_response(responder);

        // Also update aggregate stats (existing behavior)
        // Note: record_response already handles all hop-level tracking
        // We just need flow tracking on top
        let _ = rtt; // RTT is recorded in aggregate stats via record_response
    }

    /// Record a timeout on a specific flow
    pub fn record_flow_timeout(&mut self, flow_id: u8) {
        self.flow_paths.entry(flow_id).or_default().record_timeout();
    }

    /// Check if ECMP is detected (multiple unique primary responders across flows)
    pub fn has_ecmp(&self) -> bool {
        if self.flow_paths.len() < 2 {
            return false;
        }

        // Collect unique primary responders across flows
        let unique_responders: std::collections::HashSet<_> = self
            .flow_paths
            .values()
            .filter_map(|fp| fp.primary_responder)
            .collect();

        unique_responders.len() > 1
    }

    /// Get list of (flow_id, primary_responder) pairs for ECMP display
    /// Only includes flows with a primary responder
    pub fn ecmp_paths(&self) -> Vec<(u8, IpAddr)> {
        let mut paths: Vec<_> = self
            .flow_paths
            .iter()
            .filter_map(|(&flow_id, fp)| fp.primary_responder.map(|ip| (flow_id, ip)))
            .collect();
        paths.sort_by_key(|(flow_id, _)| *flow_id);
        paths
    }

    /// Get number of unique paths detected (unique responders across flows)
    pub fn path_count(&self) -> usize {
        let unique_responders: std::collections::HashSet<_> = self
            .flow_paths
            .values()
            .filter_map(|fp| fp.primary_responder)
            .collect();
        unique_responders
            .len()
            .max(if self.primary.is_some() { 1 } else { 0 })
    }

    /// Record a NAT detection result for this hop
    ///
    /// Compares the original source port (from the sent probe) with the
    /// returned source port (from the ICMP error payload). A mismatch
    /// indicates NAT is rewriting ports.
    pub fn record_nat_check(&mut self, original: Option<u16>, returned: Option<u16>) {
        match (original, returned) {
            (Some(orig), Some(ret)) => {
                let nat_info = self.nat_info.get_or_insert_with(NatInfo::default);
                if orig == ret {
                    nat_info.record_match();
                } else {
                    nat_info.record_rewrite(orig, ret);
                }
            }
            _ => {
                // ICMP probe or missing port info - no NAT check possible
            }
        }
    }

    /// Check if NAT is detected at this hop
    pub fn has_nat(&self) -> bool {
        self.nat_info.as_ref().is_some_and(|n| n.has_nat())
    }
}

/// Target being traced
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Target {
    pub original: String,
    pub resolved: IpAddr,
    pub hostname: Option<String>,
}

impl Target {
    pub fn new(original: String, resolved: IpAddr) -> Self {
        Self {
            original,
            resolved,
            hostname: None,
        }
    }
}

/// A complete tracing session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub target: Target,
    pub started_at: DateTime<Utc>,
    pub hops: Vec<Hop>,
    pub config: Config,
    pub complete: bool,       // destination reached?
    pub dest_ttl: Option<u8>, // TTL at which destination was reached (actual hop count)
    pub total_sent: u64,      // total probes sent across all hops
    #[serde(skip)]
    pub paused: bool, // pause probing (TUI only)
    /// PMTUD state (only present when --pmtud is enabled)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pmtud: Option<PmtudState>,
    /// Source IP used for probes (for display in TUI)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_ip: Option<IpAddr>,
    /// Default gateway IP (for display in TUI)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway: Option<IpAddr>,
}

impl Session {
    pub fn new(target: Target, config: Config) -> Self {
        let max_ttl = config.max_ttl;
        let mut hops = Vec::with_capacity(max_ttl as usize);
        for ttl in 1..=max_ttl {
            hops.push(Hop::new(ttl));
        }

        // Initialize PMTUD state if enabled
        let pmtud = if config.pmtud {
            Some(PmtudState::new(target.resolved.is_ipv6()))
        } else {
            None
        };

        Self {
            target,
            started_at: Utc::now(),
            hops,
            config,
            complete: false,
            dest_ttl: None,
            total_sent: 0,
            paused: false,
            pmtud,
            source_ip: None,
            gateway: None,
        }
    }

    /// Get hop by TTL (1-indexed)
    pub fn hop(&self, ttl: u8) -> Option<&Hop> {
        if ttl == 0 || ttl as usize > self.hops.len() {
            None
        } else {
            Some(&self.hops[ttl as usize - 1])
        }
    }

    /// Get mutable hop by TTL (1-indexed)
    pub fn hop_mut(&mut self, ttl: u8) -> Option<&mut Hop> {
        if ttl == 0 || ttl as usize > self.hops.len() {
            None
        } else {
            Some(&mut self.hops[ttl as usize - 1])
        }
    }

    /// Get discovered hops (those that have received at least one response)
    #[allow(dead_code)]
    pub fn discovered_hops(&self) -> impl Iterator<Item = &Hop> {
        self.hops.iter().filter(|h| h.received > 0 || h.sent > 0)
    }

    /// Get the last hop that responded
    #[allow(dead_code)]
    pub fn last_responding_hop(&self) -> Option<&Hop> {
        self.hops.iter().rev().find(|h| h.received > 0)
    }

    /// Reset all statistics while keeping the session structure
    pub fn reset_stats(&mut self) {
        self.total_sent = 0;
        self.complete = false;
        self.dest_ttl = None;
        self.started_at = Utc::now();

        // Reset PMTUD state if enabled
        if self.pmtud.is_some() {
            self.pmtud = Some(PmtudState::new(self.target.resolved.is_ipv6()));
        }

        for hop in &mut self.hops {
            hop.sent = 0;
            hop.received = 0;
            hop.timeouts = 0;
            hop.responders.clear();
            hop.primary = None;
            hop.recent_results.clear();
            hop.flow_paths.clear();
            hop.nat_info = None;
            hop.rate_limit = None;
            hop.route_changes.clear();
            hop.flap_tracking_primary = None;
        }
    }

    /// Check if NAT is detected at any hop
    pub fn has_nat(&self) -> bool {
        self.hops.iter().any(|h| h.has_nat())
    }

    /// Get the first hop where NAT is detected (likely the local NAT device)
    #[allow(dead_code)]
    pub fn first_nat_hop(&self) -> Option<u8> {
        self.hops.iter().find(|h| h.has_nat()).map(|h| h.ttl)
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
        duration.as_micros().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let micros = u64::deserialize(deserializer)?;
        Ok(Duration::from_micros(micros))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_responder_stats_initial_state() {
        let ip = IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1));
        let stats = ResponderStats::new(ip);

        assert_eq!(stats.ip, ip);
        assert_eq!(stats.sent, 0);
        assert_eq!(stats.received, 0);
        assert_eq!(stats.min_rtt, Duration::MAX);
        assert_eq!(stats.max_rtt, Duration::ZERO);
        assert_eq!(stats.mean_rtt, 0.0);
        assert_eq!(stats.jitter_avg, 0.0);
        assert_eq!(stats.jitter_max, 0.0);
        assert_eq!(stats.loss_pct(), 0.0);
    }

    #[test]
    fn test_responder_stats_single_sample() {
        let ip = IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8));
        let mut stats = ResponderStats::new(ip);

        let rtt = Duration::from_millis(10);
        stats.record_response(rtt);

        assert_eq!(stats.received, 1);
        assert_eq!(stats.min_rtt, rtt);
        assert_eq!(stats.max_rtt, rtt);
        assert_eq!(stats.avg_rtt(), rtt);
        assert_eq!(stats.stddev(), Duration::ZERO); // stddev needs 2+ samples
    }

    #[test]
    fn test_responder_stats_welford_algorithm() {
        let ip = IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1));
        let mut stats = ResponderStats::new(ip);

        // Add known samples: 10, 20, 30 ms
        // Mean = 20ms, Variance = 66.67, StdDev = ~8.16ms
        stats.record_response(Duration::from_millis(10));
        stats.record_response(Duration::from_millis(20));
        stats.record_response(Duration::from_millis(30));

        assert_eq!(stats.received, 3);
        assert_eq!(stats.min_rtt, Duration::from_millis(10));
        assert_eq!(stats.max_rtt, Duration::from_millis(30));

        // Check mean (allow small floating point tolerance)
        let avg_ms = stats.avg_rtt().as_millis();
        assert_eq!(avg_ms, 20);

        // Check stddev (population stddev of 10,20,30 is ~8.16ms)
        let stddev_ms = stats.stddev().as_micros();
        assert!(stddev_ms > 8000 && stddev_ms < 8500);
    }

    #[test]
    fn test_responder_stats_jitter() {
        let ip = IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1));
        let mut stats = ResponderStats::new(ip);

        // First sample - no jitter yet
        stats.record_response(Duration::from_millis(10));
        assert_eq!(stats.jitter(), Duration::ZERO);
        assert_eq!(stats.jitter_avg(), Duration::ZERO);
        assert_eq!(stats.jitter_max(), Duration::ZERO);

        // Second sample with large jump - jitter increases
        stats.record_response(Duration::from_millis(50));
        assert!(stats.jitter() > Duration::ZERO);
        assert!(stats.jitter_avg() > Duration::ZERO);
        assert!(stats.jitter_max() > Duration::ZERO);

        // First jitter sample: |50-10| = 40ms
        assert_eq!(stats.jitter_max(), Duration::from_millis(40));
        assert_eq!(stats.jitter_avg(), Duration::from_millis(40)); // Only one jitter sample

        // Jitter should be smoothed (RFC 3550: j = j + (|d| - j) / 16)
        let jitter_after_2 = stats.jitter();
        let max_jitter_after_2 = stats.jitter_max();

        // Add more stable samples
        for _ in 0..10 {
            stats.record_response(Duration::from_millis(50));
        }

        // Smoothed jitter should decrease with stable samples
        assert!(stats.jitter() < jitter_after_2);
        // Max jitter should remain at 40ms (largest jump was first)
        assert_eq!(stats.jitter_max(), max_jitter_after_2);
        // Average jitter should decrease with stable samples
        assert!(stats.jitter_avg() < Duration::from_millis(40));
    }

    #[test]
    fn test_hop_loss_calculation() {
        let mut hop = Hop::new(5);

        // No completed probes = 0% loss (in-flight probes don't count as loss)
        assert_eq!(hop.loss_pct(), 0.0);

        // Record 10 sends (still no completed probes)
        for _ in 0..10 {
            hop.record_sent();
        }

        // No completed probes yet = 0% loss (avoids UI "pulsing")
        assert_eq!(hop.loss_pct(), 0.0);

        // 7 responses, 3 timeouts = 30% loss (3/10)
        let ip = IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1));
        for _ in 0..7 {
            hop.record_response(ip, Duration::from_millis(10));
        }
        for _ in 0..3 {
            hop.record_timeout();
        }
        assert!((hop.loss_pct() - 30.0).abs() < 0.01);

        // 100% loss case
        let mut hop2 = Hop::new(6);
        for _ in 0..5 {
            hop2.record_sent();
            hop2.record_timeout();
        }
        assert_eq!(hop2.loss_pct(), 100.0);
    }

    #[test]
    fn test_hop_ecmp_multiple_responders() {
        let mut hop = Hop::new(3);
        let ip1 = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1));
        let ip2 = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 2));

        // Send 10 probes
        for _ in 0..10 {
            hop.record_sent();
        }

        // ip1 responds 6 times, ip2 responds 4 times
        for _ in 0..6 {
            hop.record_response(ip1, Duration::from_millis(10));
        }
        for _ in 0..4 {
            hop.record_response(ip2, Duration::from_millis(15));
        }

        // Total hop loss: 0% (all 10 probes got responses)
        assert_eq!(hop.loss_pct(), 0.0);

        // Should have 2 responders
        assert_eq!(hop.responders.len(), 2);

        // Primary should be ip1 (more responses)
        assert_eq!(hop.primary, Some(ip1));

        // Primary stats should be for ip1
        let primary = hop.primary_stats().unwrap();
        assert_eq!(primary.ip, ip1);
        assert_eq!(primary.received, 6);
    }

    #[test]
    fn test_hop_timeout_does_not_inflate_responder_loss() {
        let mut hop = Hop::new(5);
        let ip = IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1));

        // Send 10, receive 5, timeout 5
        for _ in 0..10 {
            hop.record_sent();
        }
        for _ in 0..5 {
            hop.record_response(ip, Duration::from_millis(10));
        }
        for _ in 0..5 {
            hop.record_timeout();
        }

        // Hop-level loss should be 50%
        assert_eq!(hop.loss_pct(), 50.0);

        // Responder stats should only count actual responses
        let stats = hop.responders.get(&ip).unwrap();
        assert_eq!(stats.received, 5);
    }

    #[test]
    fn test_session_hop_access() {
        let target = Target::new(
            "example.com".to_string(),
            IpAddr::V4(std::net::Ipv4Addr::new(93, 184, 216, 34)),
        );
        let config = Config::default();
        let session = Session::new(target, config);

        // TTL 0 should be None
        assert!(session.hop(0).is_none());

        // TTL 1-30 should exist
        assert!(session.hop(1).is_some());
        assert_eq!(session.hop(1).unwrap().ttl, 1);
        assert!(session.hop(30).is_some());
        assert_eq!(session.hop(30).unwrap().ttl, 30);

        // TTL 31 should be None (default max_ttl is 30)
        assert!(session.hop(31).is_none());
    }

    #[test]
    fn test_session_serialization_roundtrip() {
        let target = Target::new(
            "test.com".to_string(),
            IpAddr::V4(std::net::Ipv4Addr::new(1, 2, 3, 4)),
        );
        let config = Config::default();
        let mut session = Session::new(target, config);

        // Add some data
        if let Some(hop) = session.hop_mut(1) {
            hop.record_sent();
            hop.record_response(
                IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1)),
                Duration::from_millis(5),
            );
        }

        // Serialize
        let json = serde_json::to_string(&session).unwrap();

        // Deserialize
        let restored: Session = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.target.original, "test.com");
        assert_eq!(restored.hop(1).unwrap().sent, 1);
        assert_eq!(restored.hop(1).unwrap().received, 1);
    }

    #[test]
    fn test_session_reset_stats() {
        let target = Target::new(
            "test.com".to_string(),
            IpAddr::V4(std::net::Ipv4Addr::new(1, 2, 3, 4)),
        );
        let config = Config::default();
        let mut session = Session::new(target, config);

        // Add some data
        session.total_sent = 100;
        session.complete = true;
        session.dest_ttl = Some(5);

        if let Some(hop) = session.hop_mut(1) {
            hop.record_sent();
            hop.record_response(
                IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1)),
                Duration::from_millis(5),
            );
            // Add rate limit info that should be cleared on reset
            hop.rate_limit = Some(RateLimitInfo {
                suspected: true,
                confidence: 0.8,
                reason: Some("test".into()),
                hop_loss: 50.0,
                downstream_loss: Some(0.0),
                negative_checks: 0,
            });
        }

        // Reset
        session.reset_stats();

        // Verify reset
        assert_eq!(session.total_sent, 0);
        assert!(!session.complete);
        assert!(session.dest_ttl.is_none());
        assert_eq!(session.hop(1).unwrap().sent, 0);
        assert_eq!(session.hop(1).unwrap().received, 0);
        assert!(session.hop(1).unwrap().responders.is_empty());
        assert!(
            session.hop(1).unwrap().rate_limit.is_none(),
            "rate_limit should be cleared on reset"
        );
    }

    #[test]
    fn test_responder_stats_extreme_rtts() {
        let ip = IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1));
        let mut stats = ResponderStats::new(ip);

        // Test with sub-millisecond RTT
        stats.record_response(Duration::from_micros(100));
        assert_eq!(stats.min_rtt, Duration::from_micros(100));

        // Test with very high RTT (1 second)
        stats.record_response(Duration::from_secs(1));
        assert_eq!(stats.max_rtt, Duration::from_secs(1));

        // Average should be reasonable
        let avg_micros = stats.avg_rtt().as_micros();
        // (100 + 1_000_000) / 2 = 500_050
        assert!(avg_micros > 400_000 && avg_micros < 600_000);
    }

    #[test]
    fn test_hop_recent_results_tracking() {
        let mut hop = Hop::new(3);
        let ip = IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1));

        // Send some probes with mixed results
        hop.record_sent();
        hop.record_response(ip, Duration::from_millis(10));
        assert_eq!(hop.recent_results.back(), Some(&true));

        hop.record_sent();
        hop.record_timeout();
        assert_eq!(hop.recent_results.back(), Some(&false));

        hop.record_sent();
        hop.record_response(ip, Duration::from_millis(10));
        assert_eq!(hop.recent_results.back(), Some(&true));

        // Check ordering: [true, false, true]
        let results: Vec<bool> = hop.recent_results.iter().copied().collect();
        assert_eq!(results, vec![true, false, true]);
    }

    #[test]
    fn test_responder_stats_rolling_window_capacity() {
        let ip = IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1));
        let mut stats = ResponderStats::new(ip);

        // Add 70 samples (more than 60 capacity)
        for i in 0..70 {
            stats.record_response(Duration::from_millis(i));
        }

        // Rolling window should be capped at 60
        assert_eq!(stats.recent.len(), 60);

        // Oldest entries should be dropped (first 10)
        // Most recent should be 60-69ms
        let first_entry = stats.recent.front().unwrap().unwrap();
        assert!(first_entry >= Duration::from_millis(10));
    }

    #[test]
    fn test_responder_stats_percentiles() {
        let ip = IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1));
        let mut stats = ResponderStats::new(ip);

        // Empty samples should return None
        assert!(stats.p50().is_none());
        assert!(stats.p95().is_none());
        assert!(stats.p99().is_none());

        // Add 100 samples: 1ms, 2ms, ..., 100ms
        for i in 1..=100 {
            stats.record_response(Duration::from_millis(i));
        }

        // p50 should be around 50ms (median)
        let p50 = stats.p50().unwrap();
        assert!(p50 >= Duration::from_millis(49) && p50 <= Duration::from_millis(51));

        // p95 should be around 95ms
        let p95 = stats.p95().unwrap();
        assert!(p95 >= Duration::from_millis(94) && p95 <= Duration::from_millis(96));

        // p99 should be around 99ms
        let p99 = stats.p99().unwrap();
        assert!(p99 >= Duration::from_millis(98) && p99 <= Duration::from_millis(100));
    }

    #[test]
    fn test_responder_stats_sample_history_capacity() {
        let ip = IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1));
        let mut stats = ResponderStats::new(ip);

        // Add 300 samples (more than 256 capacity)
        for i in 0..300 {
            stats.record_response(Duration::from_millis(i));
        }

        // Sample history should be capped at 256
        assert_eq!(stats.samples.len(), 256);

        // Oldest samples (0-43ms) should be dropped
        // p50 of remaining samples (44-299) should be around 171ms
        let p50 = stats.p50().unwrap();
        assert!(p50 >= Duration::from_millis(165) && p50 <= Duration::from_millis(180));
    }

    #[test]
    fn test_flow_path_stats_basic() {
        let mut fps = FlowPathStats::new();
        let ip1 = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1));
        let ip2 = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 2));

        assert_eq!(fps.sent, 0);
        assert_eq!(fps.received, 0);
        assert!(fps.primary_responder.is_none());
        assert_eq!(fps.loss_pct(), 0.0);

        // Record 10 sends (no completed probes yet = 0% loss)
        for _ in 0..10 {
            fps.record_sent();
        }
        assert_eq!(fps.sent, 10);
        assert_eq!(fps.loss_pct(), 0.0); // No completed probes yet

        // Record 6 responses from ip1, 2 from ip2, 2 timeouts = 20% loss
        for _ in 0..6 {
            fps.record_response(ip1);
        }
        for _ in 0..2 {
            fps.record_response(ip2);
        }
        for _ in 0..2 {
            fps.record_timeout();
        }

        assert_eq!(fps.received, 8);
        assert_eq!(fps.timeouts, 2);
        assert!((fps.loss_pct() - 20.0).abs() < 0.01); // 2/10 = 20% loss
        assert_eq!(fps.primary_responder, Some(ip1)); // ip1 has most responses
        assert_eq!(fps.responder_counts.get(&ip1), Some(&6));
        assert_eq!(fps.responder_counts.get(&ip2), Some(&2));
    }

    #[test]
    fn test_hop_flow_tracking() {
        let mut hop = Hop::new(5);
        let ip1 = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1));
        let ip2 = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 2));

        // No flows initially
        assert!(hop.flow_paths.is_empty());
        assert!(!hop.has_ecmp());
        assert!(hop.ecmp_paths().is_empty());
        assert_eq!(hop.path_count(), 0);

        // Record flow 0 probes - all to ip1
        for _ in 0..5 {
            hop.record_flow_sent(0);
            hop.record_flow_response(0, ip1, Duration::from_millis(10));
        }

        // Single flow doesn't count as ECMP
        assert!(!hop.has_ecmp());
        assert_eq!(hop.path_count(), 1);
        assert_eq!(hop.ecmp_paths(), vec![(0, ip1)]);

        // Record flow 1 probes - all to ip2 (different path!)
        for _ in 0..5 {
            hop.record_flow_sent(1);
            hop.record_flow_response(1, ip2, Duration::from_millis(15));
        }

        // Now ECMP is detected
        assert!(hop.has_ecmp());
        assert_eq!(hop.path_count(), 2);
        let paths = hop.ecmp_paths();
        assert_eq!(paths.len(), 2);
        assert!(paths.contains(&(0, ip1)));
        assert!(paths.contains(&(1, ip2)));
    }

    #[test]
    fn test_hop_flow_no_ecmp_same_responder() {
        let mut hop = Hop::new(3);
        let ip = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1));

        // Record multiple flows, all to same responder
        for flow_id in 0..4 {
            for _ in 0..3 {
                hop.record_flow_sent(flow_id);
                hop.record_flow_response(flow_id, ip, Duration::from_millis(10));
            }
        }

        // Same responder on all flows = no ECMP
        assert!(!hop.has_ecmp());
        assert_eq!(hop.path_count(), 1);
        assert_eq!(hop.ecmp_paths().len(), 4); // 4 flows, but all same responder
    }

    #[test]
    fn test_session_reset_clears_flow_paths() {
        let target = Target::new(
            "test.com".to_string(),
            IpAddr::V4(std::net::Ipv4Addr::new(1, 2, 3, 4)),
        );
        let config = Config::default();
        let mut session = Session::new(target, config);

        // Add flow data
        if let Some(hop) = session.hop_mut(1) {
            hop.record_flow_sent(0);
            hop.record_flow_response(
                0,
                IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
                Duration::from_millis(5),
            );
        }

        assert!(!session.hop(1).unwrap().flow_paths.is_empty());

        // Reset should clear flow_paths
        session.reset_stats();
        assert!(session.hop(1).unwrap().flow_paths.is_empty());
    }

    #[test]
    fn test_route_flap_sticky_tie() {
        // Test that no false flaps occur when counts are equal (sticky tie-breaker)
        // The internal flap_tracking_primary uses hysteresis to prevent oscillation
        let mut hop = Hop::new(5);
        let ip1 = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1));
        let ip2 = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 2));

        // Alternate responses to keep counts equal, past the min threshold
        // ip1: 3, ip2: 3 after 6 responses (past threshold of 5)
        for _ in 0..3 {
            hop.record_response_detecting_flaps(ip1, Duration::from_millis(10), None);
            hop.record_response_detecting_flaps(ip2, Duration::from_millis(10), None);
        }

        // No flaps should be recorded because:
        // - flap_tracking_primary stuck with ip1 (first responder)
        // - ip2 never exceeded ip1's count by margin of 2
        assert!(
            hop.route_changes.is_empty(),
            "Tied counts should not cause flap (sticky tie-breaker)"
        );
    }

    #[test]
    fn test_route_flap_margin_threshold() {
        // Test that flaps are only recorded when new IP exceeds by margin of 2
        let mut hop = Hop::new(5);
        let ip1 = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1));
        let ip2 = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 2));

        // ip1 gets 3 responses, becomes initial flap_tracking_primary
        for _ in 0..3 {
            hop.record_response_detecting_flaps(ip1, Duration::from_millis(10), None);
        }

        // ip2 gets 4 responses (only +1 over ip1's 3) - not enough margin
        for _ in 0..4 {
            hop.record_response_detecting_flaps(ip2, Duration::from_millis(10), None);
        }
        // ip1: 3, ip2: 4 - only +1, below margin of 2
        // No flap recorded (flap_tracking_primary still ip1)
        assert!(
            hop.route_changes.is_empty(),
            "Sub-margin lead should not cause flap"
        );

        // ip2 gets one more (now +2 margin: 5 vs 3)
        hop.record_response_detecting_flaps(ip2, Duration::from_millis(10), None);
        // ip1: 3, ip2: 5 - now +2, should record flap
        assert_eq!(
            hop.route_changes.len(),
            1,
            "Margin of +2 should trigger flap"
        );
        assert_eq!(hop.route_changes[0].from_ip, ip1);
        assert_eq!(hop.route_changes[0].to_ip, ip2);
    }

    #[test]
    fn test_route_flap_min_response_threshold() {
        // Test that flaps are only recorded after MIN_RESPONSES_FOR_FLAP (5)
        let mut hop = Hop::new(5);
        let ip1 = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1));
        let ip2 = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 2));

        // Record 1 from ip1 (becomes flap_tracking_primary)
        hop.record_response_detecting_flaps(ip1, Duration::from_millis(10), None);

        // Record 3 from ip2 (margin +2 at received=4, switches flap_tracking_primary)
        // But below min threshold, so no flap recorded
        for _ in 0..3 {
            hop.record_response_detecting_flaps(ip2, Duration::from_millis(10), None);
        }
        // Total: 4, ip1=1, ip2=3 - switch happened but below threshold
        assert!(
            hop.route_changes.is_empty(),
            "Switch below min threshold should not record flap"
        );
        assert_eq!(hop.received, 4);

        // Now add one more from ip1 - brings total to 5, ip1=2, ip2=3
        // ip2 still leads by only 1, not enough margin for another switch
        hop.record_response_detecting_flaps(ip1, Duration::from_millis(10), None);
        assert!(hop.route_changes.is_empty());
        assert_eq!(hop.received, 5);

        // Add 2 more from ip1 - now ip1=4, ip2=3, ip1 leads by 1
        for _ in 0..2 {
            hop.record_response_detecting_flaps(ip1, Duration::from_millis(10), None);
        }
        // Not enough margin to switch back, no flap
        assert!(hop.route_changes.is_empty());

        // Add 3 more from ip1 - now ip1=7, ip2=3, margin is +4
        // This should finally trigger a flap (ip2 -> ip1) since:
        // - We're past min threshold (received=10)
        // - ip1 exceeds ip2 by more than margin of 2
        for _ in 0..3 {
            hop.record_response_detecting_flaps(ip1, Duration::from_millis(10), None);
        }
        assert_eq!(
            hop.route_changes.len(),
            1,
            "Should record flap when margin met after threshold"
        );
        assert_eq!(hop.route_changes[0].from_ip, ip2);
        assert_eq!(hop.route_changes[0].to_ip, ip1);
    }

    #[test]
    fn test_route_flap_capped_history() {
        // Test that route_changes is capped at MAX_ROUTE_CHANGES (50)
        let mut hop = Hop::new(5);
        let ip1 = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1));
        let ip2 = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 2));

        // Manually add route changes to test cap
        for i in 0..55 {
            hop.route_changes.push(RouteChange {
                from_ip: if i % 2 == 0 { ip1 } else { ip2 },
                to_ip: if i % 2 == 0 { ip2 } else { ip1 },
                at_seq: i as u64,
            });

            // Simulate cap behavior
            if hop.route_changes.len() > Hop::MAX_ROUTE_CHANGES {
                hop.route_changes.remove(0);
            }
        }

        // Should be capped at 50
        assert_eq!(hop.route_changes.len(), Hop::MAX_ROUTE_CHANGES);
        // Oldest entries should be removed (entries 0-4 removed, 5-54 remain)
        assert_eq!(hop.route_changes[0].at_seq, 5);
    }

    #[test]
    fn test_route_flap_reset_clears() {
        // Test that reset_stats() clears route_changes
        let target = Target::new(
            "test.com".to_string(),
            IpAddr::V4(std::net::Ipv4Addr::new(1, 2, 3, 4)),
        );
        let config = Config::default();
        let mut session = Session::new(target, config);

        let ip1 = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1));
        let ip2 = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 2));

        // Add a route change manually
        if let Some(hop) = session.hop_mut(1) {
            hop.route_changes.push(RouteChange {
                from_ip: ip1,
                to_ip: ip2,
                at_seq: 10,
            });
        }

        assert!(!session.hop(1).unwrap().route_changes.is_empty());

        // Reset should clear
        session.reset_stats();
        assert!(session.hop(1).unwrap().route_changes.is_empty());
    }

    #[test]
    fn test_multi_flow_no_flap_detection() {
        // Test that record_response_with_mpls (used in multi-flow mode)
        // does NOT record route changes - only record_response_detecting_flaps does
        let mut hop = Hop::new(5);
        let ip1 = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1));
        let ip2 = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 2));

        // ip1 gets 3 responses
        for _ in 0..3 {
            hop.record_response_with_mpls(ip1, Duration::from_millis(10), None);
        }

        // ip2 gets 6 responses (exceeds margin of +2 and past threshold of 5)
        for _ in 0..6 {
            hop.record_response_with_mpls(ip2, Duration::from_millis(10), None);
        }

        // primary should be ip2 (most frequent)
        assert_eq!(hop.primary, Some(ip2));
        // But no route change should be recorded (multi-flow path)
        assert!(
            hop.route_changes.is_empty(),
            "record_response_with_mpls should NOT record flaps (multi-flow mode)"
        );
    }
}
