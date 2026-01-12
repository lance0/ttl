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
    pub fn to_sequence(&self) -> u16 {
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

/// Stats for a single responder at a given TTL
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponderStats {
    pub ip: IpAddr,
    pub hostname: Option<String>,
    pub asn: Option<AsnInfo>,
    pub geo: Option<GeoInfo>,

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
    pub jitter: f64, // microseconds
    #[serde(skip)]
    pub last_rtt: Option<Duration>,

    // Rolling window for sparkline
    #[serde(skip)]
    pub recent: VecDeque<Option<Duration>>,
}

impl ResponderStats {
    pub fn new(ip: IpAddr) -> Self {
        Self {
            ip,
            hostname: None,
            asn: None,
            geo: None,
            sent: 0,
            received: 0,
            min_rtt: Duration::MAX,
            max_rtt: Duration::ZERO,
            mean_rtt: 0.0,
            m2: 0.0,
            jitter: 0.0,
            last_rtt: None,
            recent: VecDeque::with_capacity(60),
        }
    }

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

        // Latency jitter: RFC 3550-style smoothed variance of RTT
        // Note: This measures RTT variance, not inter-arrival time variance.
        // Useful for detecting network instability affecting round-trip latency.
        if let Some(last) = self.last_rtt {
            let diff = (rtt_micros - last.as_micros() as f64).abs();
            self.jitter += (diff - self.jitter) / 16.0;
        }
        self.last_rtt = Some(rtt);

        // Rolling window
        self.recent.push_back(Some(rtt));
        if self.recent.len() > 60 {
            self.recent.pop_front();
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

    /// Jitter
    pub fn jitter(&self) -> Duration {
        Duration::from_micros(self.jitter as u64)
    }
}

/// A single hop (TTL level) in the path
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hop {
    pub ttl: u8,
    pub sent: u64,
    pub received: u64,
    pub responders: HashMap<IpAddr, ResponderStats>,
    pub primary: Option<IpAddr>, // most frequently seen responder
    /// Rolling window of recent probe results for hop-level loss sparkline
    /// true = response received, false = timeout
    #[serde(skip)]
    pub recent_results: VecDeque<bool>,
}

impl Hop {
    pub fn new(ttl: u8) -> Self {
        Self {
            ttl,
            sent: 0,
            received: 0,
            responders: HashMap::new(),
            primary: None,
            recent_results: VecDeque::with_capacity(60),
        }
    }

    /// Record a probe was sent for this TTL
    pub fn record_sent(&mut self) {
        self.sent += 1;
    }

    /// Record a response from a responder
    pub fn record_response(&mut self, ip: IpAddr, rtt: Duration) {
        self.received += 1;

        let stats = self
            .responders
            .entry(ip)
            .or_insert_with(|| ResponderStats::new(ip));
        // Note: We use hop-level loss calculation (Hop::loss_pct), not per-responder.
        // ResponderStats tracks response count for display purposes only.
        stats.record_response(rtt);

        // Track in hop-level sparkline
        self.recent_results.push_back(true);
        if self.recent_results.len() > 60 {
            self.recent_results.pop_front();
        }

        self.update_primary();
    }

    /// Record a timeout - updates hop-level stats only
    ///
    /// Timeouts are tracked in `recent_results` for hop-level loss visualization.
    /// Per-responder sparklines only show RTT for actual responses, not timeouts,
    /// to avoid ECMP distortion (we can't know which responder "timed out").
    /// Hop-level loss percentage (`loss_pct()`) remains accurate.
    pub fn record_timeout(&mut self) {
        // Track in hop-level sparkline (false = timeout/loss)
        self.recent_results.push_back(false);
        if self.recent_results.len() > 60 {
            self.recent_results.pop_front();
        }
    }

    /// Update primary responder based on response count
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

    /// Loss percentage for this hop
    pub fn loss_pct(&self) -> f64 {
        if self.sent == 0 {
            0.0
        } else {
            (1.0 - (self.received as f64 / self.sent as f64)) * 100.0
        }
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
    pub complete: bool,  // destination reached?
    pub total_sent: u64, // total probes sent across all hops
}

impl Session {
    pub fn new(target: Target, config: Config) -> Self {
        let max_ttl = config.max_ttl;
        let mut hops = Vec::with_capacity(max_ttl as usize);
        for ttl in 1..=max_ttl {
            hops.push(Hop::new(ttl));
        }

        Self {
            target,
            started_at: Utc::now(),
            hops,
            config,
            complete: false,
            total_sent: 0,
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

        // Second sample with large jump - jitter increases
        stats.record_response(Duration::from_millis(50));
        assert!(stats.jitter() > Duration::ZERO);

        // Jitter should be smoothed (RFC 3550: j = j + (|d| - j) / 16)
        let jitter_after_2 = stats.jitter();

        // Add more stable samples
        for _ in 0..10 {
            stats.record_response(Duration::from_millis(50));
        }

        // Jitter should decrease with stable samples
        assert!(stats.jitter() < jitter_after_2);
    }

    #[test]
    fn test_hop_loss_calculation() {
        let mut hop = Hop::new(5);

        // No sends = 0% loss
        assert_eq!(hop.loss_pct(), 0.0);

        // Record 10 sends
        for _ in 0..10 {
            hop.record_sent();
        }

        // No responses yet = 100% loss
        assert_eq!(hop.loss_pct(), 100.0);

        // 7 responses = 30% loss
        let ip = IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1));
        for _ in 0..7 {
            hop.record_response(ip, Duration::from_millis(10));
        }
        assert!((hop.loss_pct() - 30.0).abs() < 0.01);
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
        let target = Target::new("example.com".to_string(), IpAddr::V4(std::net::Ipv4Addr::new(93, 184, 216, 34)));
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
        let target = Target::new("test.com".to_string(), IpAddr::V4(std::net::Ipv4Addr::new(1, 2, 3, 4)));
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
}
