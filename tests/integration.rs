//! Integration tests for probe→receive→state pipeline
//!
//! These tests verify the data flow from simulated probe sends
//! through state updates, without requiring actual network access.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use ttl::config::Config;
use ttl::state::session::{Session, Target};

/// Create a test session for 8.8.8.8 with default config
fn test_session() -> Session {
    let target = Target::new("8.8.8.8".to_string(), IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
    let config = Config::default();
    Session::new(target, config)
}

#[test]
fn test_session_creation() {
    let session = test_session();

    assert_eq!(session.target.original, "8.8.8.8");
    assert_eq!(session.total_sent, 0);
    assert!(!session.complete);
    assert_eq!(session.dest_ttl, None);

    // Default max_ttl is 30, so we should have 30 hops
    assert_eq!(session.hops.len(), 30);
}

#[test]
fn test_hop_probe_lifecycle() {
    let mut session = test_session();

    // Simulate sending a probe at TTL 1
    if let Some(hop) = session.hop_mut(1) {
        hop.record_sent();
        assert_eq!(hop.sent, 1);
        assert_eq!(hop.received, 0);
    }

    // Simulate receiving a response from a router
    let router_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
    let rtt = Duration::from_millis(5);

    if let Some(hop) = session.hop_mut(1) {
        hop.record_response(router_ip, rtt);
        assert_eq!(hop.received, 1);
        assert_eq!(hop.primary, Some(router_ip));

        // Check responder stats
        let stats = hop.responders.get(&router_ip).unwrap();
        assert_eq!(stats.received, 1);
        assert_eq!(stats.min_rtt, rtt);
        assert_eq!(stats.max_rtt, rtt);
    }
}

#[test]
fn test_hop_timeout() {
    let mut session = test_session();

    // Send probe and record timeout
    if let Some(hop) = session.hop_mut(5) {
        hop.record_sent();
        hop.record_timeout();

        assert_eq!(hop.sent, 1);
        assert_eq!(hop.received, 0);
        assert_eq!(hop.timeouts, 1);
    }
}

#[test]
fn test_ecmp_multiple_responders() {
    let mut session = test_session();

    let router1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let router2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let rtt = Duration::from_millis(10);

    if let Some(hop) = session.hop_mut(3) {
        // First response from router1
        hop.record_sent();
        hop.record_response(router1, rtt);

        // Second response from router2 (ECMP path)
        hop.record_sent();
        hop.record_response(router2, rtt);

        // Third response from router1 again
        hop.record_sent();
        hop.record_response(router1, rtt);

        assert_eq!(hop.sent, 3);
        assert_eq!(hop.received, 3);
        assert_eq!(hop.responders.len(), 2);

        // router1 should be primary (seen 2 times vs 1)
        assert_eq!(hop.primary, Some(router1));
    }
}

#[test]
fn test_session_reset() {
    let mut session = test_session();

    // Record some activity
    let router = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
    if let Some(hop) = session.hop_mut(1) {
        hop.record_sent();
        hop.record_response(router, Duration::from_millis(5));
    }
    session.total_sent = 10;

    // Reset
    session.reset_stats();

    assert_eq!(session.total_sent, 0);
    assert!(!session.complete);

    if let Some(hop) = session.hop(1) {
        assert_eq!(hop.sent, 0);
        assert_eq!(hop.received, 0);
        assert!(hop.responders.is_empty());
    }
}

#[test]
fn test_destination_detection() {
    let mut session = test_session();
    let target_ip = session.target.resolved;

    // Simulate reaching the destination at TTL 4
    for ttl in 1..=4 {
        if let Some(hop) = session.hop_mut(ttl) {
            hop.record_sent();
            if ttl < 4 {
                // Intermediate hops
                let router = IpAddr::V4(Ipv4Addr::new(10, 0, 0, ttl));
                hop.record_response(router, Duration::from_millis(ttl as u64 * 5));
            } else {
                // Destination reached
                hop.record_response(target_ip, Duration::from_millis(20));
            }
        }
    }

    // Mark complete when destination is detected
    if let Some(hop) = session.hop(4) {
        if hop.primary == Some(target_ip) {
            session.complete = true;
            session.dest_ttl = Some(4);
        }
    }

    assert!(session.complete);
    assert_eq!(session.dest_ttl, Some(4));
}

#[test]
fn test_flow_path_tracking() {
    let mut session = test_session();

    let router = IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1));
    let rtt = Duration::from_millis(8);

    if let Some(hop) = session.hop_mut(2) {
        // Flow 0
        hop.record_flow_sent(0);
        hop.record_flow_response(0, router, rtt);

        // Flow 1
        hop.record_flow_sent(1);
        hop.record_flow_response(1, router, rtt);

        // Check flow paths were recorded
        assert!(hop.flow_paths.contains_key(&0));
        assert!(hop.flow_paths.contains_key(&1));

        let flow0 = hop.flow_paths.get(&0).unwrap();
        assert_eq!(flow0.sent, 1);
        assert_eq!(flow0.received, 1);
    }
}

#[test]
fn test_loss_calculation() {
    let mut session = test_session();

    let router = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

    if let Some(hop) = session.hop_mut(1) {
        // 4 probes: 3 responses, 1 timeout = 25% loss
        for _ in 0..3 {
            hop.record_sent();
            hop.record_response(router, Duration::from_millis(10));
        }
        hop.record_sent();
        hop.record_timeout();

        assert_eq!(hop.sent, 4);
        assert_eq!(hop.received, 3);
        assert_eq!(hop.timeouts, 1);

        let loss = hop.loss_pct();
        assert!((loss - 25.0).abs() < 0.1);
    }
}

#[test]
fn test_jitter_calculation() {
    let mut session = test_session();

    let router = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

    if let Some(hop) = session.hop_mut(1) {
        // Variable RTTs to create jitter
        hop.record_sent();
        hop.record_response(router, Duration::from_millis(10));

        hop.record_sent();
        hop.record_response(router, Duration::from_millis(20)); // +10ms

        hop.record_sent();
        hop.record_response(router, Duration::from_millis(15)); // -5ms

        hop.record_sent();
        hop.record_response(router, Duration::from_millis(25)); // +10ms

        let stats = hop.responders.get(&router).unwrap();

        // Jitter should be non-zero
        assert!(stats.jitter() > Duration::ZERO);
        assert!(stats.jitter_max() > Duration::ZERO);

        // Check RTT stats
        assert_eq!(stats.min_rtt, Duration::from_millis(10));
        assert_eq!(stats.max_rtt, Duration::from_millis(25));
    }
}

#[test]
fn test_serialization_roundtrip() {
    let mut session = test_session();

    let router = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
    if let Some(hop) = session.hop_mut(1) {
        hop.record_sent();
        hop.record_response(router, Duration::from_millis(5));
    }
    session.source_ip = Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)));
    session.gateway = Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));

    // Serialize to JSON
    let json = serde_json::to_string(&session).expect("serialize");

    // Deserialize back
    let loaded: Session = serde_json::from_str(&json).expect("deserialize");

    assert_eq!(loaded.target.original, session.target.original);
    assert_eq!(loaded.source_ip, session.source_ip);
    assert_eq!(loaded.gateway, session.gateway);

    if let Some(hop) = loaded.hop(1) {
        assert_eq!(hop.sent, 1);
        assert_eq!(hop.received, 1);
    }
}
