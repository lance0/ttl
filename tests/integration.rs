//! Integration tests for probe→receive→state pipeline
//!
//! These tests verify the data flow from simulated probe sends
//! through state updates, without requiring actual network access.

use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use ttl::config::Config;
use ttl::state::session::{PmtudPhase, PmtudState, Session, Target};

/// Create a test session for 8.8.8.8 with default config
fn test_session() -> Session {
    let target = Target::new("8.8.8.8".to_string(), IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
    let config = Config::default();
    Session::new(target, config)
}

/// Create a test session with PMTUD enabled
fn test_session_with_pmtud() -> Session {
    let target = Target::new("8.8.8.8".to_string(), IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
    let mut config = Config::default();
    config.pmtud = true;
    Session::new(target, config)
}

/// Create an IPv6 test session with PMTUD enabled
fn test_session_ipv6_with_pmtud() -> Session {
    let target = Target::new(
        "2001:4860:4860::8888".to_string(),
        IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888)),
    );
    let mut config = Config::default();
    config.pmtud = true;
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

#[test]
fn test_pmtud_state_lifecycle() {
    let mut session = test_session_with_pmtud();

    // PMTUD should be initialized
    assert!(session.pmtud.is_some());
    let pmtud = session.pmtud.as_ref().unwrap();
    assert_eq!(pmtud.phase, PmtudPhase::WaitingForDestination);
    assert_eq!(pmtud.min_size, 68); // IPv4 minimum
    assert_eq!(pmtud.max_size, 1500);
    assert_eq!(pmtud.discovered_mtu, None);

    // Simulate PMTUD progress
    if let Some(pmtud) = session.pmtud.as_mut() {
        pmtud.start_search();
        assert_eq!(pmtud.phase, PmtudPhase::Searching);

        // Record some successes/failures
        pmtud.record_success();
        pmtud.record_success(); // 2 consecutive successes raise min_size
        assert!(pmtud.min_size > 68);
    }

    // Reset should reinitialize PMTUD state
    session.reset_stats();

    assert!(session.pmtud.is_some());
    let pmtud = session.pmtud.as_ref().unwrap();
    assert_eq!(pmtud.phase, PmtudPhase::WaitingForDestination);
    assert_eq!(pmtud.min_size, 68);
    assert_eq!(pmtud.max_size, 1500);
    assert_eq!(pmtud.discovered_mtu, None);
}

#[test]
fn test_pmtud_binary_search_convergence() {
    let mut session = test_session_with_pmtud();

    if let Some(pmtud) = session.pmtud.as_mut() {
        pmtud.start_search();

        // Simulate fragmentation needed at 1400
        pmtud.record_frag_needed(1400);
        assert!(pmtud.max_size <= 1400);

        // Continue binary search until converged
        while !pmtud.is_converged() && pmtud.phase == PmtudPhase::Searching {
            // Simulate: sizes <= 1400 succeed, > 1400 fail
            if pmtud.current_size <= 1400 {
                pmtud.record_success();
                pmtud.record_success();
            } else {
                pmtud.record_failure();
                pmtud.record_failure();
            }
        }

        assert_eq!(pmtud.phase, PmtudPhase::Complete);
        assert!(pmtud.discovered_mtu.is_some());
        // Should converge near 1400 (within 8 bytes)
        let mtu = pmtud.discovered_mtu.unwrap();
        assert!(mtu >= 1392 && mtu <= 1400);
    }
}

#[test]
fn test_pmtud_ipv6_min_size() {
    let session = test_session_ipv6_with_pmtud();

    // IPv6 PMTUD should use 1280 as minimum (RFC 8200)
    assert!(session.pmtud.is_some());
    let pmtud = session.pmtud.as_ref().unwrap();
    assert_eq!(pmtud.min_size, 1280);
    assert_eq!(pmtud.max_size, 1500);
    assert_eq!(pmtud.phase, PmtudPhase::WaitingForDestination);
}

#[test]
fn test_pmtud_frag_needed_below_min() {
    // Test that record_frag_needed clamps to reported MTU even if below typical min
    let mut pmtud = PmtudState::new(false); // IPv4
    pmtud.start_search();

    // Router reports MTU of 576 (old internet minimum)
    pmtud.record_frag_needed(576);

    // max_size should be clamped to 576
    assert_eq!(pmtud.max_size, 576);

    // min_size stays at 68 (IPv4 absolute minimum)
    assert_eq!(pmtud.min_size, 68);

    // Binary search should continue in valid range
    assert!(pmtud.current_size <= 576);
    assert!(pmtud.current_size >= 68);
}

#[test]
fn test_pmtud_frag_needed_at_min() {
    // Edge case: reported MTU equals or is below min_size
    let mut pmtud = PmtudState::new(true); // IPv6, min=1280
    pmtud.start_search();

    // Router reports exactly 1280
    pmtud.record_frag_needed(1280);

    assert_eq!(pmtud.max_size, 1280);
    assert_eq!(pmtud.min_size, 1280);

    // Should immediately converge since min == max
    assert!(pmtud.is_converged());
}

#[test]
fn test_pmtud_frag_needed_above_max() {
    // Edge case: router reports MTU > 1500 (jumbo frames or bogus value)
    let mut pmtud = PmtudState::new(false); // IPv4
    pmtud.start_search();

    // Router reports 9000 (jumbo frame MTU)
    pmtud.record_frag_needed(9000);

    // max_size should stay at 1500 (min of current max and reported)
    assert_eq!(pmtud.max_size, 1500);

    // Search continues normally
    assert_eq!(pmtud.phase, PmtudPhase::Searching);
}

#[test]
fn test_pmtud_ipv6_convergence() {
    // Full IPv6 PMTUD cycle with realistic MTU
    let mut pmtud = PmtudState::new(true); // IPv6, min=1280
    pmtud.start_search();

    // Simulate link with 1400 byte MTU (common for tunnels)
    pmtud.record_frag_needed(1400);
    assert!(pmtud.max_size <= 1400);

    // Binary search to convergence
    while !pmtud.is_converged() && pmtud.phase == PmtudPhase::Searching {
        if pmtud.current_size <= 1400 {
            pmtud.record_success();
            pmtud.record_success();
        } else {
            pmtud.record_failure();
            pmtud.record_failure();
        }
    }

    assert_eq!(pmtud.phase, PmtudPhase::Complete);
    let mtu = pmtud.discovered_mtu.unwrap();
    // Should converge between 1280 and 1400
    assert!(mtu >= 1280 && mtu <= 1400);
}

#[test]
fn test_session_json_file_roundtrip() {
    let mut session = test_session_with_pmtud();

    // Populate session with realistic data
    let router1 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
    let router2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let target = session.target.resolved;

    // Hop 1: gateway
    if let Some(hop) = session.hop_mut(1) {
        hop.record_sent();
        hop.record_response(router1, Duration::from_millis(2));
    }

    // Hop 2: ISP router
    if let Some(hop) = session.hop_mut(2) {
        hop.record_sent();
        hop.record_response(router2, Duration::from_millis(10));
        hop.record_sent();
        hop.record_timeout(); // Some loss
    }

    // Hop 3: destination
    if let Some(hop) = session.hop_mut(3) {
        hop.record_sent();
        hop.record_response(target, Duration::from_millis(15));
    }

    session.complete = true;
    session.dest_ttl = Some(3);
    session.total_sent = 4;
    session.source_ip = Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)));
    session.gateway = Some(router1);

    // Advance PMTUD state
    if let Some(pmtud) = session.pmtud.as_mut() {
        pmtud.start_search();
        pmtud.record_frag_needed(1400);
    }

    // Save to temp file with unique name (pid + timestamp to avoid parallel test collisions)
    let temp_path = std::env::temp_dir().join(format!(
        "ttl_test_session_{}_{}.json",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let json = serde_json::to_string_pretty(&session).expect("serialize");
    fs::write(&temp_path, &json).expect("write file");

    // Load from file
    let loaded_json = fs::read_to_string(&temp_path).expect("read file");
    let loaded: Session = serde_json::from_str(&loaded_json).expect("deserialize");

    // Verify all fields preserved
    assert_eq!(loaded.target.original, "8.8.8.8");
    assert_eq!(loaded.complete, true);
    assert_eq!(loaded.dest_ttl, Some(3));
    assert_eq!(loaded.total_sent, 4);
    assert_eq!(loaded.source_ip, session.source_ip);
    assert_eq!(loaded.gateway, session.gateway);

    // Verify hop data
    assert_eq!(loaded.hop(1).unwrap().received, 1);
    assert_eq!(loaded.hop(2).unwrap().timeouts, 1);
    assert_eq!(loaded.hop(3).unwrap().primary, Some(target));

    // Verify PMTUD state
    assert!(loaded.pmtud.is_some());
    let pmtud = loaded.pmtud.as_ref().unwrap();
    assert_eq!(pmtud.phase, PmtudPhase::Searching);
    assert!(pmtud.max_size <= 1400);

    // Cleanup
    let _ = fs::remove_file(&temp_path);
}
