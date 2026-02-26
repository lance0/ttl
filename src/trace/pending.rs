//! Shared pending probe tracking.
//!
//! This module provides a shared map of pending probes that both the engine
//! and receiver can access. The engine inserts entries before sending probes,
//! and the receiver removes them when responses arrive.

use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use crate::state::ProbeId;

/// A probe that has been sent and is awaiting a response
#[derive(Debug, Clone)]
pub struct PendingProbe {
    pub sent_at: Instant,
    pub target: IpAddr,
    /// Flow ID for Paris/Dublin traceroute ECMP detection (0 for single-flow mode)
    pub flow_id: u8,
    /// Original source port for NAT detection (UDP/TCP only, None for ICMP)
    pub original_src_port: Option<u16>,
    /// Packet size for PMTUD correlation (only set during PMTUD phase)
    pub packet_size: Option<u16>,
}

/// Key for pending probe lookup: (ProbeId, flow_id, target, is_pmtud)
///
/// Flow ID is included in the key because multi-flow mode sends the same ProbeId
/// for each flow per tick. Without flow_id in the key, entries would overwrite
/// each other, causing incorrect flow attribution.
///
/// Target is included to support multiple simultaneous targets - each target
/// has independent probe sequences.
///
/// is_pmtud distinguishes PMTUD probes from normal probes, preventing collision
/// when both use the same ProbeId (e.g., when dest discovered at tick N and
/// PMTUD seq wraps to N).
pub type PendingKey = (ProbeId, u8, IpAddr, bool);

/// Thread-safe map of pending probes keyed by (ProbeId, flow_id, target, is_pmtud)
pub type PendingMap = Arc<RwLock<HashMap<PendingKey, PendingProbe>>>;

/// Create a new empty pending map
pub fn new_pending_map() -> PendingMap {
    Arc::new(RwLock::new(HashMap::new()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_pending_map_multi_target_isolation() {
        let pending = new_pending_map();
        let probe_id = ProbeId::new(5, 0);
        let target1 = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let target2 = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));

        {
            let mut map = pending.write();
            for target in [target1, target2] {
                map.insert(
                    (probe_id, 0, target, false),
                    PendingProbe {
                        sent_at: Instant::now(),
                        target,
                        flow_id: 0,
                        original_src_port: None,
                        packet_size: None,
                    },
                );
            }
        }

        // Both targets coexist with same ProbeId
        let map = pending.read();
        assert_eq!(map.len(), 2);
        assert!(map.contains_key(&(probe_id, 0, target1, false)));
        assert!(map.contains_key(&(probe_id, 0, target2, false)));
        drop(map);

        // Removing one doesn't affect the other
        let mut map = pending.write();
        map.remove(&(probe_id, 0, target1, false));
        assert_eq!(map.len(), 1);
        assert!(map.contains_key(&(probe_id, 0, target2, false)));
    }

    #[test]
    fn test_pending_map_flow_isolation() {
        let pending = new_pending_map();
        let probe_id = ProbeId::new(3, 0);
        let target = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));

        {
            let mut map = pending.write();
            for flow_id in 0..4u8 {
                map.insert(
                    (probe_id, flow_id, target, false),
                    PendingProbe {
                        sent_at: Instant::now(),
                        target,
                        flow_id,
                        original_src_port: None,
                        packet_size: None,
                    },
                );
            }
        }

        let map = pending.read();
        assert_eq!(map.len(), 4);
        for flow_id in 0..4u8 {
            assert!(map.contains_key(&(probe_id, flow_id, target, false)));
        }
    }

    #[test]
    fn test_pending_map_pmtud_isolation() {
        let pending = new_pending_map();
        let probe_id = ProbeId::new(7, 1);
        let target = IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4));

        {
            let mut map = pending.write();
            map.insert(
                (probe_id, 0, target, false),
                PendingProbe {
                    sent_at: Instant::now(),
                    target,
                    flow_id: 0,
                    original_src_port: None,
                    packet_size: None,
                },
            );
            map.insert(
                (probe_id, 0, target, true),
                PendingProbe {
                    sent_at: Instant::now(),
                    target,
                    flow_id: 0,
                    original_src_port: None,
                    packet_size: Some(1400),
                },
            );
        }

        let map = pending.read();
        assert_eq!(map.len(), 2);
        assert!(map.contains_key(&(probe_id, 0, target, false)));
        assert!(map.contains_key(&(probe_id, 0, target, true)));
    }
}
