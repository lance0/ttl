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
}

/// Key for pending probe lookup: (ProbeId, flow_id)
///
/// Flow ID is included in the key because multi-flow mode sends the same ProbeId
/// for each flow per tick. Without flow_id in the key, entries would overwrite
/// each other, causing incorrect flow attribution.
pub type PendingKey = (ProbeId, u8);

/// Thread-safe map of pending probes keyed by (ProbeId, flow_id)
pub type PendingMap = Arc<RwLock<HashMap<PendingKey, PendingProbe>>>;

/// Create a new empty pending map
pub fn new_pending_map() -> PendingMap {
    Arc::new(RwLock::new(HashMap::new()))
}
