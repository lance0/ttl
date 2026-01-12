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
}

/// Thread-safe map of pending probes
pub type PendingMap = Arc<RwLock<HashMap<ProbeId, PendingProbe>>>;

/// Create a new empty pending map
pub fn new_pending_map() -> PendingMap {
    Arc::new(RwLock::new(HashMap::new()))
}
