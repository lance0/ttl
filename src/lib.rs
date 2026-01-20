//! # ttl
//!
//! Modern traceroute/mtr-style network path analyzer with a real-time TUI.
//!
//! ## Features
//!
//! - Continuous path monitoring with per-hop latency statistics
//! - ICMP, UDP, and TCP probing modes
//! - Multi-flow probing for ECMP path enumeration (Paris/Dublin traceroute)
//! - Path MTU discovery via binary search
//! - ASN, GeoIP, reverse DNS, and IX enrichment
//! - MPLS label detection from ICMP extensions
//! - Route flap and NAT detection
//!
//! ## Library Usage
//!
//! The public API exposes session state and export functionality:
//!
//! ```no_run
//! use ttl::state::Session;
//! use ttl::export::{export_json_string, export_csv};
//!
//! // Load a saved session
//! let json_data = std::fs::read_to_string("session.json").unwrap();
//! let session: Session = serde_json::from_str(&json_data).unwrap();
//!
//! // Export to JSON string
//! let json_export = export_json_string(&session).unwrap();
//!
//! // Export CSV to a writer
//! let mut csv_output = Vec::new();
//! export_csv(&session, &mut csv_output).unwrap();
//! ```
//!
//! ## CLI Usage
//!
//! ```bash
//! sudo ttl 8.8.8.8              # Basic trace
//! sudo ttl -p udp google.com    # UDP probes
//! sudo ttl --flows 4 host       # ECMP path discovery
//! ```

// Public API - data types and export functions
pub mod config;
pub mod export;
pub mod state;

// Internal implementation - not part of public API
// These modules are used by the binary but not exported from the lib
#[allow(dead_code)]
pub(crate) mod cli;
#[allow(dead_code)]
pub(crate) mod lookup;
#[allow(dead_code)]
pub(crate) mod prefs;
#[allow(dead_code)]
pub(crate) mod probe;
#[allow(dead_code)]
pub(crate) mod trace;
#[allow(dead_code)]
pub(crate) mod tui;
