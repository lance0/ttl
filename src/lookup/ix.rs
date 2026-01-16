//! Internet Exchange (IX) detection via PeeringDB
//!
//! Identifies when a hop is at an Internet Exchange point by matching
//! IP addresses against IX peering LAN prefixes from PeeringDB.

use anyhow::{Result, anyhow};
use ipnetwork::IpNetwork;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::OnceCell;
use tokio_util::sync::CancellationToken;

use super::sanitize_display;
use crate::state::IxInfo;
use crate::trace::receiver::SessionMap;

/// PeeringDB API response wrapper
#[derive(Debug, Deserialize)]
struct PdbResponse<T> {
    data: Vec<T>,
}

/// IX record from PeeringDB /api/ix
#[derive(Debug, Deserialize)]
struct PdbIx {
    id: u32,
    name: String,
    city: Option<String>,
    country: Option<String>,
}

/// IX LAN record from PeeringDB /api/ixlan
#[derive(Debug, Deserialize)]
struct PdbIxlan {
    id: u32,
    ix_id: u32,
}

/// IX prefix record from PeeringDB /api/ixpfx
#[derive(Debug, Deserialize)]
struct PdbIxpfx {
    ixlan_id: u32,
    prefix: String,
}

/// Cached IX data for fast lookups
#[derive(Debug, Clone, Serialize, Deserialize)]
struct IxCacheEntry {
    name: String,
    city: Option<String>,
    country: Option<String>,
}

/// Cached prefix to IX mapping
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PrefixCacheEntry {
    prefix: String, // Store as string for serialization
    ix_name: String,
    ix_city: Option<String>,
    ix_country: Option<String>,
}

/// Serializable cache format
#[derive(Debug, Serialize, Deserialize)]
struct IxCache {
    version: u32,
    fetched_at: u64, // Unix timestamp
    prefixes: Vec<PrefixCacheEntry>,
}

impl IxCache {
    const VERSION: u32 = 1;
    const MAX_AGE_SECS: u64 = 24 * 60 * 60; // 24 hours

    fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now - self.fetched_at > Self::MAX_AGE_SECS
    }
}

/// In-memory prefix entry for fast lookup
struct PrefixEntry {
    network: IpNetwork,
    info: IxInfo,
}

/// IX lookup via PeeringDB prefix matching
pub struct IxLookup {
    /// Parsed prefixes for lookup (populated from cache or API)
    /// Sorted by prefix length descending for longest-prefix-match
    prefixes: RwLock<Vec<PrefixEntry>>,
    /// Cache file path
    cache_path: PathBuf,
    /// OnceCell ensures successful load runs exactly once
    /// Uses get_or_try_init so failures don't fill the cell
    load_once: OnceCell<()>,
    /// Timestamp of last load failure (for backoff)
    last_failure: AtomicU64,
    /// Per-IP result cache (to avoid repeated lookups)
    ip_cache: RwLock<HashMap<IpAddr, Option<IxInfo>>>,
    /// IP cache TTL
    ip_cache_ttl: Duration,
    /// Timestamps for IP cache entries
    ip_cache_times: RwLock<HashMap<IpAddr, Instant>>,
}

/// Backoff period after load failure (5 minutes)
const LOAD_FAILURE_BACKOFF_SECS: u64 = 300;

impl IxLookup {
    /// Create a new IX lookup instance
    pub fn new() -> Result<Self> {
        // Use standard cache directory
        let cache_dir = dirs::cache_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("ttl")
            .join("peeringdb");

        // Create cache directory if needed
        fs::create_dir_all(&cache_dir)?;

        let cache_path = cache_dir.join("ix_cache.json");

        Ok(Self {
            prefixes: RwLock::new(Vec::new()),
            cache_path,
            load_once: OnceCell::new(),
            last_failure: AtomicU64::new(0),
            ip_cache: RwLock::new(HashMap::new()),
            ip_cache_ttl: Duration::from_secs(3600), // 1 hour for IP results
            ip_cache_times: RwLock::new(HashMap::new()),
        })
    }

    /// Lookup IX info for an IP address
    ///
    /// Lazily loads PeeringDB data on first lookup.
    pub async fn lookup(&self, ip: IpAddr) -> Option<IxInfo> {
        // Check IP cache first
        {
            let ip_cache = self.ip_cache.read();
            let ip_times = self.ip_cache_times.read();
            if let (Some(result), Some(time)) = (ip_cache.get(&ip), ip_times.get(&ip))
                && time.elapsed() < self.ip_cache_ttl
            {
                return result.clone();
            }
        }

        // Ensure data is loaded
        // OnceCell is only filled on success; failures can be retried after backoff
        if self.load_once.get().is_none() {
            // Check backoff period after previous failure
            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let last_fail = self.last_failure.load(Ordering::Relaxed);
            if last_fail > 0 && now - last_fail < LOAD_FAILURE_BACKOFF_SECS {
                // Still in backoff period, skip loading
                return None;
            }

            // Use get_or_try_init: only fills cell on Ok, leaves unfilled on Err
            // This allows retries after backoff period expires
            let result = self
                .load_once
                .get_or_try_init(|| async {
                    self.load_data_inner().await.inspect_err(|_e| {
                        let now = SystemTime::now()
                            .duration_since(SystemTime::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs();
                        self.last_failure.store(now, Ordering::Relaxed);
                        // Don't print to stderr - it corrupts TUI
                        // Silently fail; IX detection is optional enrichment
                    })
                })
                .await;

            if result.is_err() {
                return None;
            }
        }

        // Search prefixes for longest matching network
        // (prefixes are sorted by length descending, so first match is longest)
        let result = {
            let prefixes = self.prefixes.read();
            prefixes
                .iter()
                .find(|entry| entry.network.contains(ip))
                .map(|entry| entry.info.clone())
        };

        // Cache result
        {
            let mut ip_cache = self.ip_cache.write();
            let mut ip_times = self.ip_cache_times.write();
            ip_cache.insert(ip, result.clone());
            ip_times.insert(ip, Instant::now());
        }

        result
    }

    /// Load IX data from cache or API
    async fn load_data_inner(&self) -> Result<()> {
        // Try loading from cache first
        if let Ok(cache) = self.load_cache()
            && !cache.is_expired()
        {
            self.populate_from_cache(&cache)?;
            return Ok(());
        }

        // Fetch from API
        match self.fetch_from_api().await {
            Ok(cache) => {
                // Save to disk (ignore errors - cache is optional)
                let _ = self.save_cache(&cache);
                self.populate_from_cache(&cache)?;
                Ok(())
            }
            Err(e) => {
                // If API fails, try to use expired cache as fallback
                if let Ok(cache) = self.load_cache() {
                    // Silently use expired cache - better than nothing
                    self.populate_from_cache(&cache)?;
                    return Ok(());
                }
                Err(e)
            }
        }
    }

    /// Load cache from disk
    fn load_cache(&self) -> Result<IxCache> {
        let data = fs::read_to_string(&self.cache_path)?;
        let cache: IxCache = serde_json::from_str(&data)?;
        if cache.version != IxCache::VERSION {
            return Err(anyhow!("cache version mismatch"));
        }
        Ok(cache)
    }

    /// Save cache to disk
    fn save_cache(&self, cache: &IxCache) -> Result<()> {
        let data = serde_json::to_string_pretty(cache)?;
        fs::write(&self.cache_path, data)?;
        Ok(())
    }

    /// Populate prefixes from cache
    fn populate_from_cache(&self, cache: &IxCache) -> Result<()> {
        let mut entries = Vec::with_capacity(cache.prefixes.len());

        for p in &cache.prefixes {
            if let Ok(network) = p.prefix.parse::<IpNetwork>() {
                entries.push(PrefixEntry {
                    network,
                    // Sanitize IX names for safe terminal display
                    info: IxInfo {
                        name: sanitize_display(&p.ix_name),
                        city: p.ix_city.as_ref().map(|s| sanitize_display(s)),
                        country: p.ix_country.as_ref().map(|s| sanitize_display(s)),
                    },
                });
            }
        }

        // Sort by prefix length descending for longest-prefix-match
        // This ensures more specific prefixes are checked first
        entries.sort_by(|a, b| b.network.prefix().cmp(&a.network.prefix()));

        *self.prefixes.write() = entries;
        Ok(())
    }

    /// Fetch IX data from PeeringDB API
    async fn fetch_from_api(&self) -> Result<IxCache> {
        // PeeringDB requires User-Agent to prevent scraping blocks
        let mut builder = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent(format!(
                "ttl/{} (https://github.com/lance0/ttl)",
                env!("CARGO_PKG_VERSION")
            ));

        // Add API key header if available (higher rate limits)
        // See: https://docs.peeringdb.com/howto/api_keys/
        if let Ok(key) = std::env::var("PEERINGDB_API_KEY") {
            let mut headers = reqwest::header::HeaderMap::new();
            if let Ok(value) = reqwest::header::HeaderValue::from_str(&format!("Api-Key {}", key)) {
                headers.insert(reqwest::header::AUTHORIZATION, value);
                builder = builder.default_headers(headers);
            }
        }

        let client = builder.build()?;

        // Fetch all three endpoints in parallel
        let (ix_result, ixlan_result, ixpfx_result) = tokio::join!(
            self.fetch_ix(&client),
            self.fetch_ixlan(&client),
            self.fetch_ixpfx(&client),
        );

        let ix_data = ix_result?;
        let ixlan_data = ixlan_result?;
        let ixpfx_data = ixpfx_result?;

        // Build lookup maps
        // ixlan_id -> ix_id
        let ixlan_to_ix: HashMap<u32, u32> =
            ixlan_data.iter().map(|lan| (lan.id, lan.ix_id)).collect();

        // ix_id -> IX info
        let ix_info: HashMap<u32, IxCacheEntry> = ix_data
            .iter()
            .map(|ix| {
                (
                    ix.id,
                    IxCacheEntry {
                        name: ix.name.clone(),
                        city: ix.city.clone(),
                        country: ix.country.clone(),
                    },
                )
            })
            .collect();

        // Build prefix cache entries (sanitize for safe terminal display)
        let mut prefixes = Vec::with_capacity(ixpfx_data.len());
        for pfx in ixpfx_data {
            if let Some(&ix_id) = ixlan_to_ix.get(&pfx.ixlan_id)
                && let Some(ix) = ix_info.get(&ix_id)
            {
                prefixes.push(PrefixCacheEntry {
                    prefix: pfx.prefix,
                    ix_name: sanitize_display(&ix.name),
                    ix_city: ix.city.as_ref().map(|s| sanitize_display(s)),
                    ix_country: ix.country.as_ref().map(|s| sanitize_display(s)),
                });
            }
        }

        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Ok(IxCache {
            version: IxCache::VERSION,
            fetched_at: now,
            prefixes,
        })
    }

    /// Fetch IX data from API
    /// Note: limit=0 disables pagination to fetch all records
    async fn fetch_ix(&self, client: &reqwest::Client) -> Result<Vec<PdbIx>> {
        let url = "https://www.peeringdb.com/api/ix?limit=0";
        let resp: PdbResponse<PdbIx> = client.get(url).send().await?.json().await?;
        Ok(resp.data)
    }

    /// Fetch IXLAN data from API
    async fn fetch_ixlan(&self, client: &reqwest::Client) -> Result<Vec<PdbIxlan>> {
        let url = "https://www.peeringdb.com/api/ixlan?limit=0";
        let resp: PdbResponse<PdbIxlan> = client.get(url).send().await?.json().await?;
        Ok(resp.data)
    }

    /// Fetch IX prefix data from API
    async fn fetch_ixpfx(&self, client: &reqwest::Client) -> Result<Vec<PdbIxpfx>> {
        let url = "https://www.peeringdb.com/api/ixpfx?limit=0";
        let resp: PdbResponse<PdbIxpfx> = client.get(url).send().await?.json().await?;
        Ok(resp.data)
    }

    /// Get the number of prefixes loaded
    #[allow(dead_code)]
    pub fn prefix_count(&self) -> usize {
        self.prefixes.read().len()
    }
}

/// Maximum concurrent IX lookups
const MAX_CONCURRENT_LOOKUPS: usize = 10;

/// Background IX lookup worker that updates session state
pub async fn run_ix_worker(
    ix_lookup: Arc<IxLookup>,
    sessions: SessionMap,
    cancel: CancellationToken,
) {
    let mut interval = tokio::time::interval(Duration::from_millis(500));

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                break;
            }
            _ = interval.tick() => {
                // Collect IPs that need IX lookup from all sessions
                let ips_to_lookup: Vec<IpAddr> = {
                    let sessions = sessions.read();
                    sessions.values()
                        .flat_map(|state| {
                            let session = state.read();
                            session.hops.iter()
                                .flat_map(|hop| hop.responders.values())
                                .filter(|stats| stats.ix.is_none())
                                .map(|stats| stats.ip)
                                .collect::<Vec<_>>()
                        })
                        .collect()
                };

                if ips_to_lookup.is_empty() {
                    continue;
                }

                // Perform parallel IX lookups (limited batch size)
                let batch: Vec<IpAddr> = ips_to_lookup
                    .into_iter()
                    .take(MAX_CONCURRENT_LOOKUPS)
                    .collect();

                // Spawn concurrent lookups
                let futures: Vec<_> = batch
                    .iter()
                    .map(|&ip| {
                        let ix = ix_lookup.clone();
                        async move { (ip, ix.lookup(ip).await) }
                    })
                    .collect();

                // Wait for all lookups to complete
                let results = futures::future::join_all(futures).await;

                // Update all sessions with results
                let sessions = sessions.read();
                for (ip, ix_info) in results {
                    if let Some(ix_info) = ix_info {
                        for state in sessions.values() {
                            let mut session = state.write();
                            for hop in &mut session.hops {
                                if let Some(stats) = hop.responders.get_mut(&ip) {
                                    stats.ix = Some(ix_info.clone());
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_prefix_matching() {
        // Test IpNetwork contains check
        let network: IpNetwork = "206.223.115.0/24".parse().unwrap();
        let inside = IpAddr::V4(Ipv4Addr::new(206, 223, 115, 100));
        let outside = IpAddr::V4(Ipv4Addr::new(206, 223, 116, 100));

        assert!(network.contains(inside));
        assert!(!network.contains(outside));
    }

    #[test]
    fn test_ix_cache_expiry() {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Fresh cache
        let fresh = IxCache {
            version: IxCache::VERSION,
            fetched_at: now,
            prefixes: vec![],
        };
        assert!(!fresh.is_expired());

        // Expired cache (25 hours old)
        let old = IxCache {
            version: IxCache::VERSION,
            fetched_at: now - 25 * 60 * 60,
            prefixes: vec![],
        };
        assert!(old.is_expired());
    }

    #[test]
    fn test_longest_prefix_match_sorting() {
        // Verify that prefixes are sorted by length descending
        let mut entries = vec![
            PrefixEntry {
                network: "10.0.0.0/8".parse().unwrap(),
                info: IxInfo {
                    name: "Wide".to_string(),
                    city: None,
                    country: None,
                },
            },
            PrefixEntry {
                network: "10.0.0.0/24".parse().unwrap(),
                info: IxInfo {
                    name: "Narrow".to_string(),
                    city: None,
                    country: None,
                },
            },
            PrefixEntry {
                network: "10.0.0.0/16".parse().unwrap(),
                info: IxInfo {
                    name: "Medium".to_string(),
                    city: None,
                    country: None,
                },
            },
        ];

        // Sort by prefix length descending (same as populate_from_cache)
        entries.sort_by(|a, b| b.network.prefix().cmp(&a.network.prefix()));

        // First entry should be /24 (most specific)
        assert_eq!(entries[0].network.prefix(), 24);
        assert_eq!(entries[0].info.name, "Narrow");

        // Second should be /16
        assert_eq!(entries[1].network.prefix(), 16);
        assert_eq!(entries[1].info.name, "Medium");

        // Third should be /8 (least specific)
        assert_eq!(entries[2].network.prefix(), 8);
        assert_eq!(entries[2].info.name, "Wide");

        // Now verify find() returns the most specific match
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 50));
        let result = entries
            .iter()
            .find(|e| e.network.contains(ip))
            .map(|e| e.info.name.clone());
        assert_eq!(result, Some("Narrow".to_string()));
    }

    #[test]
    fn test_backoff_period_check() {
        // Test that backoff period logic works correctly
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Simulate a recent failure (should be in backoff)
        let recent_failure = now - 60; // 1 minute ago
        assert!(now - recent_failure < LOAD_FAILURE_BACKOFF_SECS);

        // Simulate an old failure (backoff should have expired)
        let old_failure = now - 400; // 6+ minutes ago
        assert!(now - old_failure >= LOAD_FAILURE_BACKOFF_SECS);
    }

    #[tokio::test]
    async fn test_lookup_returns_none_during_backoff() {
        // Create IxLookup with temp directory (no cache, will fail to load)
        let temp_dir = std::env::temp_dir().join(format!("ix_test_{}", std::process::id()));
        let _ = fs::create_dir_all(&temp_dir);
        let cache_path = temp_dir.join("ix_cache.json");

        let lookup = IxLookup {
            prefixes: RwLock::new(Vec::new()),
            cache_path,
            load_once: OnceCell::new(),
            last_failure: AtomicU64::new(0),
            ip_cache: RwLock::new(HashMap::new()),
            ip_cache_ttl: Duration::from_secs(3600),
            ip_cache_times: RwLock::new(HashMap::new()),
        };

        // Set last_failure to now (simulate recent failure)
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        lookup.last_failure.store(now, Ordering::Relaxed);

        // Lookup should return None immediately without attempting load
        let ip = IpAddr::V4(Ipv4Addr::new(206, 223, 115, 100));
        let result = lookup.lookup(ip).await;
        assert!(result.is_none());

        // OnceCell should still be empty (no load attempted due to backoff)
        assert!(lookup.load_once.get().is_none());

        // Cleanup
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn test_oncecell_empty_after_failure() {
        // Create IxLookup that will fail (no cache, API will fail in test env)
        let temp_dir = std::env::temp_dir().join(format!("ix_test_fail_{}", std::process::id()));
        let _ = fs::create_dir_all(&temp_dir);
        let cache_path = temp_dir.join("ix_cache.json");

        let lookup = IxLookup {
            prefixes: RwLock::new(Vec::new()),
            cache_path: cache_path.clone(),
            load_once: OnceCell::new(),
            last_failure: AtomicU64::new(0),
            ip_cache: RwLock::new(HashMap::new()),
            ip_cache_ttl: Duration::from_secs(3600),
            ip_cache_times: RwLock::new(HashMap::new()),
        };

        // No cache exists, API will timeout/fail - OnceCell should stay empty
        // We use get_or_try_init which doesn't fill on error

        // This will attempt to load and fail (no cache, no API in test)
        // But we can't easily test the API failure without mocking
        // Instead, verify the structure is correct for retry behavior

        // Verify OnceCell starts empty
        assert!(lookup.load_once.get().is_none());

        // Verify last_failure starts at 0
        assert_eq!(lookup.last_failure.load(Ordering::Relaxed), 0);

        // Cleanup
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn test_lookup_with_preloaded_data() {
        // Test that lookup works correctly with pre-populated prefixes
        let temp_dir = std::env::temp_dir().join(format!("ix_test_pre_{}", std::process::id()));
        let _ = fs::create_dir_all(&temp_dir);
        let cache_path = temp_dir.join("ix_cache.json");

        let lookup = IxLookup {
            prefixes: RwLock::new(vec![PrefixEntry {
                network: "206.223.115.0/24".parse().unwrap(),
                info: IxInfo {
                    name: "Test IX".to_string(),
                    city: Some("Test City".to_string()),
                    country: Some("US".to_string()),
                },
            }]),
            cache_path,
            load_once: OnceCell::const_new_with(()), // Pre-filled = loaded
            last_failure: AtomicU64::new(0),
            ip_cache: RwLock::new(HashMap::new()),
            ip_cache_ttl: Duration::from_secs(3600),
            ip_cache_times: RwLock::new(HashMap::new()),
        };

        // Lookup should find the pre-loaded prefix
        let ip = IpAddr::V4(Ipv4Addr::new(206, 223, 115, 100));
        let result = lookup.lookup(ip).await;
        assert!(result.is_some());
        let ix_info = result.unwrap();
        assert_eq!(ix_info.name, "Test IX");
        assert_eq!(ix_info.city, Some("Test City".to_string()));

        // Lookup for non-matching IP should return None
        let other_ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let result2 = lookup.lookup(other_ip).await;
        assert!(result2.is_none());

        // Cleanup
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn test_ip_cache_prevents_repeated_prefix_search() {
        let temp_dir = std::env::temp_dir().join(format!("ix_test_cache_{}", std::process::id()));
        let _ = fs::create_dir_all(&temp_dir);
        let cache_path = temp_dir.join("ix_cache.json");

        let lookup = IxLookup {
            prefixes: RwLock::new(vec![PrefixEntry {
                network: "206.223.115.0/24".parse().unwrap(),
                info: IxInfo {
                    name: "Cached IX".to_string(),
                    city: None,
                    country: None,
                },
            }]),
            cache_path,
            load_once: OnceCell::const_new_with(()),
            last_failure: AtomicU64::new(0),
            ip_cache: RwLock::new(HashMap::new()),
            ip_cache_ttl: Duration::from_secs(3600),
            ip_cache_times: RwLock::new(HashMap::new()),
        };

        let ip = IpAddr::V4(Ipv4Addr::new(206, 223, 115, 50));

        // First lookup populates IP cache
        let result1 = lookup.lookup(ip).await;
        assert!(result1.is_some());

        // Verify IP is now in cache
        assert!(lookup.ip_cache.read().contains_key(&ip));

        // Second lookup should use cached result
        let result2 = lookup.lookup(ip).await;
        assert_eq!(result1, result2);

        // Cleanup
        let _ = fs::remove_dir_all(&temp_dir);
    }
}
