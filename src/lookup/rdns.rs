use anyhow::Result;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

use crate::trace::SessionMap;

/// DNS cache entry
struct CacheEntry {
    hostname: Option<String>,
    cached_at: Instant,
}

/// DNS lookup worker with caching
pub struct DnsLookup {
    resolver: TokioAsyncResolver,
    cache: RwLock<HashMap<IpAddr, CacheEntry>>,
    cache_ttl: Duration,
}

impl DnsLookup {
    pub async fn new() -> Result<Self> {
        let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

        Ok(Self {
            resolver,
            cache: RwLock::new(HashMap::new()),
            cache_ttl: Duration::from_secs(3600), // 1 hour
        })
    }

    /// Lookup reverse DNS for an IP, using cache
    pub async fn reverse_lookup(&self, ip: IpAddr) -> Option<String> {
        // Check cache first
        {
            let cache = self.cache.read();
            if let Some(entry) = cache.get(&ip) {
                if entry.cached_at.elapsed() < self.cache_ttl {
                    return entry.hostname.clone();
                }
            }
        }

        // Perform lookup
        let hostname = match self.resolver.reverse_lookup(ip).await {
            Ok(lookup) => lookup.iter().next().map(|name| {
                let s = name.to_string();
                // Remove trailing dot
                s.trim_end_matches('.').to_string()
            }),
            Err(_) => None,
        };

        // Cache result
        {
            let mut cache = self.cache.write();
            cache.insert(
                ip,
                CacheEntry {
                    hostname: hostname.clone(),
                    cached_at: Instant::now(),
                },
            );
        }

        hostname
    }
}

/// Maximum concurrent DNS lookups
const MAX_CONCURRENT_LOOKUPS: usize = 10;

/// Background DNS lookup worker that updates session state (multi-target)
pub async fn run_dns_worker(
    dns: Arc<DnsLookup>,
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
                // Collect IPs that need lookup from all sessions
                let ips_to_lookup: Vec<IpAddr> = {
                    let sessions = sessions.read();
                    sessions.values()
                        .flat_map(|state| {
                            let session = state.read();
                            session.hops.iter()
                                .flat_map(|hop| hop.responders.values())
                                .filter(|stats| stats.hostname.is_none())
                                .map(|stats| stats.ip)
                                .collect::<Vec<_>>()
                        })
                        .collect()
                };

                if ips_to_lookup.is_empty() {
                    continue;
                }

                // Perform parallel DNS lookups (limited batch size)
                let batch: Vec<IpAddr> = ips_to_lookup
                    .into_iter()
                    .take(MAX_CONCURRENT_LOOKUPS)
                    .collect();

                // Spawn concurrent lookups
                let futures: Vec<_> = batch
                    .iter()
                    .map(|&ip| {
                        let dns = dns.clone();
                        async move { (ip, dns.reverse_lookup(ip).await) }
                    })
                    .collect();

                // Wait for all lookups to complete
                let results = futures::future::join_all(futures).await;

                // Update all sessions with results
                let sessions = sessions.read();
                for (ip, hostname) in results {
                    if let Some(hostname) = hostname {
                        for state in sessions.values() {
                            let mut session = state.write();
                            for hop in &mut session.hops {
                                if let Some(stats) = hop.responders.get_mut(&ip) {
                                    stats.hostname = Some(hostname.clone());
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
