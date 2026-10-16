use anyhow::Result;
use hickory_resolver::config::{GOOGLE, ResolverConfig};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::RData;
use hickory_resolver::{Resolver, TokioResolver};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

use super::sanitize_display;
use crate::trace::receiver::SessionMap;

/// DNS cache entry
struct CacheEntry {
    hostname: Option<String>,
    cached_at: Instant,
}

/// DNS lookup worker with caching
pub struct DnsLookup {
    resolver: TokioResolver,
    cache: RwLock<HashMap<IpAddr, CacheEntry>>,
    cache_ttl: Duration,
}

impl DnsLookup {
    pub async fn new() -> Result<Self> {
        // Try system DNS config first, fall back to Google DNS if unavailable.
        // Any failure in the system path (config detection or resolver build)
        // triggers the fallback so a transient setup error doesn't kill startup.
        let resolver = match Resolver::builder_tokio().and_then(|b| b.build()) {
            Ok(r) => r,
            Err(_) => {
                eprintln!("Warning: System DNS config unavailable, using Google DNS (8.8.8.8)");
                Resolver::builder_with_config(
                    ResolverConfig::udp_and_tcp(&GOOGLE),
                    TokioRuntimeProvider::default(),
                )
                .build()?
            }
        };

        Ok(Self {
            resolver,
            cache: RwLock::new(HashMap::new()),
            cache_ttl: Duration::from_secs(3600), // 1 hour
        })
    }

    /// A fresh cached miss must not consume a worker batch slot.
    fn needs_lookup(&self, ip: IpAddr) -> bool {
        !self.cache.read().get(&ip).is_some_and(|entry| {
            entry.hostname.is_none()
                && entry.cached_at.elapsed() < self.cache_ttl.min(super::NEGATIVE_CACHE_TTL)
        })
    }

    /// Lookup reverse DNS for an IP, using cache
    pub async fn reverse_lookup(&self, ip: IpAddr) -> Option<String> {
        // Check cache first
        {
            let cache = self.cache.read();
            if let Some(entry) = cache.get(&ip)
                && entry.cached_at.elapsed()
                    < if entry.hostname.is_some() {
                        self.cache_ttl
                    } else {
                        self.cache_ttl.min(super::NEGATIVE_CACHE_TTL)
                    }
            {
                return entry.hostname.clone();
            }
        }

        // Perform lookup
        let hostname = match self.resolver.reverse_lookup(ip).await {
            Ok(lookup) => lookup
                .answers()
                .iter()
                .find_map(|record| match &record.data {
                    RData::PTR(name) => {
                        let s = name.to_string();
                        // Remove trailing dot and sanitize for safe display
                        // (PTR records can contain malicious control sequences)
                        Some(sanitize_display(s.trim_end_matches('.')))
                    }
                    _ => None,
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
            // Evict stale/overflow entries to keep the cache bounded.
            super::prune_cache(
                &mut cache,
                self.cache_ttl,
                |e| e.cached_at,
                |e, ttl| {
                    e.cached_at.elapsed()
                        >= if e.hostname.is_some() {
                            ttl
                        } else {
                            ttl.min(super::NEGATIVE_CACHE_TTL)
                        }
                },
            );
        }

        hostname
    }
}

/// Maximum concurrent DNS lookups
const MAX_CONCURRENT_LOOKUPS: usize = 10;

/// Background DNS lookup worker that updates session state (multi-target)
pub async fn run_dns_worker(dns: Arc<DnsLookup>, sessions: SessionMap, cancel: CancellationToken) {
    let mut interval = tokio::time::interval(Duration::from_millis(500));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                break;
            }
            _ = interval.tick() => {
                let batch = super::collect_lookup_batch(&sessions, MAX_CONCURRENT_LOOKUPS,
                    |stats| stats.hostname.is_none(), |ip| dns.needs_lookup(ip));

                if batch.is_empty() {
                    continue;
                }

                // Spawn concurrent lookups
                let futures: Vec<_> = batch
                    .iter()
                    .map(|&ip| {
                        let dns = dns.clone();
                        async move { (ip, dns.reverse_lookup(ip).await) }
                    })
                    .collect();

                // Wait for all lookups to complete
                let Some(results) = super::lookup_batch(&cancel, futures).await else { break; };

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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn negative_results_do_not_starve_later_hops() {
        let lookup = Arc::new(DnsLookup::new().await.unwrap());
        for n in 1..=20 {
            let ip = format!("10.0.0.{n}").parse().unwrap();
            let value = if n <= 10 {
                None
            } else {
                Some("router.example.test".to_string())
            };
            lookup.cache.write().insert(
                ip,
                CacheEntry {
                    hostname: value,
                    cached_at: Instant::now(),
                },
            );
        }
        let sessions = super::super::tests::unenriched_sessions();
        let cancel = CancellationToken::new();
        super::super::tests::assert_worker_progress(
            sessions.clone(),
            run_dns_worker(lookup, sessions.clone(), cancel.clone()),
            cancel,
            |stats| stats.hostname.is_some(),
        )
        .await;
    }

    #[tokio::test]
    async fn negative_cache_retries_after_a_minute_without_expiring_positive_results() {
        let lookup = DnsLookup::new().await.unwrap();
        let ip = "192.0.2.1".parse().unwrap();
        lookup.cache.write().insert(
            ip,
            CacheEntry {
                hostname: None,
                cached_at: Instant::now(),
            },
        );
        assert!(!lookup.needs_lookup(ip));
        lookup.cache.write().get_mut(&ip).unwrap().cached_at =
            Instant::now() - Duration::from_secs(61);
        assert!(lookup.needs_lookup(ip));
        lookup.cache.write().insert(
            ip,
            CacheEntry {
                hostname: Some("router.example.test".to_string()),
                cached_at: Instant::now() - Duration::from_secs(61),
            },
        );
        assert!(lookup.reverse_lookup(ip).await.is_some());
    }
}
