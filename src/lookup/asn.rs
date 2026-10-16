use anyhow::Result;
use hickory_resolver::config::{GOOGLE, ResolverConfig};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::RData;
use hickory_resolver::{Resolver, TokioResolver};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

use super::sanitize_display;
use crate::state::AsnInfo;
use crate::trace::receiver::SessionMap;

/// ASN cache entry
struct CacheEntry {
    asn: Option<AsnInfo>,
    cached_at: Instant,
}

/// ASN lookup via Team Cymru DNS
pub struct AsnLookup {
    resolver: TokioResolver,
    cache: RwLock<HashMap<IpAddr, CacheEntry>>,
    cache_ttl: Duration,
}

impl AsnLookup {
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
        !self
            .cache
            .read()
            .get(&ip)
            .is_some_and(|entry| entry.asn.is_none() && entry.cached_at.elapsed() < self.cache_ttl)
    }

    /// Lookup ASN info for an IP via Team Cymru DNS
    pub async fn lookup(&self, ip: IpAddr) -> Option<AsnInfo> {
        // Check cache first
        {
            let cache = self.cache.read();
            if let Some(entry) = cache.get(&ip)
                && entry.cached_at.elapsed() < self.cache_ttl
            {
                return entry.asn.clone();
            }
        }

        // Perform lookup
        let asn = self.do_lookup(ip).await;

        // Cache result
        {
            let mut cache = self.cache.write();
            cache.insert(
                ip,
                CacheEntry {
                    asn: asn.clone(),
                    cached_at: Instant::now(),
                },
            );
            // Evict stale/overflow entries to keep the cache bounded.
            super::prune_cache(
                &mut cache,
                self.cache_ttl,
                |e| e.cached_at,
                |e, ttl| e.cached_at.elapsed() >= ttl,
            );
        }

        asn
    }

    /// Perform the actual DNS lookup
    async fn do_lookup(&self, ip: IpAddr) -> Option<AsnInfo> {
        // Build the query name for origin lookup
        let query_name = self.build_origin_query(ip);

        // Query TXT record at <reversed_ip>.origin.asn.cymru.com
        let txt_records = self.resolver.txt_lookup(&query_name).await.ok()?;

        // Parse the first TXT record (see `parse_origin_txt` for the format)
        let txt = txt_records
            .answers()
            .iter()
            .find_map(|record| match &record.data {
                RData::TXT(txt) => Some(txt),
                _ => None,
            })?;

        // TXT records may be quoted or split into multiple strings - join and strip quotes
        let txt_str: String = txt
            .txt_data
            .iter()
            .filter_map(|bytes| std::str::from_utf8(bytes).ok())
            .collect::<Vec<_>>()
            .join("");
        let txt_str = txt_str.trim_matches('"');

        let (asn_number, prefix) = parse_origin_txt(txt_str)?;

        // Now lookup the AS name
        let as_name = self.lookup_as_name(asn_number).await;

        Some(AsnInfo {
            number: asn_number,
            name: as_name.unwrap_or_else(|| format!("AS{}", asn_number)),
            prefix,
        })
    }

    /// Build the DNS query name for origin lookup
    fn build_origin_query(&self, ip: IpAddr) -> String {
        match ip {
            IpAddr::V4(ipv4) => self.build_ipv4_origin_query(ipv4),
            IpAddr::V6(ipv6) => self.build_ipv6_origin_query(ipv6),
        }
    }

    /// Build IPv4 origin query (reverse octets)
    /// 8.8.8.8 -> "8.8.8.8.origin.asn.cymru.com"
    fn build_ipv4_origin_query(&self, ip: Ipv4Addr) -> String {
        let octets = ip.octets();
        format!(
            "{}.{}.{}.{}.origin.asn.cymru.com",
            octets[3], octets[2], octets[1], octets[0]
        )
    }

    /// Build IPv6 origin query (reverse nibbles)
    /// 2001:4860:4860::8888 -> expanded and reversed nibbles + ".origin6.asn.cymru.com"
    fn build_ipv6_origin_query(&self, ip: Ipv6Addr) -> String {
        let segments = ip.segments();
        let mut nibbles = Vec::with_capacity(32);

        // Expand each segment to 4 hex nibbles
        for segment in segments {
            nibbles.push((segment >> 12) & 0xf);
            nibbles.push((segment >> 8) & 0xf);
            nibbles.push((segment >> 4) & 0xf);
            nibbles.push(segment & 0xf);
        }

        // Reverse and format as dotted hex nibbles
        nibbles.reverse();
        let nibble_str: String = nibbles
            .iter()
            .map(|n| format!("{:x}", n))
            .collect::<Vec<_>>()
            .join(".");

        format!("{}.origin6.asn.cymru.com", nibble_str)
    }

    /// Lookup AS name from AS number
    async fn lookup_as_name(&self, asn: u32) -> Option<String> {
        let query_name = format!("AS{}.asn.cymru.com", asn);

        let txt_records = self.resolver.txt_lookup(&query_name).await.ok()?;
        let txt = txt_records
            .answers()
            .iter()
            .find_map(|record| match &record.data {
                RData::TXT(txt) => Some(txt),
                _ => None,
            })?;

        // TXT records may be quoted or split - join and strip quotes
        let txt_str: String = txt
            .txt_data
            .iter()
            .filter_map(|bytes| std::str::from_utf8(bytes).ok())
            .collect::<Vec<_>>()
            .join("");
        let txt_str = txt_str.trim_matches('"');

        // Format: "AS | CC | Registry | Allocated | AS Name"
        // Example: "15169 | US | arin | 2000-03-30 | GOOGLE, US"
        let parts: Vec<&str> = txt_str.split('|').map(|s| s.trim()).collect();

        // AS name is at index 4, sanitize for safe display
        parts.get(4).map(|s| sanitize_display(s))
    }
}

/// Parse a Team Cymru origin TXT record into (ASN, BGP prefix).
///
/// Format: "AS | BGP Prefix | CC | Registry | Allocated"
/// Example: "15169 | 8.8.8.0/24 | US | arin | 2023-12-28"
///
/// Multi-origin prefixes list several ASNs in the first field ("701 1239");
/// the first one is used.
fn parse_origin_txt(txt: &str) -> Option<(u32, Option<String>)> {
    let mut parts = txt.split('|').map(str::trim);
    let asn = parts
        .next()?
        .split_whitespace()
        .next()?
        .trim_start_matches("AS")
        .parse()
        .ok()?;
    let prefix = parts.next().filter(|p| !p.is_empty()).map(sanitize_display);
    Some((asn, prefix))
}

/// Maximum concurrent ASN lookups
const MAX_CONCURRENT_LOOKUPS: usize = 10;

/// Background ASN lookup worker that updates session state (multi-target)
pub async fn run_asn_worker(
    asn_lookup: Arc<AsnLookup>,
    sessions: SessionMap,
    cancel: CancellationToken,
) {
    let mut interval = tokio::time::interval(Duration::from_millis(500));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                break;
            }
            _ = interval.tick() => {
                let batch = super::collect_lookup_batch(&sessions, MAX_CONCURRENT_LOOKUPS,
                    |stats| stats.asn.is_none(), |ip| asn_lookup.needs_lookup(ip));

                if batch.is_empty() {
                    continue;
                }

                // Spawn concurrent lookups
                let futures: Vec<_> = batch
                    .iter()
                    .map(|&ip| {
                        let asn = asn_lookup.clone();
                        async move { (ip, asn.lookup(ip).await) }
                    })
                    .collect();

                // Wait for all lookups to complete
                let Some(results) = cancel.run_until_cancelled(futures::future::join_all(futures)).await else {
                    break;
                };

                // Update all sessions with results
                let sessions = sessions.read();
                for (ip, asn_info) in results {
                    if let Some(asn_info) = asn_info {
                        for state in sessions.values() {
                            let mut session = state.write();
                            for hop in &mut session.hops {
                                if let Some(stats) = hop.responders.get_mut(&ip) {
                                    stats.asn = Some(asn_info.clone());
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
        let lookup = Arc::new(AsnLookup::new().await.unwrap());
        for n in 1..=20 {
            let ip = format!("10.0.0.{n}").parse().unwrap();
            let value = if n <= 10 {
                None
            } else {
                Some(AsnInfo {
                    number: 64500,
                    name: "Example".into(),
                    prefix: None,
                })
            };
            lookup.cache.write().insert(
                ip,
                CacheEntry {
                    asn: value,
                    cached_at: Instant::now(),
                },
            );
        }
        let sessions = super::super::tests::unenriched_sessions();
        let cancel = CancellationToken::new();
        super::super::tests::assert_worker_progress(
            sessions.clone(),
            run_asn_worker(lookup, sessions.clone(), cancel.clone()),
            cancel,
            |stats| stats.asn.is_some(),
        )
        .await;
    }
    #[test]
    fn test_ipv4_reverse_format() {
        // Test the format directly without the struct
        let ip: Ipv4Addr = "8.8.8.8".parse().unwrap();
        let octets = ip.octets();
        let query = format!(
            "{}.{}.{}.{}.origin.asn.cymru.com",
            octets[3], octets[2], octets[1], octets[0]
        );
        assert_eq!(query, "8.8.8.8.origin.asn.cymru.com");
    }

    #[test]
    fn test_ipv6_reverse_format() {
        let ip: Ipv6Addr = "2001:4860:4860::8888".parse().unwrap();
        let segments = ip.segments();
        let mut nibbles = Vec::with_capacity(32);

        for segment in segments {
            nibbles.push((segment >> 12) & 0xf);
            nibbles.push((segment >> 8) & 0xf);
            nibbles.push((segment >> 4) & 0xf);
            nibbles.push(segment & 0xf);
        }

        nibbles.reverse();
        let nibble_str: String = nibbles
            .iter()
            .map(|n| format!("{:x}", n))
            .collect::<Vec<_>>()
            .join(".");

        // 2001:4860:4860:0000:0000:0000:0000:8888 reversed nibbles
        assert!(nibble_str.ends_with(".1.0.0.2"));
        assert!(nibble_str.starts_with("8.8.8.8."));
    }

    #[test]
    fn test_parse_cymru_response() {
        // Real origin.asn.cymru.com format: ASN | prefix | CC | registry | date
        assert_eq!(
            parse_origin_txt("15169 | 8.8.8.0/24 | US | arin | 2023-12-28"),
            Some((15169, Some("8.8.8.0/24".to_string())))
        );
        assert_eq!(
            parse_origin_txt("701 | 204.148.0.0/14 | US | arin | 1994-09-16"),
            Some((701, Some("204.148.0.0/14".to_string())))
        );
        // Multi-origin prefix: first ASN wins
        assert_eq!(
            parse_origin_txt("701 1239 | 204.148.0.0/14 | US | arin | 1994-09-16"),
            Some((701, Some("204.148.0.0/14".to_string())))
        );
        assert_eq!(parse_origin_txt("15169"), Some((15169, None)));
        assert_eq!(parse_origin_txt("garbage | 1.0.0.0/8"), None);
    }

    #[test]
    fn test_parse_cymru_name_response() {
        let txt = "15169 | US | arin | 2000-03-30 | GOOGLE, US";
        let parts: Vec<&str> = txt.split('|').map(|s| s.trim()).collect();

        let name = parts.get(4).map(|s| s.to_string());
        assert_eq!(name, Some("GOOGLE, US".to_string()));
    }
}
