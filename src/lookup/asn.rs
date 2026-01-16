use anyhow::Result;
use hickory_resolver::config::ResolverConfig;
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
        // Try system DNS config first, fall back to Google DNS if unavailable
        let resolver = match Resolver::builder_tokio() {
            Ok(builder) => builder.build(),
            Err(_) => {
                eprintln!("Warning: System DNS config unavailable, using Google DNS (8.8.8.8)");
                Resolver::builder_with_config(
                    ResolverConfig::google(),
                    hickory_resolver::name_server::TokioConnectionProvider::default(),
                )
                .build()
            }
        };

        Ok(Self {
            resolver,
            cache: RwLock::new(HashMap::new()),
            cache_ttl: Duration::from_secs(3600), // 1 hour
        })
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
        }

        asn
    }

    /// Perform the actual DNS lookup
    async fn do_lookup(&self, ip: IpAddr) -> Option<AsnInfo> {
        // Build the query name for origin lookup
        let query_name = self.build_origin_query(ip);

        // Query TXT record at <reversed_ip>.origin.asn.cymru.com
        let txt_records = self.resolver.txt_lookup(&query_name).await.ok()?;

        // Parse the first TXT record
        // Format: "AS | IP | BGP Prefix | CC | Registry | Allocated"
        // Example: "15169 | 8.8.8.8 | 8.8.8.0/24 | US | arin | 1992-12-01"
        let txt = txt_records.iter().next()?;

        // TXT records may be quoted or split into multiple strings - join and strip quotes
        let txt_str: String = txt
            .txt_data()
            .iter()
            .filter_map(|bytes| std::str::from_utf8(bytes).ok())
            .collect::<Vec<_>>()
            .join("");
        let txt_str = txt_str.trim_matches('"');

        let parts: Vec<&str> = txt_str.split('|').map(|s| s.trim()).collect();

        if parts.is_empty() {
            return None;
        }

        // Parse ASN number (may have "AS" prefix or just number)
        let asn_str = parts[0].trim_start_matches("AS").trim();
        let asn_number: u32 = asn_str.parse().ok()?;

        // Extract prefix if available (index 2)
        let prefix = parts.get(2).map(|s| s.to_string());

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
        let txt = txt_records.iter().next()?;

        // TXT records may be quoted or split - join and strip quotes
        let txt_str: String = txt
            .txt_data()
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

/// Maximum concurrent ASN lookups
const MAX_CONCURRENT_LOOKUPS: usize = 10;

/// Background ASN lookup worker that updates session state (multi-target)
pub async fn run_asn_worker(
    asn_lookup: Arc<AsnLookup>,
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
                // Collect IPs that need ASN lookup from all sessions
                let ips_to_lookup: Vec<IpAddr> = {
                    let sessions = sessions.read();
                    sessions.values()
                        .flat_map(|state| {
                            let session = state.read();
                            session.hops.iter()
                                .flat_map(|hop| hop.responders.values())
                                .filter(|stats| stats.asn.is_none())
                                .map(|stats| stats.ip)
                                .collect::<Vec<_>>()
                        })
                        .collect()
                };

                if ips_to_lookup.is_empty() {
                    continue;
                }

                // Perform parallel ASN lookups (limited batch size)
                let batch: Vec<IpAddr> = ips_to_lookup
                    .into_iter()
                    .take(MAX_CONCURRENT_LOOKUPS)
                    .collect();

                // Spawn concurrent lookups
                let futures: Vec<_> = batch
                    .iter()
                    .map(|&ip| {
                        let asn = asn_lookup.clone();
                        async move { (ip, asn.lookup(ip).await) }
                    })
                    .collect();

                // Wait for all lookups to complete
                let results = futures::future::join_all(futures).await;

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
        let txt = "15169 | 8.8.8.8 | 8.8.8.0/24 | US | arin | 1992-12-01";
        let parts: Vec<&str> = txt.split('|').map(|s| s.trim()).collect();

        let asn_str = parts[0].trim_start_matches("AS");
        let asn_number: u32 = asn_str.parse().unwrap();
        assert_eq!(asn_number, 15169);

        let prefix = parts.get(2).map(|s| s.to_string());
        assert_eq!(prefix, Some("8.8.8.0/24".to_string()));
    }

    #[test]
    fn test_parse_cymru_name_response() {
        let txt = "15169 | US | arin | 2000-03-30 | GOOGLE, US";
        let parts: Vec<&str> = txt.split('|').map(|s| s.trim()).collect();

        let name = parts.get(4).map(|s| s.to_string());
        assert_eq!(name, Some("GOOGLE, US".to_string()));
    }
}
