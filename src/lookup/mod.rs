pub mod asn;
pub mod geo;
pub mod ix;
pub mod rdns;

/// Sanitize a string for safe terminal display by removing control characters.
///
/// This filters out ASCII control characters (0x00-0x1F, 0x7F) and Unicode control
/// characters that could be used to inject terminal escape sequences.
pub(crate) fn sanitize_display(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).collect()
}

/// Maximum number of entries per enrichment cache before eviction kicks in.
///
/// A single traceroute session with 64 max TTL × ~3 responders per hop yields
/// ~190 IPs. Multi-target mode with 10 targets tops out around 2,000. The cap
/// is generous (5× headroom) while preventing unbounded growth in pathological
/// long-running scenarios.
pub(crate) const ENRICHMENT_CACHE_CAP: usize = 10_000;

/// Prune an enrichment cache map.
///
/// Two-phase eviction:
/// 1. Remove entries whose `cached_at + ttl` has elapsed (expired).
/// 2. If still over `ENRICHMENT_CACHE_CAP`, evict oldest by `cached_at`.
///
/// `age_fn` extracts the `Instant` timestamp from each entry for sorting.
/// `is_expired` receives `&Entry` and the `ttl`; it should return `true` when
/// the entry is stale.
pub(crate) fn prune_cache<Entry, A, E>(
    cache: &mut std::collections::HashMap<std::net::IpAddr, Entry>,
    ttl: std::time::Duration,
    age_fn: A,
    is_expired: E,
) where
    A: Fn(&Entry) -> std::time::Instant,
    E: Fn(&Entry, std::time::Duration) -> bool,
{
    use std::net::IpAddr;
    use std::time::Instant;

    // Phase 1: drop TTL-expired entries.
    cache.retain(|_, entry| !is_expired(entry, ttl));

    // Phase 2: if still over cap, evict oldest by cached_at.
    if cache.len() > ENRICHMENT_CACHE_CAP {
        let mut ages: Vec<(IpAddr, Instant)> = cache
            .iter()
            .map(|(ip, entry)| (*ip, age_fn(entry)))
            .collect();
        ages.sort_unstable_by_key(|(_, t)| *t);
        let excess = cache.len() - ENRICHMENT_CACHE_CAP;
        for (ip, _) in ages.into_iter().take(excess) {
            cache.remove(&ip);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::{Duration, Instant};

    struct TestEntry {
        cached_at: Instant,
    }

    fn make_ip(n: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, n))
    }

    #[test]
    fn test_prune_removes_expired_entries() {
        let mut cache: HashMap<IpAddr, TestEntry> = HashMap::new();
        let now = Instant::now();

        // Entry well past TTL.
        cache.insert(
            make_ip(1),
            TestEntry {
                cached_at: now - Duration::from_secs(7200),
            },
        );
        // Entry within TTL.
        cache.insert(make_ip(2), TestEntry { cached_at: now });

        prune_cache(
            &mut cache,
            Duration::from_secs(3600),
            |e| e.cached_at,
            |e, ttl| e.cached_at.elapsed() >= ttl,
        );

        assert!(
            !cache.contains_key(&make_ip(1)),
            "expired entry should be evicted"
        );
        assert!(cache.contains_key(&make_ip(2)), "fresh entry should remain");
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn test_prune_keeps_all_when_under_and_fresh() {
        let mut cache: HashMap<IpAddr, TestEntry> = HashMap::new();
        let now = Instant::now();

        for n in 1..=100 {
            cache.insert(make_ip(n), TestEntry { cached_at: now });
        }

        prune_cache(
            &mut cache,
            Duration::from_secs(3600),
            |e| e.cached_at,
            |e, ttl| e.cached_at.elapsed() >= ttl,
        );

        assert_eq!(
            cache.len(),
            100,
            "all entries should remain when under cap and fresh"
        );
    }

    #[test]
    fn test_prune_phase2_evicts_oldest() {
        // Test phase 2 directly: fill cache to CAP+3 with fresh entries,
        // verify it shrinks to CAP and the oldest 3 are removed.
        let mut cache: HashMap<IpAddr, TestEntry> = HashMap::new();
        let now = Instant::now();

        for n in 0..(ENRICHMENT_CACHE_CAP + 3) {
            // Give each entry a unique age so sorting is deterministic.
            // Use nanosecond granularity; oldest entries get largest age.
            // We need unique IPs — use both v4 and v6 to get enough.
            let ip = match n {
                _ if n < 254 => IpAddr::V4(Ipv4Addr::new(10, 0, 0, (n + 1) as u8)),
                _ if n < 508 => IpAddr::V4(Ipv4Addr::new(10, 0, 1, (n - 253) as u8)),
                _ if n < 762 => IpAddr::V4(Ipv4Addr::new(10, 0, 2, (n - 507) as u8)),
                _ if n < 1016 => IpAddr::V4(Ipv4Addr::new(10, 0, 3, (n - 761) as u8)),
                _ if n < 5025 => IpAddr::V6(std::net::Ipv6Addr::new(
                    0x2001,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    (n - 1015) as u16,
                )),
                _ => IpAddr::V6(std::net::Ipv6Addr::new(
                    0x2001,
                    0,
                    0,
                    0,
                    0,
                    0,
                    1,
                    (n - 5024) as u16,
                )),
            };
            // Oldest entries (n=0) have largest age; youngest (n=CAP+2) have smallest.
            // age = (CAP+3 - n) nanoseconds
            let entry_age = Duration::from_nanos((ENRICHMENT_CACHE_CAP + 3 - n) as u64);
            cache.insert(
                ip,
                TestEntry {
                    cached_at: now - entry_age,
                },
            );
        }

        assert_eq!(cache.len(), ENRICHMENT_CACHE_CAP + 3);

        prune_cache(
            &mut cache,
            Duration::from_secs(3600), // TTL long enough that nothing is expired
            |e| e.cached_at,
            |e, ttl| e.cached_at.elapsed() >= ttl,
        );

        assert_eq!(cache.len(), ENRICHMENT_CACHE_CAP, "should shrink to cap");

        // The 3 oldest entries (n=0,1,2) should be evicted.
        // n=0 has age = CAP+3 ns, n=1 has age = CAP+2 ns, n=2 has age = CAP+1 ns.
        // Their IPs are:
        let evicted_ips = [
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), // n=0
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), // n=1
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)), // n=2
        ];
        for ip in &evicted_ips {
            assert!(
                !cache.contains_key(ip),
                "oldest entry {:?} should be evicted",
                ip
            );
        }
        // n=3 (age = CAP ns) should still be present.
        assert!(cache.contains_key(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4))));
    }

    #[test]
    fn test_prune_empty_cache_is_noop() {
        let mut cache: HashMap<IpAddr, TestEntry> = HashMap::new();
        prune_cache(
            &mut cache,
            Duration::from_secs(3600),
            |e| e.cached_at,
            |e, ttl| e.cached_at.elapsed() >= ttl,
        );
        assert_eq!(cache.len(), 0);
    }
}
