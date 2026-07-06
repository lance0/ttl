use maxminddb::{Reader, geoip2};
use parking_lot::RwLock;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

use crate::state::GeoInfo;
use crate::trace::receiver::SessionMap;

/// GeoIP cache entry
struct CacheEntry {
    geo: Option<GeoInfo>,
    cached_at: Instant,
}

/// GeoIP lookup using MaxMind GeoLite2 database
pub struct GeoLookup {
    reader: Reader<Vec<u8>>,
    cache: RwLock<HashMap<IpAddr, CacheEntry>>,
    cache_ttl: Duration,
}

impl GeoLookup {
    /// Create a new GeoLookup from a database file path
    pub fn new<P: AsRef<Path>>(db_path: P) -> Result<Self, maxminddb::MaxMindDbError> {
        let reader = Reader::open_readfile(db_path)?;

        Ok(Self {
            reader,
            cache: RwLock::new(HashMap::new()),
            cache_ttl: Duration::from_secs(3600), // 1 hour
        })
    }

    /// Try to create GeoLookup from common default paths
    pub fn try_default() -> Option<Self> {
        // Try common paths in order
        let paths = [
            // User data directory
            dirs::data_dir().map(|d| d.join("ttl").join("GeoLite2-City.mmdb")),
            // Config directory
            dirs::config_dir().map(|d| d.join("ttl").join("GeoLite2-City.mmdb")),
            // Current directory
            Some(std::path::PathBuf::from("GeoLite2-City.mmdb")),
            // System locations
            Some(std::path::PathBuf::from(
                "/usr/share/GeoIP/GeoLite2-City.mmdb",
            )),
            Some(std::path::PathBuf::from(
                "/var/lib/GeoIP/GeoLite2-City.mmdb",
            )),
        ];

        for path in paths.into_iter().flatten() {
            if path.exists()
                && let Ok(lookup) = Self::new(&path)
            {
                return Some(lookup);
            }
        }

        None
    }

    /// Lookup GeoIP info for an IP address
    pub fn lookup(&self, ip: IpAddr) -> Option<GeoInfo> {
        // Check cache first
        {
            let cache = self.cache.read();
            if let Some(entry) = cache.get(&ip)
                && entry.cached_at.elapsed() < self.cache_ttl
            {
                return entry.geo.clone();
            }
        }

        // Perform lookup
        let geo = self.do_lookup(ip);

        // Cache result
        {
            let mut cache = self.cache.write();
            cache.insert(
                ip,
                CacheEntry {
                    geo: geo.clone(),
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

        geo
    }

    /// Perform the actual database lookup
    fn do_lookup(&self, ip: IpAddr) -> Option<GeoInfo> {
        // maxminddb 0.27+ returns LookupResult which needs .decode() call
        let city: geoip2::City = self.reader.lookup(ip).ok()?.decode().ok()??;

        // Extract country (required) - country struct always exists, iso_code is Option
        let country = city.country.iso_code.map(|s| s.to_string())?;

        // Extract optional fields
        // In maxminddb 0.27+, Names has language-specific fields (e.g., .english) instead of HashMap
        let city_name = city.city.names.english.map(|s| s.to_string());

        // subdivisions is Vec<Subdivision>, get first if exists
        let region = city
            .subdivisions
            .first()
            .and_then(|s| s.names.english)
            .map(|s| s.to_string());

        // location struct always exists, lat/long are Option
        let latitude = city.location.latitude;
        let longitude = city.location.longitude;

        Some(GeoInfo {
            city: city_name,
            region,
            country,
            latitude,
            longitude,
        })
    }
}

/// Maximum concurrent GeoIP lookups
const MAX_CONCURRENT_LOOKUPS: usize = 20;

/// Background GeoIP lookup worker that updates session state (multi-target)
pub async fn run_geo_worker(
    geo_lookup: Arc<GeoLookup>,
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
                // Collect a bounded, first-seen batch of unique IPs that need geo lookup.
                let batch: Vec<IpAddr> = {
                    let sessions = sessions.read();
                    let mut seen = HashSet::new();
                    let mut batch = Vec::new();
                    'sessions: for state in sessions.values() {
                        let session = state.read();
                        for hop in &session.hops {
                            for stats in hop.responders.values() {
                                if stats.geo.is_none() && seen.insert(stats.ip) {
                                    batch.push(stats.ip);
                                    if batch.len() >= MAX_CONCURRENT_LOOKUPS {
                                        break 'sessions;
                                    }
                                }
                            }
                        }
                    }
                    batch
                };

                if batch.is_empty() {
                    continue;
                }

                // Lookups are sync and fast, just do them in a loop
                let results: Vec<(IpAddr, Option<GeoInfo>)> = batch
                    .iter()
                    .map(|&ip| (ip, geo_lookup.lookup(ip)))
                    .collect();

                // Update all sessions with results
                let sessions = sessions.read();
                for (ip, geo_info) in results {
                    if let Some(geo_info) = geo_info {
                        for state in sessions.values() {
                            let mut session = state.write();
                            for hop in &mut session.hops {
                                if let Some(stats) = hop.responders.get_mut(&ip) {
                                    stats.geo = Some(geo_info.clone());
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
    fn test_geo_info_construction() {
        let geo = GeoInfo {
            city: Some("Mountain View".to_string()),
            region: Some("California".to_string()),
            country: "US".to_string(),
            latitude: Some(37.386),
            longitude: Some(-122.0838),
        };

        assert_eq!(geo.country, "US");
        assert_eq!(geo.city, Some("Mountain View".to_string()));
    }
}
