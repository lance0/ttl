use maxminddb::{geoip2, Reader};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

use crate::state::GeoInfo;
use crate::trace::SessionMap;

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
    pub fn new<P: AsRef<Path>>(db_path: P) -> Result<Self, maxminddb::MaxMindDBError> {
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
            Some(std::path::PathBuf::from("/usr/share/GeoIP/GeoLite2-City.mmdb")),
            Some(std::path::PathBuf::from("/var/lib/GeoIP/GeoLite2-City.mmdb")),
        ];

        for path in paths.into_iter().flatten() {
            if path.exists() {
                if let Ok(lookup) = Self::new(&path) {
                    return Some(lookup);
                }
            }
        }

        None
    }

    /// Lookup GeoIP info for an IP address
    pub fn lookup(&self, ip: IpAddr) -> Option<GeoInfo> {
        // Check cache first
        {
            let cache = self.cache.read();
            if let Some(entry) = cache.get(&ip) {
                if entry.cached_at.elapsed() < self.cache_ttl {
                    return entry.geo.clone();
                }
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
        }

        geo
    }

    /// Perform the actual database lookup
    fn do_lookup(&self, ip: IpAddr) -> Option<GeoInfo> {
        let city: geoip2::City = self.reader.lookup(ip).ok()?;

        // Extract country (required)
        let country = city
            .country
            .as_ref()
            .and_then(|c| c.iso_code)
            .map(|s| s.to_string())?;

        // Extract optional fields
        let city_name = city
            .city
            .as_ref()
            .and_then(|c| c.names.as_ref())
            .and_then(|n| n.get("en"))
            .map(|s| s.to_string());

        let region = city
            .subdivisions
            .as_ref()
            .and_then(|s| s.first())
            .and_then(|s| s.names.as_ref())
            .and_then(|n| n.get("en"))
            .map(|s| s.to_string());

        let (latitude, longitude) = city
            .location
            .as_ref()
            .map(|loc| (loc.latitude, loc.longitude))
            .unwrap_or((None, None));

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
                // Collect IPs that need geo lookup from all sessions
                let ips_to_lookup: Vec<IpAddr> = {
                    let sessions = sessions.read();
                    sessions.values()
                        .flat_map(|state| {
                            let session = state.read();
                            session.hops.iter()
                                .flat_map(|hop| hop.responders.values())
                                .filter(|stats| stats.geo.is_none())
                                .map(|stats| stats.ip)
                                .collect::<Vec<_>>()
                        })
                        .collect()
                };

                if ips_to_lookup.is_empty() {
                    continue;
                }

                // GeoIP lookups are fast (local file), so we can do more at once
                let batch: Vec<IpAddr> = ips_to_lookup
                    .into_iter()
                    .take(MAX_CONCURRENT_LOOKUPS)
                    .collect();

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
