# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **ASN column in main table**: Network provider/ISP now visible at a glance
  - Shows AS name (e.g., "GOOGLE", "COMCAST") for each hop
  - Complements existing ASN details in hop detail view
- **TCP SYN probing mode**: Send TCP SYN packets instead of ICMP Echo
  - Enable with `-p tcp` or `--protocol tcp`
  - Default port 80, customizable with `--port` flag
  - Probe ID encoded in TCP sequence number for correlation
  - Proper TCP checksum calculation with pseudo-header
- **Protocol auto-detection**: Automatically select best available protocol
  - New default mode (`-p auto`): tries ICMP → UDP → TCP in order
  - Falls back when socket creation fails (e.g., no raw socket permission)
  - Seamless degradation for unprivileged users
- **Fixed port option**: Disable per-TTL port variation for UDP/TCP
  - New `--fixed-port` flag keeps destination port constant
  - Useful for probing specific services (e.g., DNS on port 53)
- **High-rate optimizations**: Improved performance at fast probe intervals
  - Batch drain limit (100 packets) prevents receiver starvation
  - Batched state updates reduce lock contention
  - Single lock acquisition per batch instead of per-packet
- **Receiver error tracking**: Stop after 50 consecutive socket errors
  - Prevents infinite error loops when socket fails persistently
  - Logs error count progress (e.g., "Receive error (5/50): ...")
  - Graceful shutdown with descriptive error message
- **ASN lookup**: Automatic ASN enrichment via Team Cymru DNS (enabled by default)
  - Displays ASN number, name, and BGP prefix in hop detail view
  - Supports both IPv4 and IPv6 addresses
  - Caching for 1 hour to reduce DNS queries
  - Disable with `--no-asn` flag
- **GeoIP lookup**: Optional geolocation via MaxMind GeoLite2 database
  - Displays city, region, country, and coordinates in hop detail view
  - Auto-discovers database in common paths (~/.local/share/ttl/, /usr/share/GeoIP/)
  - Specify custom path with `--geoip-db` flag
  - Disable with `--no-geo` flag
- **UDP probing mode**: Send UDP probes instead of ICMP Echo
  - Enable with `-p udp` or `--protocol udp`
  - Uses classic traceroute port range (33434+)
  - Port can be customized with `--port` flag
  - Probe ID encoded in UDP payload for correlation
- **Receiver panic handler**: Captures panic details instead of generic error message
  - Uses `catch_unwind` for clean error reporting
  - Improves debugging when receiver thread fails
- **Enhanced jitter statistics**: avg_jitter, max_jitter, and last_rtt now tracked and displayed
- **RTT percentiles**: p50, p95, p99 calculated from sample history (last 256 samples)
- **MPLS label parsing**: RFC 4884/4950 ICMP extensions parsed for MPLS label stacks
- **Enhanced hop detail view**: Now displays percentiles, enhanced jitter stats, last RTT, and MPLS labels
- **Parallel DNS resolution**: Up to 10 concurrent reverse DNS lookups for faster hostname resolution

### Fixed
- **Startup false drops**: Fixed race condition where fast ICMP responses arrived before probe was registered
  - Shared pending map with insert-before-send eliminates registration race
  - Socket drain before timeout cleanup prevents dropping queued responses
- Improved accuracy for low-latency first hops
- **ASN TXT parsing**: Fixed handling of quoted/split TXT records from Team Cymru DNS

### Documentation
- **Jitter semantics**: Clarified that jitter measures RTT variance, not inter-packet timing
  - Added detailed code comments explaining RFC 3550-inspired EWMA calculation
  - New "Statistics Explained" section in README with jitter/metrics documentation

### Technical
- TCP probe module (`src/probe/tcp.rs`) with SYN packet building and checksum calculation
- TCP checksum uses actual source IP via UDP connect routing lookup (not 0.0.0.0)
- TCP correlation support in ICMP error payload parsing
- Batched receiver state updates for reduced lock contention
- Added `futures` crate for parallel async operations
- Sample history stored in circular buffer (256 entries) for percentile calculations
- MplsLabel struct with RFC 4950 format parsing
- MPLS extension parsing uses RFC 4884 length field (not fixed 128-byte offset)
- Clarified jitter UI labels to distinguish smoothed vs raw sample stats
- ASN lookup uses Team Cymru DNS (origin.asn.cymru.com, AS name lookup)
- GeoIP lookup uses MaxMind GeoLite2-City database format
- UDP probe correlation extracts ProbeId from UDP payload in ICMP errors
- Receiver error tracking with consecutive failure counting

### Changed
- **Library API boundary cleanup**: Internal modules now use `pub(crate)` visibility
  - Public API: `config`, `export`, `state` modules
  - Internal (crate-only): `cli`, `lookup`, `probe`, `trace`, `tui` modules
  - Binary still has full access to all modules

## [0.1.2] - 2025-01-12

### Added
- Theme persistence: saves selected theme to `~/.config/ttl/config.toml`
- Theme automatically restored on next launch
- CLI `--theme` flag still overrides saved preference

## [0.1.1] - 2025-01-12

### Added
- Theme support with 11 built-in themes via `--theme` flag
- Themes: default, kawaii, cyber, dracula, monochrome, matrix, nord, gruvbox, catppuccin, tokyo_night, solarized
- Runtime theme cycling with `t` key in TUI
- Theme-aware UI rendering (borders, status colors, highlights)

## [0.1.0] - 2025-01-12

### Added
- Initial release
- ICMP Echo probing with TTL sweep (1-30 by default)
- IPv4 and IPv6 support with extension header handling
- Real-time TUI built with ratatui
- Hop statistics: loss%, min/avg/max RTT, standard deviation, jitter
- ECMP detection showing multiple responders per TTL
- Reverse DNS resolution for hop IPs
- Export formats: JSON, CSV, text report
- Session replay from saved JSON files
- Interactive TUI with j/k navigation, hop detail view
- Loss-aware sparkline visualization
- Pause/resume probing (p key)
- Stats reset (r key)
- Destination detection (automatically stops at actual hop count)
- Platform support documentation (Linux, macOS)

### Technical
- Welford's online algorithm for numerically stable mean/variance
- RFC 3550-style smoothed jitter calculation (measures RTT variance)
- Probe correlation via ICMP sequence field encoding
- IPv6 extension header parsing (Hop-by-Hop, Routing, Destination Options)
- ICMP checksum validation for IPv4 Echo Reply
- Graceful handling of receive buffer size limits

### Security
- Max TTL validation (capped at 64 to prevent resource exhaustion)
- Replay file size limit (10MB max to prevent DoS)

### Documentation
- Troubleshooting section in README (permissions, high loss, IPv6, DNS)

### Tests
- 32 unit tests covering ICMP parsing, stats calculation, session state
- Tests for IPv6 extension headers, ECMP scenarios, edge cases
