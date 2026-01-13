# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.1] - 2026-01-12

### Added
- **NAT detection**: Detect when NAT devices rewrite source ports
  - Compare sent source port vs returned port in ICMP error payloads
  - NAT indicator column ("!") in TUI when multi-flow mode enabled
  - `[NAT]` warning in title bar when NAT detected anywhere
  - Per-hop NAT details in hop detail view (match/rewrite counts, samples)
  - Warning when NAT may affect ECMP accuracy
  - `NatInfo` struct tracks port matches and rewrites per hop

### Technical
- `PendingProbe` now stores `original_src_port` for NAT detection
- `Hop::record_nat_check()` compares original vs returned source ports
- `Session::has_nat()` checks if NAT detected at any hop
- NAT info included in JSON export via serde

## [0.5.0] - 2026-01-12

### Added
- **Paris/Dublin traceroute (ECMP detection)**: Multi-flow probing to discover parallel network paths
  - New `--flows N` flag: Send probes on N different flows (1-16, default 1)
  - New `--src-port BASE` flag: Base source port for flow identification (default 50000)
  - Each flow uses a different source port (UDP/TCP) for path differentiation
  - Routers using ECMP load balancing will route different flows to different paths
- **Per-flow path tracking**: Track which responders are seen on each flow
  - `FlowPathStats` struct tracks sent/received/responder per flow
  - `Hop::has_ecmp()` detects when multiple paths exist
  - `Hop::ecmp_paths()` returns list of (flow_id, responder) pairs
  - `Hop::path_count()` returns number of unique paths discovered
- **ECMP display in TUI**:
  - New "Paths" column in main table when `--flows > 1`
  - Column shows number of unique responders across flows
  - Highlighted in warning color when ECMP detected (>1 path)
  - Hop detail view shows per-flow path breakdown with hostnames
- **Source port extraction**: ICMP error parsing extracts original source port for flow correlation

### Fixed
- **Loss percentage "pulsing"**: Fixed visual glitch where loss would pulse on each hop
  - Loss now calculated from completed probes only: `timeouts / (received + timeouts)`
  - In-flight probes no longer count as temporary losses
  - Added `timeouts` counter to `Hop` struct for accurate tracking

### Technical
- Multi-flow UDP probing: Creates separate bound sockets per flow
- Multi-flow TCP probing: Varies source port in raw SYN packets
- Flow ID tracked in `PendingProbe` for response correlation
- `ParsedResponse.src_port` field for flow identification from ICMP errors
- `PendingMap` keyed by `(ProbeId, flow_id)` to prevent multi-flow entry collisions
- Flow derivation validates port range to avoid mis-attribution from NAT rewrites
- Backward compatible: `--flows 1` (default) = identical to previous behavior

### Known Limitations
- NAT devices may rewrite source ports, causing multi-flow correlation to fail (responses will appear as losses)

## [0.2.0] - 2025-01-12

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
