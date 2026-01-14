# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.10.0] - 2026-01-13

### Added
- **Path MTU discovery** (`--pmtud`): Binary search to find maximum unfragmented packet size
  - Uses DF (Don't Fragment) flag to detect MTU limits
  - Binary search algorithm: starts at 1500, converges to within 8 bytes
  - Shows progress in TUI title bar: `[MTU: min-max]` during search, `[MTU: X]` when complete
  - Extracts MTU from ICMP Fragmentation Needed (IPv4 Type 3 Code 4) and ICMPv6 Packet Too Big (Type 2)
  - Handles EMSGSIZE errors for local interface MTU limits
  - Requires 2 consecutive successes or failures before moving binary search bounds (handles network flakiness)
  - IPv4 minimum: 68 bytes (RFC 791), IPv6 minimum: 1280 bytes (RFC 8200)
  - Conflicts with `--size` (mutually exclusive)
- **Packet size control** (`--size`): Set probe packet size for MTU testing
  - Range: 36-1500 bytes for IPv4, 56-1500 bytes for IPv6
  - Total packet size includes IP header (20/40 bytes) + protocol header + payload
  - Packets sent with DF (Don't Fragment) flag for proper MTU discovery
  - Works with all probe protocols (ICMP, UDP, TCP)
- **DSCP/ToS marking** (`--dscp`): Set IP header DSCP field (0-63) for QoS policy testing
  - DSCP 46 = Expedited Forwarding (EF) for VoIP traffic
  - DSCP 34 = AF41 for video traffic
  - Useful for testing QoS policies and seeing where traffic gets remarked
  - Works with all probe protocols (ICMP, UDP, TCP)
  - Supports both IPv4 (TOS) and IPv6 (Traffic Class)
- **GitHub Actions CI**: Automated build, test, clippy, and format checks on PRs
  - Runs on ubuntu-latest for all pushes to master and PRs
  - Strict clippy (`-D warnings`) catches issues before merge
- **Rate limiting** (`--rate`): Limit probes per second to avoid triggering router rate limits
  - Useful for slow links or avoiding overwhelming targets
  - `--rate 0` = unlimited (default), `--rate 10` = 10 probes/sec max
  - Global limit applies across all flows
- **Source IP selection** (`--source-ip`): Force probes to use a specific source IP address
  - Useful for multi-homed hosts with multiple IPs
  - Works with all probe protocols (ICMP, UDP, TCP)
  - Validates source IP family matches target family
- **ICMP rate limit detection**: Identify when routers are rate-limiting ICMP responses
  - Detects misleading packet loss caused by router rate limiting (not actual packet drops)
  - Three detection heuristics:
    1. **Isolated hop loss**: Loss at hop N but 0% loss downstream = rate limiting
    2. **Uniform flow loss**: All flows losing equally in Paris/Dublin mode = hop-level limiting
    3. **Stable loss ratio**: Consistent loss percentage over time = rate limiting (vs fluctuating congestion)
  - Loss% column shows "RL" suffix (e.g., "50%RL") when rate limiting suspected
  - Title bar shows `[RL?]` indicator when any hop has rate limiting detected
  - Hop detail view shows detection reason, confidence level, and mitigation tip
  - Tip suggests slower probing with `-i 1.0` or `-i 2.0` to avoid triggering limits
  - Detection automatically clears when loss drops below threshold

### Fixed
- **PeeringDB pagination**: Added `limit=0` to API requests to fetch all IX records
  - Without this, only the first page of results was cached, missing many IX detections
- **PeeringDB User-Agent**: Added proper User-Agent header to avoid 403 Forbidden responses
- **PeeringDB API key support**: Set `PEERINGDB_API_KEY` env var for higher rate limits
  - Anonymous API access is rate-limited (1/hour for large queries)
  - API key authentication provides 40 requests/minute
- **IX lookup race condition**: Use `OnceCell::get_or_try_init` for thread-safe lazy loading
  - Previously, concurrent lookups could trigger multiple parallel API fetches
  - `get_or_try_init` only fills cell on success, allowing retries after backoff on failure
- **IX lookup failure backoff**: Skip retries for 5 minutes after load failure
  - Prevents log spam and repeated API hits on unstable networks
- **Longest prefix match**: Sort prefixes by length descending for correct matching
  - Previously returned first match; now returns most specific (longest) prefix
- **Rate limit reset**: `reset_stats` now clears rate limit detection state
  - Previously RL warnings could persist after reset or replay
- **Stable loss ratio calculation**: Fixed segment length calculation for non-divisible window sizes
  - Previously third segment used wrong divisor, skewing detection
- **Rate limit clearing hysteresis**: Require 2 consecutive negative checks before clearing
  - Also clears when downstream loss rises above 10% (isolated loss no longer applies)
  - Force clears after 5 negatives regardless (signal gone if heuristics stop matching)
  - Prevents UI flicker while ensuring stale RL doesn't linger
- **Stable-loss uses recent window**: Detection now uses recent_results loss, not lifetime
  - Fixes sticky RL during recovery when lifetime loss is still high but recent is 0%
- **PMTUD probe ID collision**: Added `is_pmtud` flag to pending map key
  - Completely eliminates collision between normal and PMTUD probes with same ProbeId
- **PMTUD consecutive counter logic**: Direction changes now reset opposite counter
  - Ensures 2 truly consecutive results before advancing binary search bounds
- **PMTUD response size verification**: Only process responses matching current probe size
  - Ignores late responses from previous probe sizes that could corrupt state
- **IPv6 Packet Too Big handling**: Added dedicated `PacketTooBig` enum variant
  - ICMPv6 Type 2 now correctly triggers PMTUD MTU clamping
- **Multi-target JSON output**: Multiple targets now wrapped in JSON array
  - Previously output invalid JSON (concatenated objects without delimiters)
- **TUI pause state sync**: Switching targets now syncs pause indicator with target's state
  - Previously pause indicator could be stale after Tab/n target switch

### Changed
- **Dependencies updated**: ratatui 0.28→0.30, crossterm 0.28→0.29, maxminddb 0.24→0.27
  - Fixes RUSTSEC-2025-0132 (maxminddb unsafe memmap), RUSTSEC-2024-0436 (paste unmaintained)
- **Security audit CI**: Added `.github/workflows/audit.yml` for daily RustSec advisory checks

### Technical
- PMTUD: `PmtudState` struct with binary search state (min/max bounds, success/failure counters)
- PMTUD: `PmtudPhase` enum (WaitingForDestination, Searching, Complete)
- PMTUD: `set_dont_fragment()` in `socket.rs` for Linux (`IP_MTU_DISCOVER`) and macOS (`IP_DONTFRAG`)
- PMTUD: MTU extraction from ICMP errors in `correlate.rs` (Type 3 Code 4 for IPv4, Type 2 for ICMPv6)
- PMTUD: `packet_size` field in `PendingProbe` for correlation
- PMTUD: Engine sends PMTUD probes at destination TTL after normal traceroute finds destination
- New `src/state/ratelimit.rs` module for detection logic
- `RateLimitInfo` struct with suspected flag, confidence (0-1), reason, and loss data
- Background async worker runs analysis every 2 seconds (lightweight)
- Detection integrates with all modes: interactive TUI, batch, and streaming
- JSON export includes rate limit data via serde
- IX lookup uses `tokio::sync::OnceCell` for thread-safe lazy initialization
- Refactored `Receiver::new()` and `spawn_receiver()` to use `ReceiverConfig` struct (9 args → 4 args)
- Renamed internal `fixed_port` field to `port_fixed` for Rust naming consistency

## [0.9.0] - 2026-01-13

### Added
- **IX detection via PeeringDB**: Identify Internet Exchange points in the path
  - Fetches IX peering LAN prefixes from PeeringDB API
  - Matches hop IPs against IX prefixes (IPv4 and IPv6)
  - Shows IX name, city, and country in hop detail view
  - Data cached locally for 24 hours to respect API rate limits
  - Cache stored in `~/.cache/ttl/peeringdb/ix_cache.json`
  - Disable with `--no-ix` flag

### Technical
- New `src/lookup/ix.rs` module for PeeringDB integration
- `IxInfo` struct added to `ResponderStats` for IX data
- `IxLookup` handles API fetching, caching, and prefix matching
- Background `run_ix_worker` updates session state like ASN/GeoIP workers
- Added `reqwest` dependency for HTTP requests

## [0.7.0] - 2026-01-13

### Added
- **Interface binding**: Force probes through a specific network interface
  - New `--interface <NAME>` flag binds all sockets to the specified interface
  - Useful for multi-homed hosts, VPN split tunneling, or deterministic egress path selection
  - Works with all probe protocols (ICMP, UDP, TCP)
  - Interface name shown in TUI title bar ("via eth0") and report output
  - Linux uses `SO_BINDTODEVICE`, macOS uses `IP_BOUND_IF`
- **Asymmetric routing support**: New `--recv-any` flag
  - Requires `--interface` to be set
  - Disables receiver socket binding to interface
  - Allows receiving replies on any interface (for asymmetric routing, VPN scenarios)
  - Send sockets remain bound to the specified interface

### Fixed
- **IPv6 interface detection**: Fixed bug where global IPv6 addresses were incorrectly rejected
  - The link-local check used bitwise NOT (`!v6.segments()[0]`) instead of comparison (`!=`)
  - Global IPv6 addresses like `2001:db8::1` now correctly detected on dual-stack interfaces
- **Link-local only rejection**: Non-loopback interfaces with only link-local IPv6 now return clear error
  - Link-local addresses require scope IDs and can't reach Internet targets
  - Error message explains the issue and suggests assigning a global address
- **Auto-protocol UDP binding**: Auto-protocol mode now tests UDP with interface binding
  - Previously could select UDP even if interface binding would fail later
  - Now fails fast with clear error instead of confusing runtime failure

### Technical
- New `src/probe/interface.rs` module for cross-platform interface validation and binding
- `is_link_local_ipv6()` helper function shared between production code and tests
- `InterfaceInfo` struct holds validated interface name, index, IPv4/IPv6 addresses
- Interface passed through `ProbeEngine`, `Receiver`, and all socket creation functions
- `recv_any` field in `Config` controls receiver binding behavior
- Uses `pnet::datalink::interfaces()` for enumeration, `socket2` for binding

## [0.6.1] - 2026-01-13

### Fixed
- **Enrichment in batch/streaming modes**: DNS, ASN, and GeoIP lookups now work in `--json`, `--report`, `--csv`, and `--no-tui` modes
  - Previously enrichment workers only spawned in interactive TUI mode
  - Batch mode waits for enrichment to settle before export
  - Streaming mode shows hostnames progressively as DNS resolves
- **Terminal state restoration**: TUI now properly restores terminal on early errors or panics
  - Added `scopeguard::defer!` guard to ensure cleanup runs on all exit paths
  - Prevents terminal being left in raw/alternate screen mode on crash

### Technical
- Added `scopeguard = "1"` dependency for cleanup guards
- `run_batch_mode()` and `run_streaming_mode()` now spawn enrichment workers
- Streaming output includes hostname column when resolved

## [0.6.0] - 2026-01-12

### Added
- **Multiple simultaneous targets**: Trace to multiple destinations at once
  - Pass multiple targets: `ttl 8.8.8.8 1.1.1.1 google.com`
  - Tab/n to switch to next target, Shift-Tab/N for previous
  - Target indicator in title bar shows `[1/3]` for current target
  - Per-target pause/reset (p/r affect only current target)
  - Each target runs its own probe engine with independent state
- **SessionMap architecture**: Shared sessions map for multi-target support
  - `SessionMap = Arc<RwLock<HashMap<IpAddr, Arc<RwLock<Session>>>>>`
  - Single receiver demultiplexes responses to correct session
  - Lookup workers (DNS, ASN, GeoIP) iterate all sessions

### Technical
- `PendingKey` now includes target IP: `(ProbeId, flow_id, IpAddr)`
- Receiver iterates target list to find matching probe
- `run_tui()` accepts SessionMap and targets list
- `MainView::with_target_info()` for target indicator display
- Mixed IPv4/IPv6 targets not supported (single receiver limitation)

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
