# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.12.8] - 2026-01-19

### Fixed
- Fix cargo fmt in integration tests (no functional changes from 0.12.7)

## [0.12.7] - 2026-01-19 [YANKED]

### Fixed
- **Non-responding hops frozen after destination found**: Hops showing `* * *` now continue
  to be probed after destination is discovered, matching mtr/trippy behavior
  - Previously, `Sent` counters froze on non-responding hops after completion
  - Now probes all TTLs up to destination every round
  - Allows detecting hops that recover from rate limiting

### Added
- **Ctrl+C to quit TUI**: Now handles Ctrl+C (and ETX) in addition to `q`
- **`[max_ttl=30]` warning**: Title bar shows warning when destination not found
  and using default max_ttl of 30; hints to try `--max-ttl 64` for long paths

### Changed
- More probes sent after destination found (all TTLs probed each round)
  - Bounded by `dest_ttl`, not `max_ttl`
  - Matches mtr/trippy probing behavior

## [0.12.6] - 2026-01-18

### Fixed
- **ICMPv6 checksum computation**: Fix IPv6 traceroute not detecting destinations
  - ICMPv6 packets had checksum 0, relying on kernel to fill it in (it didn't)
  - Destinations dropped packets with invalid checksums; intermediate hops worked
  - Added manual ICMPv6 checksum computation with RFC 8200 pseudo-header
  - Algorithm derived from trippy (BSD-licensed) with known-value test verification
  - Socket now bound to source IP for IPv6 to ensure checksum consistency

### Improved
- **IPv6 address display**: Increased width for full IPv6 addresses
  - TUI host column: 28 → 42 chars for IPv6 (prevents truncation)
  - Text report host column: 40 → 46 chars

## [0.12.5] - 2026-01-18

### Fixed
- **IPv6 ICMP traceroute**: Fix 100% packet loss on Linux for destination hop
  - Linux delivers ICMPv6 Echo Reply only to the socket that sent the request
  - Added send socket polling for Echo Reply in IPv6 ICMP mode (Linux-only)
  - Intermediate hops (Time Exceeded) were unaffected; only destination detection was broken
  - ICMPv6 Echo Request now uses correct type 128 (was incorrectly using type 8)

### Improved
- **Hop detail dialog**: Add `Enter` and `q` keys to close dialog (PR #6 by @themoog)
  - `Enter` now toggles the dialog (open and close)
  - `q` provides familiar quit-key for TUI users
  - Improves accessibility for users with non-functional Escape keys

### Changed
- **Cargo.lock**: Now tracked in version control for reproducible builds
  - Best practice for binary applications per Cargo documentation
  - Enables deterministic builds for package managers (nixpkgs, etc.)

## [0.12.4] - 2026-01-17

### Fixed
- **Linux binary compatibility**: Switch x86_64 builds to musl libc
  - Pre-built binaries now work on Debian 11/12 and other older distros
  - Previously required glibc 2.39 (Ubuntu 24.04+), now fully static

## [0.12.3] - 2026-01-16

### Fixed
- **Hop detail view stats**: Fixed "Sent: 0" display bug in hop detail panel
  - Hop detail now correctly shows hop-level sent/received/loss stats
  - Previously showed per-responder `sent` (always 0) instead of hop-level `sent`
  - Note: Per-responder sent can't be tracked (we don't know which responder will reply before sending)

## [0.12.2] - 2026-01-16

### Improved
- **Quick Start documentation**: Made Linux `setcap` command more prominent
  - Shows how to run without sudo on Linux after one-time capability setup
  - Clarifies macOS always requires sudo

## [0.12.1] - 2026-01-16

### Security
- **Terminal injection protection**: Sanitize DNS hostnames, ASN names, and IX info before display
  - Filters control characters from external data sources (PTR records, Team Cymru, PeeringDB)
  - Prevents malicious terminal escape sequences from affecting the TUI

### Fixed
- **--count semantics**: `-c N` now sends N probe rounds (one probe per TTL), not N × max_ttl probes
  - Each round sends probes to all active TTLs in a single interval
  - Behavior now matches user expectations: `-c 10` = 10 rounds of probing
  - Updated help text to clarify "probe rounds" semantics
- **Port overflow validation**: `--src-port` + `--flows` combination now correctly validated
  - Fixed off-by-one: ports 65520 + 16 flows (max port 65535) now accepted
  - Clear error message shows the computed maximum port number
- **Sequence wrap prevention**: Reject `--timeout` > 256 × `--interval`
  - ProbeId uses u8 sequence (0-255), wraps every 256 intervals
  - Validation prevents mis-correlation when old probes outlive sequence wrap
- **Dead code removal**: Removed unused `recv_icmp_for_udp` function

### Changed
- **Dependencies updated**:
  - hickory-resolver 0.24 → 0.25
  - socket2 0.5 → 0.6
  - reqwest 0.12 → 0.13
  - dirs 5.0 → 6.0
  - toml 0.8 → 0.9
  - ipnetwork 0.20 → 0.21
  - Removed unused `thiserror` dependency

### Technical
- Added `sanitize_display()` helper in lookup module for control character filtering
- Added 5 CLI validation tests for port overflow and timeout/interval checks
- All three probe modes (ICMP, UDP, TCP) now track `rounds_completed` for consistent `-c` behavior

## [0.12.0] - 2026-01-16

### Added
- **Shell completions**: Generate completions for bash, zsh, fish, and powershell via `--completions <shell>`
- **WSL2 documentation**: Added Windows via WSL2 installation guide to README

### Improved
- Document `PEERINGDB_API_KEY` environment variable for higher API rate limits
- Extract `RECENT_WINDOW_SIZE` constant for cleaner code
- Better documentation for rate limit detection edge cases

## [0.11.5] - 2026-01-15

### Fixed
- **Linux permission error**: Fail fast with clear instructions (setcap or sudo) instead of silently falling back to broken unprivileged mode

## [0.11.4] - 2026-01-15

### Fixed
- **Multi-target response misattribution**: Fix bug where responses could be attributed to wrong target when tracing multiple destinations concurrently
  - Extract original destination IP from quoted ICMP error packets for direct lookup
  - Use responder IP for Echo Reply disambiguation (responder IS the target)
  - Eliminates ambiguous linear target iteration

### Changed
- **MSG_CTRUNC detection**: Return `None` TTL when control message is truncated to prevent unreliable asymmetry detection
- **IPv6 permission check on Linux**: Warn if IPv6 sockets unavailable (mirrors macOS behavior)
- **macOS CI**: Add macOS test job to catch platform-specific issues before release

### Improved
- Remove panic-able `unwrap()` from MPLS label parsing (use direct array conversion)

## [0.11.3] - 2026-01-15

### Changed
- **macOS Sequoia (15) support**: Document as "build from source" only
  - Pre-built binaries are built on Tahoe (26) and may have display issues on Sequoia
  - Users on macOS 15 should use `cargo install ttl` to compile from source
  - Updated README Platform Support table to clarify compatibility

## [0.11.2] - 2026-01-15

### Changed
- Switch macOS build to `macos-latest` runner (Tahoe 26)
  - Did not resolve Sequoia compatibility (see 0.11.3)

## [0.11.1] - 2026-01-15

### Fixed
- **macOS traceroute 100% packet loss**: Fix ICMP traceroute showing all hops as `* * *`
  - DGRAM ICMP sockets cannot receive ICMP Time Exceeded messages from intermediate routers
  - Now uses RAW socket for receiving (can receive all ICMP types) while keeping DGRAM for sending (supports IP_TTL)
  - Added payload-based correlation fallback for RAW receive paths (fixes 100% loss when macOS kernel modifies ICMP identifier)
  - Requires `sudo` on macOS since RAW sockets need root privileges
  - Clear error message when run without elevated privileges
- **Linux unprivileged ICMP**: Restore support for unprivileged ICMP sockets (broken in v0.11.0)
  - Linux users with `ping_group_range` enabled can run without sudo
  - Falls back to DGRAM sockets when RAW sockets are unavailable
- **IPv6 DGRAM availability check**: Warn on macOS if IPv6 DGRAM sockets are unavailable

## [0.11.0] - 2026-01-14

### Fixed
- **macOS traceroute**: Fix ICMP traceroute showing only 1 hop on macOS
  - Use `SOCK_DGRAM` instead of `SOCK_RAW` for ICMP sockets on macOS
  - macOS raw sockets don't support `IP_TTL` setsockopt, preventing TTL manipulation
  - DGRAM sockets allow setting TTL per-packet for proper traceroute functionality
  - Added DGRAM-aware packet parsing (no IP header in received packets)
  - Embedded ProbeId in ICMP payload for correlation fallback (macOS may override identifier)

## [0.10.3] - 2026-01-14

### Changed
- **Platform support**: Drop Intel Mac (x86_64-apple-darwin) binaries - Apple Silicon only
  - Intel Macs can still build from source via `cargo install ttl`

## [0.10.2] - 2026-01-14

### Fixed
- **Cross-compilation**: Switch from native-tls to rustls-tls to avoid OpenSSL dependency for aarch64 builds
- **macOS build**: Fix `msg_controllen` type mismatch (u32 vs usize)
- **Deprecation warning**: Use `bind_device_by_index_v4` instead of deprecated `bind_device_by_index`

## [0.10.1] - 2026-01-14

### Added
- **CLI examples in help**: `--help` now shows usage examples and detection indicator legend
- **Smoke test script**: `tests/smoke.sh` for cross-platform verification

### Changed
- **README improvements**: Homebrew install, simplified permissions, Known Limitations section, better troubleshooting

## [0.10.0] - 2026-01-13

**Highlights**: Path MTU discovery, ICMP rate limit detection, route flap detection, asymmetric routing detection, TTL manipulation detection, and CI/CD automation. Major release for network diagnostic capabilities.

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
- **Binary releases**: Automated builds on version tags via GitHub Actions
  - Linux x86_64 and aarch64 (cross-compiled)
  - macOS x86_64 (Intel) and aarch64 (Apple Silicon)
  - Pre-built binaries attached to GitHub releases
  - SHA256 checksums included for verification
  - cargo-audit security check before release
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
- **First-hop gateway detection**: Display source IP and default gateway in TUI
  - Shows routing info in title bar: `eth0 (192.168.1.100 → 192.168.1.1)`
  - Auto-detects default gateway from system routing table
  - Works with or without `--interface` flag
  - Parses `ip route show` on Linux, `route -n get default` on macOS
  - Gateway info also populated when using `--interface` option
- **Route flap detection**: Detect when primary responder IP changes at a hop
  - Indicates routing instability in single-flow mode
  - Main table shows "!" after hostname when flaps detected
  - Hop detail view shows route change history (last 5 changes)
  - Uses sticky tie-breaker with margin (requires new IP to exceed old by 2+ responses)
  - Minimum 5 responses before recording flaps (avoids startup noise)
  - Disabled in multi-flow mode (`--flows > 1`) where path changes are expected
  - History capped at 50 changes per hop
- **Asymmetric routing detection**: Detect when return path differs from forward path
  - Extracts response TTL from ICMP packets using `recvmsg()` with `IP_RECVTTL`/`IPV6_RECVHOPLIMIT`
  - Estimates return hops using common initial TTL defaults (64, 128, 255)
  - Compares forward TTL vs estimated return hops to detect asymmetry
  - Flags asymmetry when difference >= 3 hops in >50% of samples (minimum 5 samples)
  - Title bar shows `[ASYM]` indicator when any hop has asymmetric routing detected
  - Main table shows "~" after hostname when asymmetry suspected at that hop
  - Hop detail view shows routing symmetry section: forward hops, return hops, confidence
  - High variance in return hops suggests return-path ECMP
  - Disabled in multi-flow mode (like route flap detection)
- **TTL manipulation detection**: Detect middleboxes that modify IP TTL values
  - Analyzes quoted TTL in ICMP Time Exceeded (code 0) responses only
  - Code 0 = TTL exceeded in transit; code 1 = fragment reassembly exceeded (ignored)
  - Per RFC 1812, quoted TTL should be 0 or 1 (post-decrement or pre-decrement)
  - Detects: transparent proxies (quoted TTL == sent TTL), abnormal quoted TTL > 1
  - Hop 1 guard: avoids false positive when sent_ttl=1 and quoted_ttl=1 (normal pre-decrement)
  - Title bar shows `[TTL!]` indicator when manipulation detected
  - Main table shows "^" after hostname at affected hops
  - Hop detail view shows: sent TTL, last quoted TTL, normal/anomalous sample counts
  - Works in both single-flow and multi-flow modes (unlike asymmetry/flap detection)
  - Hysteresis clearing resets anomaly counters to prevent re-triggering

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
- Gateway detection: `detect_gateway_ipv4()` and `detect_gateway_ipv6()` in `interface.rs`
- Gateway detection: `detect_default_gateway()` for auto-detected interface routing
- `InterfaceInfo` extended with `gateway_ipv4` and `gateway_ipv6` fields
- `Session` extended with `source_ip` and `gateway` fields for TUI display

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
- 92 unit tests covering ICMP parsing, stats calculation, session state
- 20 integration tests for probe→state pipeline
- 9 property-based tests (proptest) for packet parsing robustness
- Tests for IPv6 extension headers, ECMP scenarios, edge cases
