# ttl Roadmap

## Current Status (v0.13.0)

### Core Features
- [x] ICMP Echo probing with TTL sweep
- [x] IPv4 and IPv6 support with extension header handling
- [x] Real-time TUI with ratatui
- [x] Hop statistics (loss, min/avg/max, stddev, jitter)
- [x] Enhanced jitter stats (avg, max, last RTT)
- [x] RTT percentiles (p50, p95, p99) from sample history
- [x] ECMP detection (multiple responders per TTL)
- [x] Paris/Dublin traceroute (multi-flow ECMP path enumeration)
- [x] NAT detection (source port rewrite detection)
- [x] ICMP rate limit detection (identify misleading loss% from router limits)
- [x] Reverse DNS resolution (parallel lookups)
- [x] MPLS label detection (RFC 4884/4950 ICMP extensions)
- [x] JSON, CSV, and report export formats (with full enrichment)
- [x] Session replay from saved JSON
- [x] Pause/resume probing
- [x] Stats reset
- [x] Destination detection (stops at actual hop count)
- [x] Race-free probe correlation (shared pending map)
- [x] Terminal state cleanup on error/panic
- [x] Interface binding (`--interface`, `--recv-any`)
- [x] Shell completions (`--completions bash/zsh/fish/powershell`)
- [x] Terminal injection protection (sanitize external data)

### Probing Modes
- [x] ICMP Echo (default for privileged users)
- [x] UDP probing (`-p udp`)
- [x] TCP SYN probing (`-p tcp`)
- [x] Protocol auto-detection (`-p auto`, new default)
- [x] Custom port selection (`--port`, `--fixed-port`)
- [x] Multi-flow probing (`--flows`, `--src-port`)

### Enrichment
- [x] ASN lookup (Team Cymru DNS)
- [x] GeoIP lookup (MaxMind GeoLite2)
- [x] IX detection (PeeringDB)

### TUI Features
- [x] Interactive hop selection with j/k navigation
- [x] Hop detail modal view (with percentiles, jitter, MPLS)
- [x] Loss-aware sparkline visualization
- [x] Help overlay
- [x] Settings modal (theme + wide mode)
- [x] Target list overlay (multi-target mode)
- [x] Status bar with keybind hints
- [x] Theme support (11 built-in themes via --theme flag)
- [x] Theme persistence (~/.config/ttl/config.toml)
- [x] Wide mode persistence

### Platform Support
- [x] Linux (raw sockets with CAP_NET_RAW or root)
- [x] macOS (requires root, uses DGRAM sockets for proper TTL support)
- [ ] Windows (not supported - requires WinPcap/Npcap)

## Planned Features

### v0.2.0 - Robustness & Enrichment
- [x] Receiver panic handler for clean shutdown
- [x] Receiver error tracking (stop after consecutive failures)
- [x] Parallel DNS lookups for faster resolution
- [x] ASN lookup (Team Cymru DNS)
- [x] GeoIP lookup (MaxMind GeoLite2)
- [x] UDP probing mode
- [x] Hide internal APIs (library boundary cleanup)
- [x] Document jitter semantics (RTT variance vs RFC 3550)
- [x] High-rate mode optimizations (max drain count, reduced lock contention)

### v0.3.0 - Probing Modes
- [x] UDP probing mode (completed in v0.2.0)
- [x] TCP SYN probing mode
- [x] Custom port selection (`--fixed-port` flag)
- [x] Protocol auto-detection fallback (`-p auto` default)

### v0.4.0 - Enrichment
- [x] ASN lookup (Team Cymru DNS) (completed in v0.2.0)
- [x] Geolocation display (MaxMind) (completed in v0.2.0)
- [x] MPLS label detection (ICMP extensions)
- [x] Network provider/ISP display (ASN column in main table)

### v0.5.0 - Advanced ECMP (Released)
- [x] Paris traceroute (flow-aware) - multi-flow probing with source port variation
- [x] Dublin traceroute - systematic flow enumeration via `--flows` flag
- [x] Flow-level display (per-path stats) - "Paths" column and hop detail view

### v0.6.0 - Multi-target (Released)
- [x] NAT detection (completed in v0.5.1)
- [x] Multiple simultaneous targets (`ttl 8.8.8.8 1.1.1.1 9.9.9.9`)
- [x] Tab/n/N to cycle between targets in TUI
- [x] Per-target pause/reset
- [x] Target indicator in title bar `[1/3]`
- [ ] Target groups/presets
- [ ] Comparative views
- [ ] Split-screen mode

### v0.7.0 - Interface Binding (Released)
- [x] Source interface selection (`--interface eth0`)
- [x] Asymmetric routing support (`--recv-any`)
- [x] Cross-platform binding (Linux SO_BINDTODEVICE, macOS IP_BOUND_IF)
- [x] IPv6 link-local detection and rejection
- [x] Interface-aware auto-protocol detection

### v0.8.0 - Probe Control & MTU (Released)
- [x] Source IP selection (`--source-ip 10.0.0.1`)
- [x] Packet size control (`--size 1400`)
- [x] Path MTU discovery mode (`--pmtud`, binary search for max unfragmented size)
- [x] DSCP/ToS marking (`--dscp 46`) for QoS policy testing
- [x] Flows per second control (`--rate`)
- [x] First-hop gateway detection (show source IP and gateway in TUI title bar)

### v0.9.0 - IX Detection (Released)
- [x] IX detection via PeeringDB (identify Internet Exchange points in path)
- [x] Local cache for PeeringDB data (24 hour TTL)
- [x] IX info shown in hop detail view
- [x] `--no-ix` flag to disable

### v0.10.0 - Rate Limit Detection (Released)
- [x] Rate limit detection (identify ICMP rate limiting, explain misleading loss%)
- [x] Asymmetric routing detection (compare forward path TTLs in responses)
- [x] Route flap/change detection (alert on path changes, show in TUI)
- [x] TTL manipulation detection (identify middlebox TTL changes via quoted TTL analysis)
- [ ] Packet loss pattern analysis (bursty vs random loss classification)
- [ ] DNS resolution timing (separate DNS latency from network latency)
- [ ] IPv4 + IPv6 simultaneous (happy eyeballs dual-stack testing)

### v0.11.0 - macOS Fix (Released)
- [x] macOS ICMP traceroute fix (use SOCK_DGRAM for IP_TTL support)
- [x] DGRAM-aware packet parsing (handle missing IP header)
- [x] ProbeId payload fallback (handle macOS identifier override)
- [x] Homebrew formula and curl installer

### v0.11.1 - macOS Fix Part 2 (Released)
- [x] macOS: Use RAW recv + DGRAM send (DGRAM can't receive Time Exceeded)
- [x] Payload-based correlation fallback for RAW receive paths
- [x] Restore Linux unprivileged ICMP support (broken in v0.11.0)
- [x] IPv6 DGRAM availability check with warning on macOS

### v0.12.0 - Shell Completions (Released)
- [x] Shell completion generation (`--completions bash/zsh/fish/powershell`)
- [x] Dependency updates (hickory-resolver 0.25, socket2 0.6, reqwest 0.13)

### v0.12.1 - Security & Polish (Released)
- [x] Terminal injection protection (sanitize DNS hostnames, ASN names, IX info)
- [x] Fixed `--count` semantics (now counts probe rounds, not total probes)
- [x] Port overflow validation (`--src-port` + `--flows` bounds checking)
- [x] Sequence wrap prevention (reject timeout > 256 × interval)

### v0.12.2 - Documentation (Released)
- [x] Improved Quick Start with prominent Linux setcap instructions

### v0.12.3 - Bug Fix (Released)
- [x] Fixed hop detail view showing "Sent: 0" (was using wrong counter)
- [x] Added "Hop totals" label for ECMP clarity

### v0.12.4 - Linux Compatibility (Released)
- [x] Switch Linux x86_64 builds to musl libc for glibc compatibility
- [x] Pre-built binaries now work on Debian 11/12 and other older distros

### v0.12.5 - IPv6 ICMP Fix Part 1 (Released)
- [x] Fix IPv6 ICMP traceroute 100% packet loss on Linux destination hop
- [x] Add send socket polling for Echo Reply in IPv6 ICMP mode
- [x] Fix ICMPv6 Echo Request type (128, was incorrectly using type 8)

### v0.12.6 - IPv6 ICMP Fix Part 2 (Released)
- [x] Fix ICMPv6 checksum computation (was 0, destinations dropped packets)
- [x] Add manual ICMPv6 checksum with RFC 8200 pseudo-header
- [x] Bind IPv6 sockets to source IP for checksum consistency
- [x] Increase IPv6 address display width in TUI and reports

### v0.13.0 - Multi-IP Resolution & Settings (In Progress)
- [x] Multi-IP resolution (`--resolve-all`) for round-robin DNS and dual-stack hosts
- [x] Target list overlay (`l` key) showing all resolved targets with stats
- [x] Settings modal (`s` key) for theme, wide mode, and PeeringDB configuration
- [x] Wide mode CLI flag (`--wide`) and persistence
- [x] Wide mode saved to config file
- [x] PeeringDB API key configuration in settings modal
- [x] PeeringDB cache status display (prefix count, age, expiry)
- [x] Cache refresh from settings (`r` key in PeeringDB section)
- [x] Fix macOS probe TTL batching issue (#12) - add minimum inter-probe delay

### v1.0.0 - BGP & Routing Integration
- [ ] Looking glass integration (query public route servers)
- [ ] BGP community display (show communities on path if available)
- [ ] RPKI/ROA validation (prefix origin validation for each hop)
- [ ] AS path display (full BGP AS path where available)

### v1.1.0 - Operational Features
- [ ] Baseline comparison (save baseline, alert on deviations)
- [ ] Threshold alerts (configurable latency/loss/jitter alerts)
- [ ] Prometheus/OpenMetrics export (for monitoring dashboards)
- [ ] Continuous logging mode (log path changes over hours/days)
- [ ] Network topology learning (build graph from multiple traces over time)
- [ ] Historical data storage (SQLite/file-based path history)

### v1.2.0 - Advanced Protocol Testing
- [ ] TCP behavior testing (MSS clamping, window scaling, SACK)
- [ ] ECN testing (Explicit Congestion Notification support)
- [ ] Fragmentation testing (test behavior at different packet sizes)
- [ ] Multi-path validation (verify all ECMP paths are functional)

### TUI Polish (Deferred)
- [ ] Customizable columns (choose which stats to display)
- [ ] Custom keybindings
- [ ] World map visualization (ASCII/Unicode geographic path display)

### Testing & Code Quality
- [x] Integration tests for probe→receive→state pipeline
- [x] Property-based/fuzz tests for packet parsing (correlate.rs)
- [x] RAW payload fallback unit tests (IPv4 Echo Reply, Time Exceeded)
- [ ] IPv6 RAW payload fallback unit tests (Echo Reply, Time Exceeded)
- [ ] IX lookup performance: radix trie for O(prefix_len) instead of O(n) linear scan
- [x] Refactor Receiver::new() 9-arg signature to config struct
- [x] Document --pmtud flag in README
- [x] Fix naming inconsistency: fixed_port (CLI) vs port_fixed (Config)

### Infrastructure
- [x] GitHub Actions CI (build, test, clippy)
- [x] Binary releases (Linux x86_64/aarch64, macOS aarch64)
- [x] Homebrew formula (`brew install lance0/tap/ttl`)
- [x] Curl installer (`curl -fsSL https://raw.githubusercontent.com/lance0/ttl/master/install.sh | sh`)
- [ ] AUR package

### Future Ideas
- [ ] Bidirectional probing (with remote agent, measure both directions)
- [ ] One-way delay estimation (detect latency asymmetry)
- [ ] Bandwidth/capacity estimation (pathchar-style probing)
- [ ] SNMP integration (query router interface stats)
- [ ] Web UI mode (browser-based interface)
- [ ] Packet capture integration (optional pcap output)

## Scope Creep (Not Planned)
- Hop privacy mode (mask IPs for screenshots) - users can redact manually
- Multi-language TUI (i18n) - English-only is fine for CLI tools

## Non-Goals
- Full packet capture/analysis (use tcpdump/wireshark)
- Bandwidth testing (use iperf)
- Port scanning (use nmap)
