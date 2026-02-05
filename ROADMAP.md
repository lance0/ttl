# ttl Roadmap

## Current Status (v0.16.0)

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
- [x] Animated replay with speed control
- [x] Pause/resume probing
- [x] Stats reset
- [x] Destination detection (stops at actual hop count)
- [x] Race-free probe correlation (shared pending map)
- [x] Immediate sent counting (mtr parity — sent increments at probe send, not response)
- [x] Dual-stack `--resolve-all` (trace IPv4 and IPv6 simultaneously)
- [x] Terminal state cleanup on error/panic
- [x] Interface binding (`--interface`, `--recv-any`)
- [x] Shell completions (`--completions bash/zsh/fish/powershell`)
- [x] Terminal injection protection (sanitize external data)
- [x] FreeBSD build support

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
- [x] Settings modal (theme + display mode + PeeringDB)
- [x] Target list overlay (multi-target mode)
- [x] Status bar with keybind hints
- [x] Theme support (11 built-in themes via --theme flag)
- [x] Theme persistence (~/.config/ttl/config.toml)
- [x] Display mode (auto/compact/wide) with `w` key cycling
- [x] Autosize columns in auto mode (fit to content, capped)

### Platform Support
- [x] Linux (raw sockets with CAP_NET_RAW or root)
- [x] macOS (requires root, uses DGRAM sockets for proper TTL support)
- [x] FreeBSD (raw sockets, gateway detection unavailable)

## Planned Features

### v0.15.0 - Animated Replay (#9) ✓
- [x] TUI refresh rate increased to 60fps (from 10fps) for responsive updates (#17)
- [x] ProbeEvent recording during trace (offset_ms, ttl, seq, flow_id, response/timeout)
- [x] Session JSON includes events array (backward compatible)
- [x] `--animate` flag for replay mode
- [x] Animated replay shows hop-by-hop discovery in TUI
- [x] Space/p to pause/resume replay
- [x] Graceful fallback for old sessions without events
- [x] Replay speed control (`--speed` multiplier, default 10x)
- [x] Monotonic event timestamps (immune to clock jumps)
- [x] Late reply tracking for replay accuracy
- [ ] Progress indicator in status bar
- [ ] Interactive replay (step through events, jump to time)

### v0.16.0 - Trace Diffing & Streaming
- [ ] Trace comparison (`ttl --diff trace1.json trace2.json`)
- [ ] Show added/removed/changed hops between two sessions
- [ ] Highlight latency and path changes
- [ ] Streaming JSON output (`--stream-json`) for piping to other tools
- [ ] Line-delimited JSON (one event per line, composable with jq/grep)

### v0.17.0 - Docker & Daemon Mode
- [ ] Official Dockerfile (minimal image, NET_RAW capability)
- [ ] `--daemon` mode (no TUI, lightweight, signal handling)
- [ ] Prometheus/OpenMetrics exporter (`--prometheus :9090`)
- [ ] Health check endpoint for container orchestration

### v0.18.0 - Interactive Target Selection
- [ ] `ttl` with no args enters interactive mode
- [ ] Press `o` to open target input modal
- [ ] Text input with hostname/IP validation
- [ ] DNS resolution with loading state
- [ ] First target determines IPv4/IPv6 family for session
- [ ] Add additional targets mid-session (same family only)
- [ ] Empty state UI: "Press 'o' to add target"

### v1.0.0 - Stable Release
- [ ] Library API stabilization (stable `lib.rs` for third-party integrations)
- [ ] Comprehensive documentation for library consumers
- [ ] Semantic versioning commitment
- [ ] PCAP export (write probe/response packets to .pcap for Wireshark analysis)

### v1.1.0 - BGP & Routing Integration
- [ ] Looking glass integration (query public route servers)
- [ ] BGP community display (show communities on path if available)
- [ ] RPKI/ROA validation (prefix origin validation for each hop)
- [ ] AS path display (full BGP AS path where available)

### v1.2.0 - Operational Features
- [ ] Baseline comparison (save baseline, alert on deviations)
- [ ] Threshold alerts (configurable latency/loss/jitter alerts)
- [ ] Continuous logging mode (log path changes over hours/days)
- [ ] Historical data storage (SQLite/file-based path history)

### v1.3.0 - Advanced Protocol Testing
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
- [x] GitHub Actions CI (build, test, clippy, FreeBSD)
- [x] Binary releases (Linux x86_64/aarch64, macOS aarch64)
- [x] Homebrew formula (`brew install lance0/tap/ttl`)
- [x] Curl installer (`curl -fsSL https://raw.githubusercontent.com/lance0/ttl/master/install.sh | sh`)
- [x] Dependabot (Cargo + GitHub Actions)
- [x] AUR package (`ttl-bin`, community-maintained)
- [x] Gentoo package (`net-analyzer/ttl`, official repository)
- [ ] Docker Hub image

### Future Ideas
- [ ] Bidirectional probing (with remote agent, measure both directions)
- [ ] One-way delay estimation (detect latency asymmetry)
- [ ] Bandwidth/capacity estimation (pathchar-style probing)
- [ ] SNMP integration (query router interface stats)
- [ ] Network topology learning (build graph from multiple traces over time)

## Scope Creep (Not Planned)
- Web/mobile UI - this is a CLI tool, SSH into a box
- Shareable URLs / hosted trace service - JSON files are the sharing format
- Webhook/event streaming - use `--stream-json | curl` instead
- Monitor mode with alerting - use Smokeping/Nagios for long-running monitoring
- Modular output plugins - Unix pipes are the plugin system
- Windows native support - massive Npcap effort, WSL2 works, revisit if demand warrants
- Hop privacy mode (mask IPs for screenshots) - users can redact manually
- Multi-language TUI (i18n) - English-only is fine for CLI tools

## Non-Goals
- Full packet capture/analysis (use tcpdump/wireshark)
- Bandwidth testing (use iperf)
- Port scanning (use nmap)
- Enterprise collaboration platform
