# ttl Roadmap

## Current Status (v0.5.1)

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
- [x] Reverse DNS resolution (parallel lookups)
- [x] MPLS label detection (RFC 4884/4950 ICMP extensions)
- [x] JSON, CSV, and report export formats
- [x] Session replay from saved JSON
- [x] Pause/resume probing
- [x] Stats reset
- [x] Destination detection (stops at actual hop count)
- [x] Race-free probe correlation (shared pending map)

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

### TUI Features
- [x] Interactive hop selection with j/k navigation
- [x] Hop detail modal view (with percentiles, jitter, MPLS)
- [x] Loss-aware sparkline visualization
- [x] Help overlay
- [x] Status bar with keybind hints
- [x] Theme support (11 built-in themes via --theme flag)
- [x] Theme persistence (~/.config/ttl/config.toml)

### Platform Support
- [x] Linux (raw sockets with CAP_NET_RAW or root)
- [x] macOS (requires root)
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

### v0.6.0 - Multi-target
- [x] NAT detection (completed in v0.5.1)
- [ ] Multiple simultaneous targets
- [ ] Target groups/presets
- [ ] Comparative views
- [ ] Split-screen mode

### v0.7.0 - TUI Polish
- [ ] Customizable columns (choose which stats to display)
- [ ] Custom keybindings
- [ ] World map visualization (ASCII/Unicode geographic path display)
- [ ] Hop privacy mode (mask sensitive IPs for screenshots/sharing)

### v0.8.0 - Probe Control & MTU
- [ ] Source interface selection (`--interface eth0`)
- [ ] Source IP selection (`--source-ip 10.0.0.1`)
- [ ] Packet size control (`--size 1400`)
- [ ] Path MTU discovery mode (binary search for max unfragmented size)
- [ ] DSCP/ToS marking (`--dscp 46`) for QoS policy testing
- [ ] Flows per second control (`--rate`)
- [ ] First-hop gateway detection (show which interface/gateway is used)

### v0.9.0 - Advanced Diagnostics
- [ ] Rate limit detection (identify ICMP rate limiting, explain misleading loss%)
- [ ] Asymmetric routing detection (compare forward path TTLs in responses)
- [ ] Route flap/change detection (alert on path changes, log history)
- [ ] Packet loss pattern analysis (bursty vs random loss classification)
- [ ] DNS resolution timing (separate DNS latency from network latency)
- [ ] IPv4 + IPv6 simultaneous (happy eyeballs dual-stack testing)
- [ ] TTL manipulation detection (identify middlebox TTL changes)

### v1.0.0 - BGP & Routing Integration
- [ ] Looking glass integration (query public route servers)
- [ ] BGP community display (show communities on path if available)
- [ ] IX detection (identify Internet Exchange points in path)
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

### Future Ideas
- [ ] Bidirectional probing (with remote agent, measure both directions)
- [ ] One-way delay estimation (detect latency asymmetry)
- [ ] Bandwidth/capacity estimation (pathchar-style probing)
- [ ] SNMP integration (query router interface stats)
- [ ] Web UI mode (browser-based interface)
- [ ] Multi-language TUI (i18n support)
- [ ] Packet capture integration (optional pcap output)

## Non-Goals
- Full packet capture/analysis (use tcpdump/wireshark)
- Bandwidth testing (use iperf)
- Port scanning (use nmap)
