# ttl Roadmap

## Current Status (v0.1.2)

### Core Features
- [x] ICMP Echo probing with TTL sweep
- [x] IPv4 and IPv6 support with extension header handling
- [x] Real-time TUI with ratatui
- [x] Hop statistics (loss, min/avg/max, stddev, jitter)
- [x] Enhanced jitter stats (avg, max, last RTT)
- [x] RTT percentiles (p50, p95, p99) from sample history
- [x] ECMP detection (multiple responders per TTL)
- [x] Reverse DNS resolution (parallel lookups)
- [x] MPLS label detection (RFC 4884/4950 ICMP extensions)
- [x] JSON, CSV, and report export formats
- [x] Session replay from saved JSON
- [x] Pause/resume probing
- [x] Stats reset
- [x] Destination detection (stops at actual hop count)
- [x] Race-free probe correlation (shared pending map)

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
- [ ] Document jitter semantics (RTT variance vs RFC 3550)
- [ ] High-rate mode optimizations (max drain count, reduced lock contention)

### v0.3.0 - Probing Modes
- [x] UDP probing mode (completed in v0.2.0)
- [ ] TCP SYN probing mode
- [ ] Custom port selection
- [ ] Protocol auto-detection fallback

### v0.4.0 - Enrichment
- [x] ASN lookup (Team Cymru DNS) (completed in v0.2.0)
- [x] Geolocation display (MaxMind) (completed in v0.2.0)
- [x] MPLS label detection (ICMP extensions)
- [ ] Network provider/ISP display

### v0.5.0 - Advanced ECMP
- [ ] Paris traceroute (flow-aware)
- [ ] Dublin traceroute
- [ ] Flow-level display (per-path stats)
- [ ] NAT detection

### v0.6.0 - Multi-target
- [ ] Multiple simultaneous targets
- [ ] Target groups/presets
- [ ] Comparative views
- [ ] Split-screen mode

### v0.7.0 - TUI Polish
- [ ] Customizable columns
- [ ] Custom keybindings
- [ ] World map visualization (optional)
- [ ] Hop privacy mode (hide sensitive IPs)

### Future Ideas
- [ ] Historical data storage
- [ ] Alert thresholds (latency/loss)
- [ ] Web UI mode
- [ ] Prometheus metrics export
- [ ] Path MTU discovery
- [ ] Multi-language TUI

## Non-Goals
- Full packet capture/analysis (use tcpdump/wireshark)
- Bandwidth testing (use iperf)
- Port scanning (use nmap)
