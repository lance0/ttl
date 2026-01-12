# ttl Roadmap

## Current Status (v0.1.2)

### Core Features
- [x] ICMP Echo probing with TTL sweep
- [x] IPv4 and IPv6 support with extension header handling
- [x] Real-time TUI with ratatui
- [x] Hop statistics (loss, min/avg/max, stddev, jitter)
- [x] ECMP detection (multiple responders per TTL)
- [x] Reverse DNS resolution
- [x] JSON, CSV, and report export formats
- [x] Session replay from saved JSON
- [x] Pause/resume probing
- [x] Stats reset
- [x] Destination detection (stops at actual hop count)
- [x] Race-free probe correlation (shared pending map)

### TUI Features
- [x] Interactive hop selection with j/k navigation
- [x] Hop detail modal view
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

### v0.2.0 - Robustness
- [ ] Receiver panic handler for clean shutdown
- [ ] Receiver error tracking (stop after consecutive failures)
- [ ] Parallel DNS lookups for faster resolution
- [ ] Hide internal APIs (library boundary cleanup)
- [ ] Document jitter semantics (RTT variance vs RFC 3550)

### v0.3.0 - Enrichment
- [ ] ASN lookup via MaxMind GeoLite2
- [ ] Geolocation display
- [ ] IP-to-ASN mapping
- [ ] Network path visualization

### v0.4.0 - Multi-target
- [ ] Multiple simultaneous targets
- [ ] Target groups/presets
- [ ] Comparative views

### v0.5.0 - Advanced Probing
- [ ] UDP probing mode
- [ ] TCP SYN probing mode
- [ ] Custom port selection
- [ ] Paris traceroute (flow-aware)

### Future Ideas
- [ ] Historical data storage
- [ ] Alert thresholds (latency/loss)
- [ ] Web UI mode
- [ ] Prometheus metrics export
- [ ] MPLS label detection
- [ ] Path MTU discovery

## Non-Goals
- Full packet capture/analysis (use tcpdump/wireshark)
- Bandwidth testing (use iperf)
- Port scanning (use nmap)
