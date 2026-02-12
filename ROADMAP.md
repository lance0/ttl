# ttl Roadmap

## Market Context

**mtr is the de facto standard** for interactive traceroute but hasn't seen major feature development in years. **trippy** (Rust) is the main modern alternative but focuses on a different feature set.

**Key advantages ttl already has:**
- ECMP path enumeration (Paris/Dublin traceroute with `--flows`)
- NAT detection (source port rewrite analysis)
- ICMP rate limit detection (distinguish rate limiting from real loss)
- Route flap and asymmetric routing detection
- TTL manipulation detection (transparent proxies, middleboxes)
- Path MTU discovery (`--pmtud`)
- IX detection via PeeringDB
- Animated session replay
- Dual-stack `--resolve-all` (trace IPv4 and IPv6 simultaneously)

---

## Completed (v0.1.x - v0.6.x)

- [x] ICMP Echo probing with TTL sweep
- [x] IPv4 and IPv6 support with extension header handling
- [x] Real-time TUI with ratatui (11 built-in themes)
- [x] Hop statistics (loss, min/avg/max, stddev, jitter, percentiles)
- [x] Reverse DNS resolution (parallel lookups)
- [x] MPLS label detection (RFC 4884/4950 ICMP extensions)
- [x] JSON, CSV, and report export formats
- [x] Session replay from saved JSON
- [x] Multiple simultaneous targets (`ttl 8.8.8.8 1.1.1.1`)
- [x] NAT detection (source port rewrite analysis)
- [x] Paris/Dublin traceroute (`--flows` for ECMP path enumeration)
- [x] UDP probing (`-p udp`) and TCP SYN probing (`-p tcp`)
- [x] Protocol auto-detection (`-p auto`, default)
- [x] ASN lookup (Team Cymru DNS), GeoIP (MaxMind), IX detection (PeeringDB)
- [x] Terminal injection protection (sanitize external data)
- [x] Terminal state cleanup on error/panic

## Completed (v0.7.x - v0.12.x)

- [x] Interface binding (`--interface`, `--recv-any`)
- [x] Shell completions (`--completions bash/zsh/fish/powershell`)
- [x] Settings modal (theme, display mode, PeeringDB API key)
- [x] Target list overlay for multi-target mode
- [x] Autosize columns (auto/compact/wide with `w` key cycling)
- [x] Linux binary compatibility (musl libc for broad distro support)

## Completed (v0.13.x - v0.14.x)

- [x] Path MTU discovery (`--pmtud`) with binary search
- [x] Packet size control (`--size`) with DF flag
- [x] DSCP/ToS marking (`--dscp`) for QoS policy testing
- [x] ICMP rate limit detection with TUI indicators
- [x] Route flap detection (primary responder IP changes)
- [x] Asymmetric routing detection (forward vs return path hops)
- [x] TTL manipulation detection (transparent proxies, middleboxes)
- [x] First-hop gateway detection via kernel APIs (netlink/sysctl)
- [x] Rate limiting (`--rate`) for slow links
- [x] Source IP selection (`--source-ip`)
- [x] Update notifications (checks GitHub releases, install-method-aware)
- [x] FreeBSD support (experimental, raw sockets)

## Completed (v0.15.x - v0.17.x)

- [x] Animated replay (`--replay file --animate`) with speed control
- [x] Probe event recording for replay accuracy
- [x] TUI refresh rate increased to 60fps (#17)
- [x] Jumbo frame support (`--size` up to 9216, `--jumbo` for PMTUD)
- [x] Immediate sent counting (mtr parity — increments at probe send, not response)
- [x] Dual-stack `--resolve-all` (trace IPv4 and IPv6 simultaneously)
- [x] FreeBSD ICMP socket fix (RAW sockets, not DGRAM)
- [x] Last RTT column in main table (mtr parity — `Loss% Snt Last Avg Min Max StdDev`)
- [x] JAvg and JMax columns in Wide display mode
- [x] Wider ASN column for full AS name visibility

---

## Planned Features

### Next — Trace Diffing & Streaming

**Why this matters:** Users frequently need to compare traces taken at different times (before/after a change, during/after an incident). Streaming output enables integration with monitoring pipelines.

- [ ] Trace comparison (`ttl --diff trace1.json trace2.json`)
- [ ] Show added/removed/changed hops between two sessions
- [ ] Highlight latency and path changes
- [ ] Streaming JSON output (`--stream-json`) for piping to other tools
- [ ] Line-delimited JSON (one event per line, composable with jq/grep)

### Docker & Daemon Mode

**Why this matters:** Containerized infrastructure needs lightweight, headless traceroute for continuous path monitoring and integration with Prometheus/Grafana.

- [ ] Official Dockerfile (minimal image, NET_RAW capability)
- [ ] `--daemon` mode (no TUI, lightweight, signal handling)
- [ ] Prometheus/OpenMetrics exporter (`--prometheus :9090`)
- [ ] Health check endpoint for container orchestration

### Interactive Target Selection

**Why this matters:** Power users want to add and manage targets without restarting. This makes ttl a persistent network investigation tool.

- [ ] `ttl` with no args enters interactive mode
- [ ] Press `o` to open target input modal
- [ ] Text input with hostname/IP validation
- [ ] DNS resolution with loading state
- [ ] Add additional targets mid-session
- [ ] Empty state UI: "Press 'o' to add target"

---

## Future Ideas

*Prioritized by effort vs user impact. Quick wins first, then bigger lifts.*

### Quick Wins (low effort, high impact)
- [ ] **Progress indicator in replay** — show position in timeline during animated replay
- [ ] **Interactive replay** — step through events, jump to time
- [ ] **IPv6 RAW payload fallback tests** — unit tests for IPv6 Echo Reply and Time Exceeded parsing

### Medium Effort (moderate effort, high impact)
- [ ] **PCAP export** — write probe/response packets to .pcap for Wireshark analysis
- [ ] **IX lookup performance** — radix trie for O(prefix_len) instead of O(n) linear scan
- [ ] **Customizable columns** — choose which stats to display in TUI
- [ ] **Docker Hub image** — pre-built container for CI/monitoring pipelines

### Larger Projects (high effort, high impact)
- [ ] **BGP & routing integration** — looking glass queries, AS path display, RPKI/ROA validation
- [ ] **Baseline comparison** — save baseline, alert on latency/loss/path deviations
- [ ] **Continuous logging mode** — log path changes over hours/days
- [ ] **Historical data storage** — SQLite/file-based path history

### Nice to Have
- [ ] **Custom keybindings** — user-configurable key mappings
- [ ] **World map visualization** — ASCII/Unicode geographic path display
- [ ] **Advanced protocol testing** — TCP MSS clamping, ECN, fragmentation testing
- [ ] **Multi-path validation** — verify all ECMP paths are functional

---

## Pre-1.0 Requirements

### Code Quality
- [ ] Library API stabilization (stable `lib.rs` for third-party integrations)
- [ ] Comprehensive documentation for library consumers
- [ ] Semantic versioning commitment

### Testing
- [x] Integration tests for probe-receive-state pipeline
- [x] Property-based/fuzz tests for packet parsing (correlate.rs)
- [x] RAW payload fallback unit tests (IPv4)
- [ ] IPv6 RAW payload fallback unit tests
- [ ] Concurrent multi-target stress tests

---

## Low Priority

### Windows Native
- [ ] Basic ICMP traceroute (Npcap or Winsock raw sockets)
- [ ] TUI compatibility with Windows Terminal
- [ ] Pre-built binaries

*Rationale: Massive Npcap effort. WSL2 works well. Revisit if demand warrants.*

### Bidirectional Probing
- [ ] Remote agent for measuring both directions
- [ ] One-way delay estimation (detect latency asymmetry)

*Rationale: Requires deploying an agent on the remote side, which changes the tool's simplicity model.*

### Advanced Network Analysis
- [ ] Bandwidth/capacity estimation (pathchar-style probing)
- [ ] SNMP integration (query router interface stats)
- [ ] Network topology learning (build graph from multiple traces)

*Rationale: These push ttl toward being a full network management tool. Better served by purpose-built tools.*

---

## Competitive Landscape

| Tool | Language | ECMP | MTU Discovery | Rate Limit Detection | TUI | Active Development |
|------|----------|------|---------------|---------------------|-----|-------------------|
| mtr | C | No | No | No | Yes | Maintenance |
| trippy | Rust | No | No | No | Yes | Active |
| traceroute | C | No | Yes | No | No | Maintenance |
| tracepath | C | No | Yes | No | No | Maintenance |
| **ttl** | Rust | Yes | Yes | Yes | Yes | Active |

---

## Scope Creep / Non-Goals

ttl is a **CLI traceroute tool**. The following are explicitly out of scope:

- **Web/mobile UI** — this is a CLI tool, SSH into a box
- **Shareable URLs / hosted trace service** — JSON files are the sharing format
- **Webhook/event streaming** — use `--stream-json | curl` instead
- **Monitor mode with alerting** — use Smokeping/Nagios for long-running monitoring
- **Modular output plugins** — Unix pipes are the plugin system
- **Hop privacy mode** (mask IPs for screenshots) — users can redact manually
- **Multi-language TUI** (i18n) — English-only is fine for CLI tools
- **Full packet capture** — use tcpdump/wireshark
- **Bandwidth testing** — use [xfr](https://github.com/lance0/xfr) or iperf
- **Port scanning** — use nmap
- **Enterprise collaboration platform** — not a SaaS product

If you need these features, combine ttl with purpose-built tools.

---

## Known Limitations

See [KNOWN_ISSUES.md](KNOWN_ISSUES.md) for documented edge cases and limitations.

---

## Infrastructure

- [x] GitHub Actions CI (build, test, clippy, FreeBSD)
- [x] Binary releases (Linux x86_64/aarch64, macOS x86_64/aarch64)
- [x] Homebrew formula (`brew install lance0/tap/ttl`)
- [x] Curl installer (`install.sh`)
- [x] Dependabot (Cargo + GitHub Actions)
- [x] AUR package (`ttl-bin`, community-maintained)
- [x] Gentoo package (`net-analyzer/ttl`, official repository)
- [ ] Docker Hub image

---

## Contributing

See issues labeled `good first issue` for entry points. PRs welcome for any roadmap item.
