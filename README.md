# ttl

Modern traceroute/mtr-style TUI with hop stats and optional ASN/geo enrichment.

[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE-MIT)

## Features

- Fast, low-overhead continuous path monitoring
- **Multiple simultaneous targets**: Trace to several destinations at once
- Useful hop-level stats (loss, min/avg/max, jitter, stddev, percentiles)
- RTT percentiles (p50, p95, p99) from sample history
- MPLS label detection from ICMP extensions
- ASN lookup via Team Cymru DNS (enabled by default)
- GeoIP lookup via MaxMind GeoLite2 database
- ICMP, UDP, and TCP probing modes with auto-detection
- **Paris/Dublin traceroute**: Multi-flow probing for ECMP path enumeration
- **NAT detection**: Identify when NAT devices rewrite source ports
- Great terminal UX built with ratatui
- Scriptable mode for CI and automation
- Reverse DNS resolution (parallel lookups)
- ECMP detection (multiple responders per TTL)
- Multiple export formats (JSON, CSV)
- Session replay from saved JSON files
- IPv4 and IPv6 support

## Installation

### From crates.io

```bash
cargo install ttl
```

### From source

```bash
cargo install --git https://github.com/lance0/ttl
```

### Permissions

Raw sockets require elevated privileges. Choose one:

```bash
# Option 1: Run with sudo
sudo ttl 1.1.1.1

# Option 2: Add capability (Linux)
sudo setcap cap_net_raw+ep $(which ttl)

# Option 3: Enable unprivileged ICMP (Linux)
sudo sysctl -w net.ipv4.ping_group_range='0 65534'
```

## Platform Support

| Platform | Status | Notes |
|----------|--------|-------|
| Linux | Full support | Raw sockets require `CAP_NET_RAW` or root |
| macOS | Full support | Requires root |
| Windows | Not supported | Would require WinPcap/Npcap |

## Usage

### Interactive TUI (default)

```bash
ttl 1.1.1.1
ttl google.com
```

### Multiple targets

```bash
# Trace to multiple destinations simultaneously
ttl 8.8.8.8 1.1.1.1 9.9.9.9

# Use Tab/n to switch between targets, Shift-Tab/N for previous
# Each target shows independent hop data
```

### Report mode

```bash
ttl 1.1.1.1 -c 100 --report
```

### JSON export

```bash
ttl 1.1.1.1 -c 100 --json > results.json
```

### CSV export

```bash
ttl 1.1.1.1 -c 100 --csv > results.csv
```

### Replay a saved session

```bash
ttl --replay results.json --report
ttl --replay results.json           # opens in TUI
```

### Streaming output

```bash
ttl 1.1.1.1 --no-tui
```

### Probing modes

```bash
# Auto-detect best protocol (default): ICMP → UDP → TCP
ttl 1.1.1.1

# Force specific protocol
ttl 1.1.1.1 -p icmp             # ICMP Echo (requires raw sockets)
ttl 1.1.1.1 -p udp              # UDP to high ports
ttl 1.1.1.1 -p tcp              # TCP SYN probes

# Custom port
ttl 1.1.1.1 -p udp --port 33500 # Custom base port
ttl 1.1.1.1 -p tcp --port 443   # Probe HTTPS port

# Fixed port (disable per-TTL variation)
ttl 1.1.1.1 -p udp --port 53 --fixed-port  # Probe DNS specifically
```

### Multi-flow ECMP detection (Paris/Dublin traceroute)

```bash
# Discover ECMP paths with 4 flows
ttl 1.1.1.1 --flows 4

# More flows for thorough path enumeration
ttl 1.1.1.1 --flows 8 -p udp

# Custom source port base
ttl 1.1.1.1 --flows 4 --src-port 33000
```

Each flow uses a different source port, causing ECMP routers to route flows along different paths. The TUI shows a "Paths" column when `--flows > 1`, highlighted when multiple paths are detected.

### Options

```
-c, --count <N>      Number of probes (0 = infinite, default)
-i, --interval <S>   Probe interval in seconds (default: 1.0)
-m, --max-ttl <N>    Maximum TTL (default: 30)
-p, --protocol <P>   Probe protocol: auto (default), icmp, udp, tcp
--port <N>           Base port for UDP/TCP probes
--fixed-port         Use fixed port (disable per-TTL variation)
--flows <N>          Number of flows for ECMP detection (1-16, default: 1)
--src-port <N>       Base source port for multi-flow (default: 50000)
--timeout <S>        Probe timeout in seconds (default: 3)
-4, --ipv4           Force IPv4
-6, --ipv6           Force IPv6
--no-dns             Skip reverse DNS lookups
--no-asn             Skip ASN enrichment
--no-geo             Skip geolocation
--geoip-db <PATH>    Path to MaxMind GeoLite2 database
--no-tui             Streaming output mode
--report             Batch report mode (requires -c)
--json               JSON output (requires -c)
--csv                CSV output (requires -c)
--replay <FILE>      Replay a saved JSON session
--theme <NAME>       Color theme (see Themes section)
```

## Keybindings

| Key | Action |
|-----|--------|
| `q` | Quit |
| `p` | Pause/Resume |
| `r` | Reset stats |
| `t` | Cycle theme |
| `e` | Export to JSON |
| `?` / `h` | Help |
| `Up` / `k` | Move selection up |
| `Down` / `j` | Move selection down |
| `Enter` | Expand selected hop |
| `Esc` | Close popup / Deselect |

## Themes

11 built-in themes are available. Set via `--theme` flag or cycle with `t` key in the TUI.

| Theme | Description |
|-------|-------------|
| `default` | Classic cyan borders (original ttl look) |
| `kawaii` | Cute pastel colors |
| `cyber` | Neon cyan/magenta on dark |
| `dracula` | Popular dark theme |
| `monochrome` | Grayscale only |
| `matrix` | Green on black hacker style |
| `nord` | Arctic, north-bluish colors |
| `gruvbox` | Retro groove warm colors |
| `catppuccin` | Soothing pastel colors |
| `tokyo_night` | Tokyo city lights inspired |
| `solarized` | Precision colors for readability |

```bash
# Start with a specific theme
ttl 1.1.1.1 --theme dracula

# Press 't' during runtime to cycle themes
# Your selection is saved to ~/.config/ttl/config.toml
```

## Troubleshooting

### Permission errors

```
Error: Insufficient permissions for raw sockets
```

Raw ICMP sockets require elevated privileges. See the [Permissions](#permissions) section above.

### High packet loss

If you see high loss (>10%) to a destination that should be reachable:

1. **Network congestion** - Some routers deprioritize ICMP traffic
2. **Rate limiting** - Target may rate-limit ICMP responses
3. **Firewall** - Intermediate firewalls may drop ICMP
4. **ECMP paths** - Multiple paths with different characteristics

Try increasing the probe interval: `ttl target -i 2.0`

### All hops showing `* * *`

This usually means:

1. **Firewall blocking** - Your outbound ICMP is blocked
2. **VPN interference** - Some VPNs don't pass ICMP correctly
3. **Target unreachable** - Verify the IP/hostname is correct

### IPv6 not working

1. Verify IPv6 connectivity: `ping6 2001:4860:4860::8888`
2. Force IPv6: `ttl -6 google.com`
3. Check if your ISP supports IPv6

### DNS resolution slow

Reverse DNS lookups can be slow. Disable with `--no-dns` for faster startup.

## Statistics Explained

### Jitter

Jitter measures **RTT variance** - the absolute difference between consecutive round-trip times (`|RTT_n - RTT_n-1|`). This is different from inter-packet arrival jitter used in VoIP/streaming contexts.

Three jitter metrics are tracked:

| Metric | Description |
|--------|-------------|
| **Jitter (smoothed)** | RFC 3550-style EWMA with 1/16 smoothing factor. Tracks trends while filtering noise. |
| **Avg Jitter** | Running mean of all jitter observations. Shows overall session variance. |
| **Max Jitter** | Largest single RTT change. Captures worst-case latency spike. |

**Interpretation**: High jitter indicates path instability from congestion, route changes, bufferbloat, or load balancing. Stable paths typically show jitter below 5-10% of average RTT.

### Other Statistics

| Metric | Description |
|--------|-------------|
| **Loss %** | Percentage of probes that timed out without response |
| **Min/Avg/Max** | RTT range across all samples |
| **StdDev** | Standard deviation of RTT (Welford's algorithm) |
| **p50/p95/p99** | RTT percentiles from last 256 samples |

## Tech Stack

- **Language**: Rust
- **TUI**: ratatui + crossterm
- **Async**: tokio
- **Sockets**: socket2 + pnet
- **DNS**: hickory-resolver

## Comparison with Similar Tools

| Feature | ttl | [Trippy](https://trippy.rs/) | [MTR](https://github.com/traviscross/mtr) | [NextTrace](https://github.com/nxtrace/NTrace-core) |
|---------|:---:|:---:|:---:|:---:|
| **Protocols** |
| ICMP | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| UDP | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| TCP | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| **Statistics** |
| Loss % | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| Min/Avg/Max RTT | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| Jitter | :white_check_mark: | :white_check_mark: | :x: | :x: |
| Std deviation | :white_check_mark: | :white_check_mark: | :white_check_mark: | :x: |
| **Enrichment** |
| Reverse DNS | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| ASN lookup | :white_check_mark: | :white_check_mark: | :x: | :white_check_mark: |
| GeoIP | :white_check_mark: | :white_check_mark: | :x: | :white_check_mark: |
| MPLS labels | :white_check_mark: | :white_check_mark: | :white_check_mark: | :x: |
| **ECMP** |
| Multi-path detection | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| Paris traceroute | :white_check_mark: | :white_check_mark: | :x: | :x: |
| **TUI** |
| Interactive | :white_check_mark: | :white_check_mark: | :white_check_mark: | :x: |
| Themes | :white_check_mark: | :white_check_mark: | :x: | :x: |
| Theme persistence | :white_check_mark: | :white_check_mark: | :x: | :x: |
| Sparklines/charts | :white_check_mark: | :white_check_mark: | :x: | :x: |
| World map | :x: | :white_check_mark: | :x: | :white_check_mark: |
| **Export** |
| JSON | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| CSV | :white_check_mark: | :white_check_mark: | :white_check_mark: | :x: |
| Session replay | :white_check_mark: | :x: | :x: | :x: |

:white_check_mark: = supported | :construction: = planned | :x: = not supported

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
