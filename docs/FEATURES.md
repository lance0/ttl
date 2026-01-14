# Features

Comprehensive documentation of ttl features and options.

## Probing Modes

ttl supports three probe protocols:

### ICMP (default)

```bash
ttl 8.8.8.8 -p icmp
```

Sends ICMP Echo Request packets. Most compatible but requires raw socket privileges.

### UDP

```bash
ttl 8.8.8.8 -p udp
ttl 8.8.8.8 -p udp --port 33500  # Custom base port
ttl 8.8.8.8 -p udp --port 53 --fixed-port  # Fixed port (DNS)
```

Sends UDP packets to high ports. By default, the destination port increments per TTL to help with ECMP load balancing. Use `--fixed-port` to probe a specific service.

### TCP

```bash
ttl 8.8.8.8 -p tcp
ttl 8.8.8.8 -p tcp --port 443  # Probe HTTPS
ttl 8.8.8.8 -p tcp --port 80   # Probe HTTP
```

Sends TCP SYN packets. Useful for tracing through firewalls that only allow specific ports.

### Auto-detection

```bash
ttl 8.8.8.8  # or: ttl 8.8.8.8 -p auto
```

Tries ICMP first, falls back to UDP, then TCP if raw sockets aren't available.

## Multi-flow ECMP Detection (Paris/Dublin Traceroute)

```bash
ttl 8.8.8.8 --flows 4
ttl 8.8.8.8 --flows 8 -p udp
ttl 8.8.8.8 --flows 4 --src-port 33000
```

Discover multiple ECMP (Equal-Cost Multi-Path) routes by probing with different flow identifiers.

### How It Works

ECMP routers hash on the 5-tuple: (src_ip, dst_ip, src_port, dst_port, protocol). By varying the source port, each flow may take a different path through load-balanced routers.

- Each flow uses source port `base + flow_id`
- The TUI shows a "Paths" column when `--flows > 1`
- Paths are highlighted when multiple responders are detected

### Paris vs Dublin

- **Paris traceroute**: Varies source port to enumerate paths
- **Dublin traceroute**: Also manipulates flow label (IPv6)

ttl implements Paris-style ECMP detection using source port variation.

## NAT Detection

ttl automatically detects NAT devices that rewrite source ports:

- Compares the source port sent vs returned in ICMP error payloads
- Displays "NAT" indicator in hop details when mismatch detected
- Useful for diagnosing carrier-grade NAT (CGNAT) or enterprise NAT

## Interface Binding

```bash
ttl --interface eth0 8.8.8.8
ttl --interface wlan0 1.1.1.1
ttl --interface eth0 --recv-any 8.8.8.8
```

Bind probes to a specific network interface. Useful for:
- Multi-homed hosts with multiple uplinks
- VPN split tunneling testing
- Deterministic path selection

The `--recv-any` flag disables receiver socket binding, allowing asymmetric routing where replies arrive on a different interface.

### Title Bar Routing Display

When binding to an interface or when the source can be determined, the TUI title bar shows routing information:

```
ttl -- 8.8.8.8 -- eth0 (192.168.1.100 → 192.168.1.1) -- 100 probes
```

- **Interface name** (eth0, wlan0) - shown when `--interface` is used
- **Source IP** (192.168.1.100) - the local address used for probes
- **Gateway** (192.168.1.1) - the default gateway for the route

This helps verify which network path your probes are taking, especially useful on multi-homed systems or when testing VPN configurations.

## Packet Size and DSCP

```bash
ttl --size 1400 8.8.8.8           # Large packets for MTU testing
ttl --dscp 46 8.8.8.8             # EF (Expedited Forwarding)
ttl --dscp 34 8.8.8.8             # AF41 for video
ttl --dscp 46 --size 1400 8.8.8.8 # Combine both
```

### Packet Size

Control probe packet size for MTU testing. Range: 36-1500 bytes for IPv4, 56+ for IPv6.

### DSCP Marking

Set the DSCP (Differentiated Services Code Point) value in the IP header for QoS policy testing.

Common DSCP values:
| Value | Name | Use Case |
|-------|------|----------|
| 0 | Best Effort | Default |
| 46 | EF | VoIP, real-time |
| 34 | AF41 | Video conferencing |
| 26 | AF31 | Streaming media |

Verify with: `sudo tcpdump -v -n icmp | grep tos`

## Path MTU Discovery (PMTUD)

```bash
ttl --pmtud 8.8.8.8
```

Discover the path MTU using binary search:

1. Sends probes with Don't Fragment (DF) flag set
2. Binary searches between min (68 for IPv4, 1280 for IPv6) and max (1500)
3. Uses ICMP "Fragmentation Needed" / "Packet Too Big" responses
4. Results displayed in TUI title bar

PMTUD runs in the background after the destination is discovered, without interrupting normal tracing.

## Enrichment Lookups

### ASN Lookup (enabled by default)

```bash
ttl 8.8.8.8           # ASN lookup enabled
ttl 8.8.8.8 --no-asn  # Disable
```

Queries Team Cymru DNS for Autonomous System information. Displays AS number and organization name.

### Reverse DNS

```bash
ttl 8.8.8.8           # rDNS enabled
ttl 8.8.8.8 --no-dns  # Disable for faster startup
```

Parallel reverse DNS lookups for hop IP addresses.

### GeoIP Location

```bash
ttl 8.8.8.8 --geoip-db /path/to/GeoLite2-City.mmdb
ttl 8.8.8.8 --no-geo  # Disable
```

Requires a MaxMind GeoLite2 database. Get one free at [maxmind.com](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data).

### IX Detection

```bash
ttl 8.8.8.8           # IX detection enabled
ttl 8.8.8.8 --no-ix   # Disable
```

Identifies Internet Exchange points using PeeringDB data. Set `PEERINGDB_API_KEY` environment variable for higher rate limits.

## Statistics

### Jitter

Jitter measures RTT variance - the absolute difference between consecutive round-trip times.

| Metric | Description |
|--------|-------------|
| Jitter (smoothed) | RFC 3550-style EWMA with 1/16 smoothing factor |
| Avg Jitter | Running mean of all jitter observations |
| Max Jitter | Largest single RTT change |

High jitter indicates path instability from congestion, route changes, or load balancing.

### Other Metrics

| Metric | Description |
|--------|-------------|
| Loss % | Percentage of probes that timed out |
| Min/Avg/Max | RTT range across all samples |
| StdDev | Standard deviation (Welford's algorithm) |
| p50/p95/p99 | RTT percentiles from last 256 samples |

## TUI Keybindings

| Key | Action |
|-----|--------|
| `q` | Quit |
| `p` | Pause/Resume probing |
| `r` | Reset all statistics |
| `t` | Cycle color theme |
| `e` | Export current session to JSON |
| `?` / `h` | Show help dialog |
| `Tab` / `n` | Switch to next target |
| `Shift-Tab` / `N` | Switch to previous target |
| `Up` / `k` | Move selection up |
| `Down` / `j` | Move selection down |
| `Enter` | Expand selected hop details |
| `Esc` | Close popup / Deselect |

## Themes

11 built-in themes available via `--theme` or `t` key:

| Theme | Description |
|-------|-------------|
| `default` | Classic cyan borders |
| `kawaii` | Cute pastel colors |
| `cyber` | Neon cyan/magenta |
| `dracula` | Popular dark theme |
| `monochrome` | Grayscale only |
| `matrix` | Green on black |
| `nord` | Arctic blue tones |
| `gruvbox` | Retro warm colors |
| `catppuccin` | Soothing pastels |
| `tokyo_night` | City lights inspired |
| `solarized` | Precision readability |

Theme selection is persisted to `~/.config/ttl/config.toml`.

## Output Formats

### JSON

```bash
ttl 8.8.8.8 -c 100 --json > results.json
```

Full session data including all hops, statistics, and enrichment.

### CSV

```bash
ttl 8.8.8.8 -c 100 --csv > results.csv
```

Tabular format for spreadsheet analysis.

### Text Report

```bash
ttl 8.8.8.8 -c 100 --report
```

Human-readable summary similar to mtr report mode.

### Session Replay

```bash
ttl --replay results.json           # Open in TUI
ttl --replay results.json --report  # Text report
```

Load a previously saved JSON session for review.

## CLI Reference

```
ttl [OPTIONS] <TARGETS>...

Arguments:
  <TARGETS>...  One or more target hostnames or IP addresses

Options:
  -c, --count <N>        Number of probes (0 = infinite, default)
  -i, --interval <S>     Probe interval in seconds (default: 1.0)
  -m, --max-ttl <N>      Maximum TTL (default: 30)
  -p, --protocol <P>     Probe protocol: auto, icmp, udp, tcp
      --port <N>         Base port for UDP/TCP probes
      --fixed-port       Use fixed port (no per-TTL variation)
      --flows <N>        Number of flows for ECMP (1-16, default: 1)
      --src-port <N>     Base source port for multi-flow (default: 50000)
      --timeout <S>      Probe timeout in seconds (default: 3)
      --size <N>         Packet size in bytes (36-1500)
      --dscp <N>         DSCP value for QoS testing (0-63)
      --rate <N>         Max probes per second (0 = unlimited)
      --pmtud            Enable Path MTU Discovery
      --source-ip <IP>   Force specific source IP address
      --interface <NAME> Bind probes to specific interface
      --recv-any         Don't bind receiver (asymmetric routing)
  -4, --ipv4             Force IPv4
  -6, --ipv6             Force IPv6
      --no-dns           Skip reverse DNS lookups
      --no-asn           Skip ASN enrichment
      --no-geo           Skip geolocation
      --no-ix            Skip IX detection
      --geoip-db <PATH>  Path to MaxMind GeoLite2 database
      --no-tui           Streaming output mode
      --report           Batch report mode (requires -c)
      --json             JSON output (requires -c)
      --csv              CSV output (requires -c)
      --replay <FILE>    Replay a saved JSON session
      --theme <NAME>     Color theme
  -h, --help             Print help
  -V, --version          Print version
```
