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

## Multi-IP Resolution

```bash
ttl --resolve-all google.com
ttl --resolve-all -6 cloudflare.com    # Force IPv6
ttl --resolve-all example.com cdn.com  # Multiple hostnames
```

Trace all IP addresses that a hostname resolves to. Useful for:
- **Round-robin DNS**: CDNs and load balancers often return multiple A records
- **Dual-stack hosts**: Compare IPv4 vs IPv6 paths to the same destination
- **Anycast investigation**: See if different IPs take different paths

### How It Works

1. Resolves all A/AAAA records for each hostname
2. Deduplicates by IP (merges hostnames that resolve to the same IP)
3. Filters by IP family (prefers IPv4, falls back to IPv6 if none)
4. Shows skip count in status (e.g., "3 IPv6 skipped")

### Display Format

- Title bar shows `hostname -> IP` when tracing a resolved hostname
- Multiple hostnames resolving to same IP shown as `hostname (+N more)`
- Press `l` to see all resolved targets with their stats

### Flags

| Flag | Effect |
|------|--------|
| `--resolve-all` | Enable multi-IP resolution |
| `-4` / `--ipv4` | Force IPv4 only (skip IPv6) |
| `-6` / `--ipv6` | Force IPv6 only (skip IPv4) |

## Route Flap Detection

ttl detects route instability when the primary responder IP changes at a hop:

- Main table shows "!" indicator after hostname when route changes detected
- Hop detail view (Enter key) shows route change history with timestamps
- Uses hysteresis (margin of 2 responses) to avoid false positives from per-packet load balancing
- Requires 5+ responses before recording changes (avoids startup noise)
- History capped at 50 changes per hop
- Only active in single-flow mode (disabled when `--flows > 1` since ECMP expects path variation)

Route flaps can indicate:
- Unstable BGP routes
- Flapping links
- Load balancer issues
- Network convergence events

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

### JSON Output with PMTUD

```bash
ttl --pmtud 8.8.8.8 -c 50 --json > pmtud_results.json
```

The JSON output includes PMTUD state:

```json
{
  "pmtud": {
    "min_size": 1400,
    "max_size": 1500,
    "current_size": 1450,
    "successes": 0,
    "failures": 0,
    "discovered_mtu": 1400,
    "phase": "Complete"
  }
}
```

Fields:
- `min_size`: Lower bound (known to work)
- `max_size`: Upper bound (known to fail or untested)
- `current_size`: Size being tested in current binary search step
- `discovered_mtu`: Final MTU when `phase` is `Complete`
- `phase`: `WaitingForDestination`, `Searching`, or `Complete`

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

Shows city, region, and country for each hop. Requires a MaxMind GeoLite2-City database (free).

**Setup:**

1. Create a free MaxMind account at [maxmind.com/en/geolite2/signup](https://www.maxmind.com/en/geolite2/signup)

2. Log in and go to **Download Files** in the left sidebar

3. Download **GeoLite2 City** (the `.mmdb` file, not CSV)

4. Place the database file in one of these locations (checked in order):
   ```
   ~/.local/share/ttl/GeoLite2-City.mmdb   # Linux
   ~/Library/Application Support/ttl/GeoLite2-City.mmdb  # macOS
   ~/.config/ttl/GeoLite2-City.mmdb
   ./GeoLite2-City.mmdb                    # Current directory
   /usr/share/GeoIP/GeoLite2-City.mmdb     # System-wide Linux
   /var/lib/GeoIP/GeoLite2-City.mmdb       # System-wide Linux (alt)
   ```

   Or specify a custom path:
   ```bash
   ttl 8.8.8.8 --geoip-db /path/to/GeoLite2-City.mmdb
   ```

**Note:** GeoIP is optional. Without the database, ttl works normally but won't show location data. MaxMind updates their database weekly; re-download periodically for accuracy.

### IX Detection

```bash
ttl 8.8.8.8           # IX detection enabled (default)
ttl 8.8.8.8 --no-ix   # Disable
```

Identifies Internet Exchange points in your path using PeeringDB data. When a hop's IP matches an IX peering LAN prefix, the hop detail view shows the IX name, city, and country.

**How it works:**

IX detection works out of the box with no configuration. On first use, ttl fetches IX prefix data from PeeringDB and caches it locally (`~/.cache/ttl/peeringdb/ix_cache.json`) for 24 hours.

**API Key (optional but recommended):**

Anonymous PeeringDB access has rate limits. For frequent use or scripting, set up an API key:

1. Create a free PeeringDB account at [peeringdb.com/register](https://www.peeringdb.com/register)

2. Log in and go to your profile (click username in top right)

3. Scroll to **API Keys** section and click **Add API Key**

4. Give it a name (e.g., "ttl") and copy the generated key

5. Configure the API key (choose one method):

   **Via Settings Modal (recommended):**
   - Press `s` to open settings
   - Tab to the PeeringDB section
   - Type your API key and press `Esc` to save
   - Key is saved to `~/.config/ttl/config.toml`

   **Via environment variable:**
   ```bash
   # One-time use
   PEERINGDB_API_KEY=your_key_here ttl 8.8.8.8

   # Persistent (add to ~/.bashrc or ~/.zshrc)
   export PEERINGDB_API_KEY="your_key_here"
   ```

   Note: The environment variable takes precedence over the saved config.

**Cache Status:**

The settings modal shows PeeringDB cache status:
- Number of IX prefixes loaded
- Cache age (e.g., "3h ago")
- Expiry indicator when cache is older than 24 hours
- Press `r` in the PeeringDB section to refresh the cache

**Note:** IX detection is optional. Without an API key, ttl uses anonymous access which works fine for occasional use. The API key just removes rate limiting for heavy usage.

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
| `q` / `Ctrl+C` | Quit |
| `p` | Pause/Resume probing |
| `r` | Reset all statistics |
| `t` | Cycle color theme |
| `w` | Cycle display mode (auto/compact/wide) |
| `s` | Open settings modal |
| `e` | Export current session to JSON |
| `?` / `h` | Show help dialog |
| `Tab` / `n` | Switch to next target |
| `Shift-Tab` / `N` | Switch to previous target |
| `l` | Open target list (multi-target mode) |
| `Up` / `k` | Move selection up |
| `Down` / `j` | Move selection down |
| `Enter` | Expand selected hop details |
| `Esc` | Close popup / Deselect |

## Settings Modal

Press `s` to open the settings modal. Configure:

- **Theme**: Select from 11 built-in themes with live preview
- **Display Mode**: Control column widths (auto/compact/wide)
- **PeeringDB**: Configure API key and view cache status (only shown when IX detection is enabled)

### Navigation

| Key | Action |
|-----|--------|
| `Tab` | Switch between sections |
| `Up`/`Down` or `j`/`k` | Navigate within section |
| `Enter` or `Space` | Cycle option (theme/display mode) |
| `r` | Refresh PeeringDB cache (in PeeringDB section) |
| `Esc` | Close and save |

### Display Mode

The display mode controls Host and ASN column widths:

| Mode | Description | Host Width | ASN Width |
|------|-------------|------------|-----------|
| **Auto** (default) | Fits to content | 12-60 chars | 8-30 chars |
| **Compact** | Minimal widths | 20 chars | 12 chars |
| **Wide** | Generous widths | 45 chars | 24 chars |

Press `w` in the main view (or `Enter` in the Display Mode settings section) to cycle through modes. Auto mode is recommended for most use cases - it adapts to your content while respecting maximum caps to prevent layout issues.

### PeeringDB Section

When in the PeeringDB section, you can:
- Type your API key directly (text input with cursor support)
- View cache status: prefix count, age, and expiry indicator
- Press `r` to refresh the cache from PeeringDB

Settings are saved to `~/.config/ttl/config.toml` when exiting the TUI.

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
  -c, --count <N>        Number of probe rounds (0 = infinite, default)
  -i, --interval <S>     Probe interval in seconds (default: 1.0)
  -m, --max-ttl <N>      Maximum TTL (default: 30, increase for long paths)
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
      --resolve-all      Trace all resolved IPs for hostnames
      --wide             Wide mode (expand columns for wider terminals)
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

## Download Verification

Pre-built binaries are available from [GitHub Releases](https://github.com/lance0/ttl/releases). Each release includes a `SHA256SUMS` file for verification.

### Linux

```bash
curl -LO https://github.com/lance0/ttl/releases/latest/download/ttl-x86_64-unknown-linux-musl.tar.gz
curl -LO https://github.com/lance0/ttl/releases/latest/download/SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
```

### macOS

```bash
curl -LO https://github.com/lance0/ttl/releases/latest/download/ttl-aarch64-apple-darwin.tar.gz
curl -LO https://github.com/lance0/ttl/releases/latest/download/SHA256SUMS
shasum -a 256 -c SHA256SUMS --ignore-missing
```

Available targets:
- `x86_64-unknown-linux-musl` - Linux x86_64
- `aarch64-unknown-linux-gnu` - Linux ARM64
- `aarch64-apple-darwin` - macOS Apple Silicon
