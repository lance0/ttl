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

### ECMP Classification

ttl distinguishes two types of ECMP:

- **Per-flow ECMP**: Each flow consistently maps to one next-hop. Different flows take different paths. The Paths column shows unique flow primaries.
- **Per-packet ECMP**: Responses rotate between responders regardless of flow. The Paths column shows the actual number of observed responders.

Classification uses a primary concentration heuristic: if no single responder dominates a flow's responses (below 70% threshold), it's per-packet. The `E` indicator appears in the main table when ECMP is detected at a hop.

**Note:** `--flows` requires UDP or TCP probing (`-p udp` or `-p tcp`). ICMP probes have no port to vary, so flows are always 1 in ICMP mode. ttl warns at startup if `--flows > 1` resolves to effective ICMP probing.

### Paris vs Dublin

- **Paris traceroute**: Varies source port to enumerate paths
- **Dublin traceroute**: Also manipulates flow label (IPv6)

ttl implements Paris-style ECMP detection using source port variation.

## NAT Detection

ttl automatically detects NAT devices that rewrite source ports:

- Compares the source port sent vs returned in ICMP error payloads
- Displays "NAT" indicator in hop details when mismatch detected
- Useful for diagnosing carrier-grade NAT (CGNAT) or enterprise NAT

## Interactive Target Selection

```bash
ttl              # Start with an empty session
```

Run `ttl` with no arguments to open an empty interactive session, then press
`o` to add targets. The input modal resolves hostnames in the background
(showing a "Resolving..." state) and starts probing immediately on success —
no restart needed. Targets can also be added mid-session in any live TUI run;
entering a host that's already being traced switches to it.

Probe infrastructure scales at runtime: each added target gets its own probe
engine, and a packet receiver is started for an IP family the first time a
target of that family is added.

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
3. Filters by IP family (uses IP family of the first resolved address)
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

- Main table shows `!` indicator after hostname when route changes detected
- `!` is suppressed when ECMP is detected at the hop (`E` shown instead) — per-packet load balancing is expected multi-path behavior, not instability
- Hop detail view (Enter key) shows route change history with timestamps
- Uses hysteresis (margin of 2 responses) to avoid false positives
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

Control probe packet size for MTU testing. Range: 36-9216 bytes for IPv4, 56-9216 for IPv6. Supports jumbo frames.

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
ttl --pmtud 8.8.8.8              # Standard ethernet (max 1500)
ttl --pmtud --jumbo 8.8.8.8      # Jumbo frame environments (max 9216)
```

Discover the path MTU using binary search:

1. Sends probes with Don't Fragment (DF) flag set
2. Binary searches between min (68 for IPv4, 1280 for IPv6) and max (1500 or 9216)
3. Uses ICMP "Fragmentation Needed" / "Packet Too Big" responses
4. Results displayed in TUI title bar

By default, PMTUD uses 1500 bytes as the upper bound (standard ethernet MTU). Use `--jumbo` to search up to 9216 bytes for jumbo frame environments (data centers, 10GbE networks with 9000-byte MTUs).

PMTUD runs in the background after the destination is discovered, without interrupting normal tracing.

**Note:** For IPv4, the Don't Fragment bit is set directly in the IP header (via `IP_HDRINCL`), so PMTUD works on all supported platforms — including NetBSD, which lacks the `IP_DONTFRAG` socket option the previous implementation relied on.

### JSON Output with PMTUD

```bash
ttl --pmtud 8.8.8.8 -c 50 --json > pmtud_results.json
```

The JSON output includes PMTUD state:

```json
{
  "pmtud": {
    "min_size": 1400,
    "max_size": 1400,
    "current_size": 1400,
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
| `p` / `Space` | Pause/Resume |
| `r` | Reset all statistics |
| `t` | Cycle color theme |
| `w` | Cycle display mode (auto/compact/wide) |
| `s` | Open settings modal |
| `e` | Export current session to JSON |
| `?` / `h` | Show help dialog |
| `o` | Add a target (works mid-session and from the empty state) |
| `Tab` / `n` | Switch to next target |
| `Shift-Tab` / `N` | Switch to previous target |
| `l` | Open target list (multi-target mode) |
| `Up` / `k` | Move selection up |
| `Down` / `j` | Move selection down |
| `Enter` | Expand selected hop details |
| `Esc` | Close popup / Deselect |
| *Replay* | *See [Replay Controls](#replay-controls) for seek, speed, and position keys* |

## Settings Modal

Press `s` to open the settings modal. Configure:

- **Theme**: Select from 11 built-in themes with live preview
- **Display Mode**: Control column widths (auto/compact/wide)
- **PeeringDB**: Configure API key and view cache status (only shown when IX detection is enabled)
- **Update Check**: Toggle the startup check for new releases on/off (persisted to config)

### Navigation

| Key | Action |
|-----|--------|
| `Tab` | Switch between sections |
| `Up`/`Down` or `j`/`k` | Navigate within section |
| `Enter` or `Space` | Cycle option (theme/display mode) or toggle update check |
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

## Update Notifications

ttl checks GitHub releases for new versions in a background thread at startup. The check is non-blocking and doesn't delay startup or probing.

- **TUI banner**: Yellow banner appears at the top of the screen when an update is available
- **Dismiss**: Press `u` to dismiss the banner for the current session
- **Install-aware**: The help overlay (`?`) shows the appropriate update command based on how ttl was installed:
  - Homebrew: `brew upgrade ttl`
  - Cargo: `cargo install ttl`
  - Pre-built binary: link to GitHub releases
- **Non-interactive mode**: Update notice is printed to stderr after the run completes (JSON/CSV/report modes)

### Disabling the update check

The check can be turned off — useful for packaged installs, air-gapped hosts, or
privacy. Any of these opts out (checked in this order):

- **Per run**: `ttl --no-update-check <target>`
- **Environment**: `DO_NOT_TRACK=1` (the [cross-tool standard](https://consoledonottrack.com/))
  or `TTL_NO_UPDATE_CHECK=1`. Any value other than empty/`0`/`false` counts as set.
- **Persistent**: `no_update_check = true` in `~/.config/ttl/config.toml` (see
  [`examples/config.toml`](../examples/config.toml)), or toggle **Update Check**
  off in the Settings modal (`s`), which saves the preference.
- **Compile-time**: build with `--no-default-features` to drop the check — and the
  `update-informer` dependency — entirely. Package maintainers can ship a build
  that never phones home.

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

### Streaming JSON

```bash
ttl 8.8.8.8 --stream-json                    # One JSON event per line
ttl 8.8.8.8 --stream-json -c 10 | jq .       # Finite run, piped to jq
ttl 8.8.8.8 --stream-json | jq 'select(.type == "timeout")'
```

Emits each probe event as a single line of JSON on stdout (NDJSON), suitable
for piping into `jq`, `grep`, or monitoring pipelines. Implies `--no-tui` and
runs until `-c` rounds complete or Ctrl-C.

Event lines match the schema of the `events` array in saved session files,
with a `target` field added for demultiplexing multi-target runs:

```json
{"target":"8.8.8.8","offset_ms":1052,"ttl":5,"seq":1,"flow_id":0,"type":"reply","addr":"192.178.105.139","rtt_us":12500}
{"target":"8.8.8.8","offset_ms":4021,"ttl":7,"seq":1,"flow_id":0,"type":"timeout"}
```

Event types are `reply`, `timeout`, and `late_reply`. When the stream ends, a
final `summary` line is emitted per target:

```json
{"target":"8.8.8.8","type":"summary","complete":true,"dest_ttl":13,"total_sent":130,"hops_responding":12}
```

### Trace Diff

```bash
ttl --diff before.json after.json            # Human-readable comparison
ttl --diff before.json after.json --json     # Machine-readable diff
```

Compare two saved sessions hop by hop. Reports:

- **`[path]`** — primary responder changed at a hop
- **`[added]`** / **`[lost]`** — hop responds in only one session
- **Responder-set changes** — ECMP responders that appeared or disappeared
- **Latency shifts** — avg RTT deltas, highlighted when ≥5ms *and* ≥20% of the
  before value
- **Loss changes** and destination reachability

```
Trace diff: 8.8.8.8
  before: before.json  (2026-06-09 14:00:12 UTC)
  after:  after.json   (2026-06-10 09:30:44 UTC)

 TTL  Before           After            Change       Avg RTT (ms)       Loss (%)
   1  192.168.1.1      192.168.1.1                    2.0 →     2.1    0.0 →   0.0
   2  10.0.2.1         10.0.2.99        [path]        8.0 →     9.0    0.0 →   0.0
   3  10.0.3.1         *                [lost]       12.0 →       -    0.0 →     -

Summary: 1 path change(s), 0 hop(s) added, 1 hop(s) lost, 0 significant latency shift(s)
  destination reached in both (5 → 5 hops)
```

### Daemon Mode & Prometheus Exporter

```bash
ttl --daemon --prometheus :9090 8.8.8.8      # Headless, metrics on :9090
ttl --daemon --prometheus 127.0.0.1:9100 host1 host2
ttl --daemon --stream-json host | jq .       # Daemon + event stream
```

`--daemon` runs headless with no per-hop stdout — probing continues until
`-c` rounds complete or SIGINT/SIGTERM. Combine with `--prometheus` and/or
`--stream-json` to consume the data. `docker stop` (SIGTERM) triggers the
same graceful shutdown as Ctrl-C.

`--prometheus <ADDR>` serves an OpenMetrics endpoint (`:9090` binds all
interfaces). Endpoints:

- `GET /metrics` — Prometheus exposition format
- `GET /healthz` — returns `200 ok` for container orchestration

Exported metrics (labels: `target` = resolved IP, `host` = name as given,
`ttl` = hop number):

| Metric | Type | Description |
|--------|------|-------------|
| `ttl_probes_sent_total` | counter | Probes sent per hop |
| `ttl_responses_total` | counter | Responses received per hop |
| `ttl_timeouts_total` | counter | Timeouts per hop |
| `ttl_loss_ratio` | gauge | Loss ratio per hop (0–1) |
| `ttl_rtt_avg_seconds` / `min` / `max` / `stddev` | gauge | RTT stats for the hop's primary responder |
| `ttl_hop_responders` | gauge | Distinct responder IPs at the hop (ECMP) |
| `ttl_hop_info` | gauge | Primary responder identity (`ip`, `hostname` labels, value 1) |
| `ttl_target_reachable` | gauge | Destination responded (1/0) |
| `ttl_path_hops` | gauge | Hop count to destination |
| `ttl_target_probes_total` | counter | Completed probes across all hops |

### Docker

Multi-arch images (amd64/arm64) are published to GHCR on each release:

```bash
docker pull ghcr.io/lance0/ttl:latest                    # or :0.20, :0.20.0
docker run --rm -it ghcr.io/lance0/ttl 8.8.8.8           # Interactive TUI
docker run -d -p 9090:9090 ghcr.io/lance0/ttl --daemon --prometheus :9090 8.8.8.8
curl localhost:9090/metrics
```

Or build locally:

```bash
docker build -t ttl .
```

The image is Alpine-based with a static musl binary. Docker grants
`CAP_NET_RAW` by default; stricter runtimes (Kubernetes, podman) may need it
added explicitly:

```yaml
# Kubernetes
securityContext:
  capabilities:
    add: ["NET_RAW"]
```

### Session Replay

```bash
ttl --replay results.json                    # Open in TUI (final state)
ttl --replay results.json --animate          # Animated replay (10x speed)
ttl --replay results.json --animate --speed 1.0  # Real-time replay
ttl --replay results.json --report           # Text report
```

Load a previously saved JSON session for review. Use `--animate` to replay
the session showing hop-by-hop discovery as it happened.

#### Replay Controls

During animated replay, a progress bar shows the current position, speed, and event count. The following controls are available:

| Key | Action |
|-----|--------|
| `p` / `Space` | Pause/resume |
| `Left` / `Right` | Seek ±0.5s |
| `[` / `]` | Seek ±5s |
| `+` / `-` | Speed ±0.5x (0.5x–5.0x) |
| `Home` | Seek to start |
| `End` | Seek to end |
| `?` | Help (shows replay controls) |

Backward seeking rebuilds session state from scratch for correctness — fast even on long traces.

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
      --size <N>         Packet size in bytes (36-9216)
      --dscp <N>         DSCP value for QoS testing (0-63)
      --rate <N>         Max probes per second (0 = unlimited)
      --pmtud            Enable Path MTU Discovery (max 1500)
      --jumbo            Enable jumbo frame detection (max 9216, requires --pmtud)
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
      --stream-json      Stream probe events as line-delimited JSON (implies --no-tui)
      --daemon           Headless mode, no per-hop output (for --prometheus/--stream-json)
      --prometheus <ADDR> Serve Prometheus metrics + /healthz (e.g. :9090; implies --no-tui)
      --diff <BEFORE> <AFTER>  Compare two saved sessions (with --json for JSON output)
      --replay <FILE>    Replay a saved JSON session
      --animate          Animate replay (show probe-by-probe discovery)
      --speed <N>        Replay speed multiplier (default: 10.0, requires --animate)
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
- `x86_64-apple-darwin` - macOS Intel
