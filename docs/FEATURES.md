# Features

Reference for ttl's probing modes, detections, enrichment, TUI, and output
formats. Installation and permissions are in [INSTALL.md](INSTALL.md); scripting
recipes are in [SCRIPTING.md](SCRIPTING.md).

**Probing:** [Probing Modes](#probing-modes) · [Multi-flow ECMP](#multi-flow-ecmp-detection-parisdublin-traceroute) ·
[Multi-IP Resolution](#multi-ip-resolution) · [Interface Binding](#interface-binding) ·
[Packet Size and DSCP](#packet-size-and-dscp) · [Path MTU Discovery](#path-mtu-discovery-pmtud)

**Detections:** [Detection Indicators](#detection-indicators) · [ICMP Extension Details](#icmp-extension-details) ·
[NAT Detection](#nat-detection) · [Route Flap Detection](#route-flap-detection)

**Enrichment and statistics:** [Enrichment Lookups](#enrichment-lookups) (ASN, rDNS, GeoIP, IX) ·
[Statistics](#statistics)

**TUI:** [Interactive Target Selection](#interactive-target-selection) · [Keybindings](#tui-keybindings) ·
[Settings](#settings-modal) · [Themes](#themes) · [Update Notifications](#update-notifications)

**Output:** [Output Formats](#output-formats) (JSON, CSV, report, streaming JSON, diff, daemon and
Prometheus, replay) · [CLI Reference](#cli-reference)

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

Sends UDP packets to high ports (base port 33434 by default). The destination port increments per TTL; use `--fixed-port` to probe a specific service.

### TCP

```bash
ttl 8.8.8.8 -p tcp
ttl 8.8.8.8 -p tcp --port 443  # Probe HTTPS
ttl 8.8.8.8 -p tcp --port 80   # Probe HTTP
```

Sends TCP SYN packets (base port 80 by default; the port increments per TTL unless `--fixed-port` is set). Useful for tracing through firewalls that only allow specific ports. ttl does not complete the handshake.

### Auto-detection

```bash
ttl 8.8.8.8  # or: ttl 8.8.8.8 -p auto
```

Tries ICMP first, falls back to UDP, then TCP if raw sockets aren't available.

## Multi-flow ECMP Detection (Paris/Dublin Traceroute)

```bash
ttl 8.8.8.8 -p udp --flows 4
ttl 8.8.8.8 -p tcp --port 443 --flows 8
ttl 8.8.8.8 -p udp --flows 4 --src-port 33000
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

## Detection Indicators

ttl flags what it detects in two places: the title bar (for the whole trace)
and beside each hop's host name.

| Title bar | Meaning |
|-----------|---------|
| `[NAT]` | A device rewrote probe source ports ([NAT Detection](#nat-detection)); multi-flow results may be inaccurate |
| `[RL?]` | Loss at some hop looks like ICMP rate limiting rather than real loss |
| `[ASYM]` | The return path of some hop appears to differ from the forward path |
| `[TTL!]` | A middlebox (for example a transparent proxy) appears to modify TTL values |
| `[MTU: 1400-1500]` / `[MTU: 1400]` / `[MTU: unconfirmed]` | PMTUD search range, result, or no confirmed size ([Path MTU Discovery](#path-mtu-discovery-pmtud)) |
| `[max_ttl=30]` | The destination was not reached within the default 30 hops; raise `-m` |
| `[PAUSED]` | Probing is paused (`p` or Space) |

| Beside a hop | Meaning |
|--------------|---------|
| `E` | ECMP: several responders answer at this hop ([ECMP Classification](#ecmp-classification)) |
| `!` | Route flap: the primary responder changed ([Route Flap Detection](#route-flap-detection)) |
| `~` | Asymmetric routing suspected at this hop |
| `^` | TTL manipulation suspected at this hop |
| `+` | Interface or MPLS details are available ([ICMP Extension Details](#icmp-extension-details)) |

`E`, `!` and `~` appear only in single-flow mode; with `--flows > 1` the
**Paths** and **NAT** columns carry that information instead. A loss value
such as `50%RL` marks a hop where rate limiting is suspected: routers often
deprioritize the ICMP replies traceroute depends on, so loss that does not
continue to later hops is usually not real packet loss. The check needs a
later hop to compare against, so it is skipped at the destination.

The hop detail view (Enter) shows the NAT, rate-limit, route-change and
asymmetry evidence for the selected hop.

## ICMP Extension Details

A `+` beside a hop means interface information (RFC 5837), MPLS labels
(RFC 4950), or both are available from one of its responders. Press Enter to
inspect the details, including additional responders at that hop. Long values
wrap to the popup width. PgUp/PgDn scroll the details; Home/End jump to the
start/end, while Up/Down continue to select adjacent hops.

## NAT Detection

ttl detects NAT devices that rewrite source ports of UDP and TCP probes:

- Compares the source port sent with the one quoted back in ICMP error payloads
- Shows `[NAT]` in the title bar, `NAT Detected!` with port-match counts and rewrite samples in the hop detail view, and a `!` in the NAT column in multi-flow mode
- Useful for diagnosing carrier-grade NAT (CGNAT) or enterprise NAT, which breaks flow correlation for `--flows`

```bash
ttl -p udp --flows 4 target.com
```

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
3. Keeps both IPv4 and IPv6 addresses (dual-stack) unless `-4` or `-6` restricts the family
4. Shows the skip count in the status line when a family is filtered (e.g., "3 IPv6 skipped")

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

```bash
ttl -i 0.5 production-server.com
```

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

The `--recv-any` flag (requires `--interface`) disables receiver socket binding, allowing asymmetric routing where replies arrive on a different interface. `--source-ip <IP>` sets the probe source address instead; IPv6 link-local addresses accept a zone (`fe80::1%eth0`).

Interface binding is not available on FreeBSD or NetBSD; use `--source-ip` there.

### Title Bar Routing Display

When binding to an interface or when the source can be determined, the TUI title bar shows routing information:

```
ttl ── 8.8.8.8 eth0 (192.168.1.100 → 192.168.1.1) ── 100 probes ── 1000ms interval ── RTT ms
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

Control probe packet size for MTU testing. The size includes IP and protocol headers. Range: 36-9216 bytes for IPv4, 56-9216 for IPv6 (smaller values are clamped to the minimum). Supports jumbo frames. `--size` cannot be combined with `--pmtud`, which chooses its own sizes.

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

Discover the path MTU using binary search. Useful for finding MTU blackholes,
for example in VPN tunnels where large packets are silently dropped and
connections hang.

PMTUD probes are ICMP Echo Requests, so they are sent only when ttl probes
with ICMP (`-p icmp`, or the default `-p auto` when it selects ICMP). With
`-p udp` or `-p tcp`, `--pmtud` has no effect.

1. Sends probes with Don't Fragment (DF) flag set
2. Binary searches between min (68 for IPv4, 1280 for IPv6) and max (1500 or 9216)
3. Uses ICMP "Fragmentation Needed" / "Packet Too Big" responses to narrow the search, then confirms the size with two Echo Replies from the destination
4. Results displayed in TUI title bar

By default, PMTUD uses 1500 bytes as the upper bound (standard ethernet MTU). Use `--jumbo` to search up to 9216 bytes for jumbo frame environments (data centers, 10GbE networks with 9000-byte MTUs).

PMTUD runs in the background after the destination is discovered, without interrupting normal tracing. A router hint is an upper bound: another link may have a smaller MTU. Timeouts, local size errors, and intermediate ICMP replies cannot confirm delivery. If no size is confirmed, the TUI shows `MTU: unconfirmed` and JSON leaves `discovered_mtu` null. A confirmed result is the largest positively tested size within the configured ceiling and the search's 8-byte tolerance; loss or filtering can make it conservative. This is ICMP Echo probing, not a complete datagram DPLPMTUD implementation.

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
    "confirmed_size": 1400,
    "discovered_mtu": 1400,
    "phase": "Complete"
  }
}
```

Fields:
- `min_size`: Search floor (initially the protocol minimum; not evidence of delivery)
- `max_size`: Upper bound (known to fail or untested)
- `current_size`: Size being tested in current binary search step
- `confirmed_size`: Largest size confirmed by two destination Echo Replies
- `discovered_mtu`: Confirmed result when `phase` is `Complete`, or null if no size was confirmed
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
   - Key is saved to the [config file](#config-file) when the TUI exits

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
- Press `Ctrl+R` in the PeeringDB section to refresh the cache

**Note:** IX detection is optional. Without an API key, ttl uses anonymous access which works fine for occasional use. An API key raises the rate limit for heavy use.

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

Press `?` in the TUI for the same list.

| Key | Action |
|-----|--------|
| `q` | Quit |
| `Ctrl+C` | Quit from anywhere, including dialogs and text inputs |
| `p` / `Space` | Pause/resume probing (in replay: pause/resume playback) |
| `r` | Reset statistics for the current target |
| `t` | Cycle color theme |
| `w` | Cycle display mode (auto/compact/wide) |
| `s` | Open settings |
| `e` | Export the current target's session to `ttl-<target>-<timestamp>.json` in the current directory |
| `?` / `h` | Show help |
| `u` | Dismiss the update banner |
| `o` | Add a target (live mode, including the empty session) |
| `Tab` / `n` | Next target (multi-target) |
| `Shift-Tab` / `N` | Previous target (multi-target) |
| `l` | Open the target list (multi-target) |
| `Up` / `k`, `Down` / `j` | Move hop selection |
| `Enter` | Open details for the selected hop |
| `Esc` | Clear the selection |
| *Replay* | *See [Replay Controls](#replay-controls)* |

Inside overlays:

| Overlay | Keys |
|---------|------|
| Help | `PgUp`/`PgDn` scroll a page, `Home`/`End` jump to start/end; any other key closes |
| Hop details | `PgUp`/`PgDn`/`Home`/`End` scroll; `Up`/`Down` (`k`/`j`) or `1`-`9` select another hop; `Esc`, `Enter` or `q` close |
| Target list | `Up`/`Down` (`k`/`j`) move, `Enter` selects, `1`-`9` jump to a target, `Esc` closes |
| Add target | Type a hostname or IP, `Enter` resolves and adds it, `Esc` cancels |
| Settings | See [Settings Modal](#settings-modal) |

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
| `Ctrl+R` | Refresh PeeringDB cache (in PeeringDB section, where plain keys type into the API key field) |
| `Esc` | Close and save |

### Display Mode

The display mode sets preferred Host and ASN widths:

| Mode | Description | Host Width | ASN Width |
|------|-------------|------------|-----------|
| **Auto** (default) | Fits to content | 12-60 cells | 8-40 cells |
| **Compact** | Compact preferences | 20 cells | 12 cells |
| **Wide** | Generous widths, plus JAvg/JMax | 45 cells | 36 cells |

Press `w` in the main view (or `Enter` in the Display Mode settings section) to cycle through modes. All modes adapt to the available terminal width: secondary columns disappear before numeric cells are squeezed, and Enter opens all statistics for the selected hop. Large counters or RTTs use scientific notation when needed. Latency values are in milliseconds.

Hop and target selections scroll into view automatically, and settings keeps the active section visible.

The **Recent** column shows the latest ten probe outcomes for the hop, oldest to newest: `·` is a reply and `×` is a timeout.

### PeeringDB Section

When in the PeeringDB section, you can:
- Type your API key directly (text input with cursor support)
- View cache status: prefix count, age, and expiry indicator
- Press `Ctrl+R` to refresh the cache from PeeringDB

Settings are saved to the [config file](#config-file) when the TUI exits.

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

Theme selection is saved to the [config file](#config-file) when the TUI exits. `--theme <name>` overrides the saved theme for that run (and is saved on exit); `--theme default` does not override a saved theme.

## Config File

ttl keeps preferences in `config.toml` under the platform config directory:

| Platform | Path |
|----------|------|
| Linux and BSD | `~/.config/ttl/config.toml` (or `$XDG_CONFIG_HOME/ttl/config.toml`) |
| macOS | `~/Library/Application Support/ttl/config.toml` |

The TUI writes the file when it exits; you can also edit it by hand. Every key
is optional:

| Key | Values | Set from |
|-----|--------|----------|
| `theme` | A [theme](#themes) name | `t`, Settings, or `--theme` |
| `display_mode` | `auto`, `compact`, `wide` | `w`, Settings, or `--wide` |
| `peeringdb_api_key` | PeeringDB API key | Settings (`PEERINGDB_API_KEY` overrides it) |
| `no_update_check` | `true` / `false` | Settings ([Disabling the update check](#disabling-the-update-check)) |

[`examples/config.toml`](../examples/config.toml) is a commented example.

## Update Notifications

ttl checks GitHub releases for new versions in a background thread at startup. The check is non-blocking and doesn't delay startup or probing.

- **TUI banner**: a banner at the top of the screen announces an available update
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
- **Persistent**: `no_update_check = true` in the [config file](#config-file) (see
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

Human-readable summary similar to mtr report mode. When available, indented
lines include RFC 5837 interface roles, names, addresses, ifIndex, MTU, and
MPLS label stacks (label, traffic class, bottom-of-stack flag, and TTL).
Each extension line identifies its responder IP so ECMP details remain clear.
These details are also available with `--replay results.json --report`.

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

The GHCR image runs any of these modes headless, for example
`docker run -d -p 9090:9090 ghcr.io/lance0/ttl --daemon --prometheus :9090 8.8.8.8`.
Tags, capabilities, and Kubernetes settings are in
[INSTALL.md](INSTALL.md#docker).

### Session Replay

```bash
ttl --replay results.json                    # Open in TUI (final state)
ttl --replay results.json --animate          # Animated replay (10x speed)
ttl --replay results.json --animate --speed 1.0  # Real-time replay
ttl --replay results.json --report           # Text report (also --json, --csv)
ttl --replay long.json --replay-size-limit 64  # Allow a trusted file over 10 MiB
```

Load a previously saved JSON session for review. Use `--animate` to replay
the session showing hop-by-hop discovery as it happened.

Replay and diff refuse input over 10 MiB by default, since saved sessions may
come from untrusted sources. `--replay-size-limit <MiB>` (1-1024) raises the
cap for a larger recording you trust.

#### Replay Controls

During animated replay, a progress bar shows the current position, speed, and event count. The following controls are available:

| Key | Action |
|-----|--------|
| `p` / `Space` | Pause/resume |
| `Left` / `Right` | Seek ±0.5s |
| `[` / `]` | Seek ±5s |
| `+` / `-` (or `>` / `<`) | Speed ±0.5x (0.1x–1000x) |
| `Home` | Seek to start |
| `End` | Seek to end |
| `?` | Help (shows replay controls) |

Backward seeking rebuilds session state from the start of the recording.

## CLI Reference

`ttl --help` prints the authoritative list for your version. Usage:
`ttl [OPTIONS] [TARGETS]...`. With no targets, ttl opens an empty interactive
session ([Interactive Target Selection](#interactive-target-selection)).

**Probing**

```
  -c, --count <N>            Probe rounds; 0 = run until quit (default: 0)
  -i, --interval <S>         Seconds between rounds (default: 1.0)
  -m, --max-ttl <N>          Maximum TTL, 1-64 (default: 30)
  -p, --protocol <P>         auto, icmp, udp, tcp (default: auto)
      --port <N>             Base destination port (default: 33434 UDP, 80 TCP)
      --fixed-port           Keep the destination port fixed instead of incrementing per TTL
      --flows <N>            Flows for ECMP detection, 1-16 (default: 1; needs UDP or TCP)
      --src-port <N>         Base source port for flows (default: 50000)
      --timeout <S>          Probe timeout in seconds (default: 3; must be < 256 x interval)
      --rate <N>             Max probes per second, 0-10000 (0 = unlimited)
      --size <N>             Packet size in bytes, 36-9216 (conflicts with --pmtud)
      --dscp <N>             DSCP value, 0-63
      --pmtud                Path MTU discovery, up to 1500 bytes (ICMP only)
      --jumbo                Search up to 9216 bytes (requires --pmtud)
  -4, --ipv4                 Force IPv4
  -6, --ipv6                 Force IPv6
      --resolve-all          Trace every resolved address of each hostname
      --interface <NAME>     Bind probes to an interface (not on FreeBSD/NetBSD)
      --recv-any             Don't bind the receive socket (requires --interface)
      --source-ip <IP>       Source address; IPv6 zones allowed (fe80::1%eth0)
```

**Enrichment**

```
      --no-dns               Skip reverse DNS
      --no-asn               Skip ASN lookups
      --no-geo               Skip GeoIP
      --no-ix                Skip IX detection (PeeringDB)
      --geoip-db <PATH>      MaxMind GeoLite2-City database file
```

**Output and modes**

```
      --no-tui               Plain text output, one line per hop each round
      --json                 JSON at the end of the run (requires -c)
      --csv                  CSV at the end of the run (requires -c)
      --report               Text report at the end of the run (requires -c)
      --stream-json          Line-delimited JSON events (implies --no-tui)
      --daemon               Headless, no per-hop output
      --prometheus <ADDR>    Serve /metrics and /healthz (e.g. :9090; implies --no-tui)
      --diff <BEFORE> <AFTER>  Compare two saved sessions (text, or --json)
      --replay <FILE>        Open a saved JSON session
      --replay-size-limit <MiB>  Max --replay/--diff input, 1-1024 (default: 10)
      --animate              Animated replay (requires --replay)
      --speed <N>            Replay speed, 0.1-1000 (default: 10.0; requires --animate)
```

**Interface and misc**

```
      --theme <NAME>         Color theme (see Themes)
      --wide                 Start in wide display mode
      --no-update-check      Skip the startup release check
      --completions <SHELL>  Print completions for bash, zsh, fish, or powershell
  -h, --help                 Print help
  -V, --version              Print version
```

Mode rules: `--json`, `--csv` and `--report` are mutually exclusive. `--diff`
supports text or `--json` output only. `--stream-json`, `--daemon` and
`--prometheus` cannot be combined with batch formats, `--replay` or `--diff`.
`--animate` cannot be combined with `--json`, `--csv`, `--report` or
`--no-tui`. Non-interactive modes need at least one target.

<a id="download-verification"></a>

Download verification moved to [INSTALL.md](INSTALL.md#verify-a-download).
