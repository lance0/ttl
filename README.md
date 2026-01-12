# ttl

Modern traceroute/mtr-style TUI with hop stats and optional ASN/geo enrichment.

[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE-MIT)

## Features

- Fast, low-overhead continuous path monitoring
- Useful hop-level stats (loss, min/avg/max, jitter, stddev)
- Great terminal UX built with ratatui
- Scriptable mode for CI and automation
- Reverse DNS resolution
- ECMP detection (multiple responders per TTL)
- Multiple export formats (JSON, CSV)
- Session replay from saved JSON files
- IPv4 and IPv6 support

## Installation

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

## Usage

### Interactive TUI (default)

```bash
ttl 1.1.1.1
ttl google.com
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

### Options

```
-c, --count <N>      Number of probes (0 = infinite, default)
-i, --interval <S>   Probe interval in seconds (default: 1.0)
-m, --max-ttl <N>    Maximum TTL (default: 30)
--timeout <S>        Probe timeout in seconds (default: 3)
-4, --ipv4           Force IPv4
-6, --ipv6           Force IPv6
--no-dns             Skip reverse DNS lookups
--no-tui             Streaming output mode
--report             Batch report mode (requires -c)
--json               JSON output (requires -c)
--csv                CSV output (requires -c)
--replay <FILE>      Replay a saved JSON session
```

## Keybindings

| Key | Action |
|-----|--------|
| `q` | Quit |
| `p` | Pause/Resume |
| `r` | Reset stats |
| `e` | Export to JSON |
| `?` / `h` | Help |
| `Up` / `k` | Move selection up |
| `Down` / `j` | Move selection down |
| `Enter` | Expand selected hop |
| `Esc` | Close popup / Deselect |

## Tech Stack

- **Language**: Rust
- **TUI**: ratatui + crossterm
- **Async**: tokio
- **Sockets**: socket2 + pnet
- **DNS**: hickory-resolver

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
