<p align="center">
  <img src="ttl.png" alt="ttl logo" width="200">
</p>

# ttl

Modern traceroute/mtr-style TUI with hop stats and optional ASN/geo enrichment.

[![Crates.io](https://img.shields.io/crates/v/ttl.svg)](https://crates.io/crates/ttl)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE-MIT)

## Quick Start

```bash
# Install
cargo install ttl

# Basic usage (requires root or CAP_NET_RAW)
sudo ttl 8.8.8.8

# Common options
sudo ttl -p udp google.com           # UDP probes
sudo ttl --flows 8 cloudflare.com    # ECMP path discovery
sudo ttl --pmtud 1.1.1.1             # Path MTU discovery
sudo ttl 8.8.8.8 1.1.1.1 9.9.9.9     # Multiple targets
```

## Features

- **Fast continuous path monitoring** with detailed hop statistics
- **Multiple simultaneous targets** - trace to several destinations at once
- **Paris/Dublin traceroute** - multi-flow probing for ECMP path enumeration
- **Path MTU discovery** - binary search for maximum unfragmented size
- **NAT detection** - identify when NAT devices rewrite source ports
- **Rich enrichment** - ASN, GeoIP, reverse DNS, IX detection (PeeringDB)
- **MPLS label detection** from ICMP extensions
- **ICMP, UDP, TCP probing** with auto-detection
- **Great TUI** with themes, sparklines, and session export
- **Scriptable** - JSON, CSV, and text report output

See [docs/FEATURES.md](docs/FEATURES.md) for detailed feature documentation.

## Installation

### From crates.io

```bash
cargo install ttl
```

### From source

```bash
cargo install --git https://github.com/lance0/ttl
```

### Pre-built binaries

Download from [GitHub Releases](https://github.com/lance0/ttl/releases):

```bash
# Download and extract
curl -LO https://github.com/lance0/ttl/releases/latest/download/ttl-x86_64-unknown-linux-gnu.tar.gz
curl -LO https://github.com/lance0/ttl/releases/latest/download/SHA256SUMS

# Verify checksum (Linux)
sha256sum -c SHA256SUMS --ignore-missing
# Or on macOS:
shasum -a 256 -c SHA256SUMS --ignore-missing

# Extract and install
tar xzf ttl-x86_64-unknown-linux-gnu.tar.gz
sudo mv ttl /usr/local/bin/
```

Available targets: `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`, `x86_64-apple-darwin`, `aarch64-apple-darwin`

### Permissions

Raw sockets require elevated privileges:

```bash
# Option 1: Run with sudo
sudo ttl 1.1.1.1

# Option 2: Add capability (Linux)
sudo setcap cap_net_raw+ep $(which ttl)

# Option 3: Enable unprivileged ICMP (Linux)
sudo sysctl -w net.ipv4.ping_group_range='0 65534'
```

## Usage Examples

### Interactive TUI

```bash
ttl google.com
ttl 8.8.8.8 1.1.1.1      # Multiple targets (Tab to switch)
```

### Report and Export

```bash
ttl 1.1.1.1 -c 100 --report    # Text report
ttl 1.1.1.1 -c 100 --json      # JSON export
ttl 1.1.1.1 -c 100 --csv       # CSV export
ttl --replay results.json      # Replay saved session
```

### Advanced Options

```bash
ttl -p tcp --port 443 host     # TCP probes to HTTPS
ttl --flows 4 host             # ECMP path enumeration
ttl --interface eth0 host      # Bind to interface
ttl --size 1400 host           # Large packets for MTU testing
ttl --dscp 46 host             # QoS marking (EF)
```

See [docs/FEATURES.md](docs/FEATURES.md) for full CLI reference.

## Keybindings

| Key | Action |
|-----|--------|
| `q` | Quit |
| `p` | Pause/Resume |
| `r` | Reset stats |
| `t` | Cycle theme |
| `e` | Export JSON |
| `?` | Help |
| `Tab` | Next target |
| `Enter` | Expand hop |

## Themes

11 built-in themes: `default`, `kawaii`, `cyber`, `dracula`, `monochrome`, `matrix`, `nord`, `gruvbox`, `catppuccin`, `tokyo_night`, `solarized`

```bash
ttl 1.1.1.1 --theme dracula    # Start with theme
# Press 't' to cycle themes (saved to ~/.config/ttl/config.toml)
```

## Platform Support

| Platform | Status |
|----------|--------|
| Linux | Full support |
| macOS | Full support |
| Windows | Not supported |

## Documentation

- [Features](docs/FEATURES.md) - Detailed feature documentation and CLI reference
- [Architecture](docs/ARCHITECTURE.md) - Internal design and module structure
- [Contributing](docs/CONTRIBUTING.md) - Development setup and guidelines
- [Comparison](docs/COMPARISON.md) - Comparison with similar tools
- [Changelog](CHANGELOG.md) - Release history
- [Roadmap](ROADMAP.md) - Planned features

## Troubleshooting

### Permission errors

Raw ICMP sockets require `CAP_NET_RAW` or root. See [Permissions](#permissions).

### High packet loss

Try increasing probe interval: `ttl target -i 2.0`

Some routers rate-limit or deprioritize ICMP traffic.

### All hops showing `* * *`

Check firewall rules, VPN configuration, or verify target reachability.

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
