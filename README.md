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
- **Route flap detection** - alert on path changes indicating routing instability
- **Rich enrichment** - ASN, GeoIP, reverse DNS, IX detection (PeeringDB)
- **MPLS label detection** from ICMP extensions
- **ICMP, UDP, TCP probing** with auto-detection
- **Great TUI** with themes, sparklines, and session export
- **Scriptable** - JSON, CSV, and text report output

See [docs/FEATURES.md](docs/FEATURES.md) for detailed feature documentation.

## Installation

### Quick Install (macOS/Linux)

```bash
curl -fsSL https://raw.githubusercontent.com/lance0/ttl/master/install.sh | sh
```

### Homebrew

```bash
brew install lance0/tap/ttl
```

### Pre-built Binaries

Download from [GitHub Releases](https://github.com/lance0/ttl/releases):

| Platform | Target |
|----------|--------|
| Linux x86_64 | `ttl-x86_64-unknown-linux-gnu.tar.gz` |
| Linux ARM64 | `ttl-aarch64-unknown-linux-gnu.tar.gz` |
| macOS Apple Silicon | `ttl-aarch64-apple-darwin.tar.gz` |

```bash
# Download, verify, and install (Linux x86_64 example)
curl -LO https://github.com/lance0/ttl/releases/latest/download/ttl-x86_64-unknown-linux-gnu.tar.gz
curl -LO https://github.com/lance0/ttl/releases/latest/download/SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing  # macOS: shasum -a 256 -c
tar xzf ttl-*.tar.gz && sudo mv ttl /usr/local/bin/
```

### From crates.io

```bash
cargo install ttl
```

### From Source

```bash
git clone https://github.com/lance0/ttl
cd ttl && cargo build --release
sudo cp target/release/ttl /usr/local/bin/
```

### Permissions (Linux)

Raw sockets require elevated privileges. The easiest approach is to add the capability once:

```bash
# Add capability (works for any install location)
sudo setcap cap_net_raw+ep $(which ttl)

# Then run without sudo:
ttl 8.8.8.8
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
| macOS (Tahoe 26+) | Full support |
| macOS (Sequoia 15) | Build from source* |
| Windows | Not supported |

*Pre-built binaries are built on `macos-latest` (Tahoe). Older macOS versions may have display issues - use `cargo install ttl` to compile from source.

## Known Limitations

### Permissions
- Linux: Requires `CAP_NET_RAW` capability or root (see [Permissions](#permissions-linux))
- macOS: Requires root (`sudo ttl target`) - RAW sockets are needed to receive ICMP Time Exceeded messages from intermediate routers

### Protocol Limitations
- ICMP probes: Some networks filter ICMP, try `-p udp` or `-p tcp`
- TCP probes: Only SYN (no connection establishment)
- UDP probes: High ports may be filtered by firewalls

### Multi-flow Mode
- NAT devices may rewrite source ports, breaking flow correlation
- The `[NAT]` indicator warns when this is detected

## Documentation

- [Features](docs/FEATURES.md) - Detailed feature documentation and CLI reference
- [Architecture](docs/ARCHITECTURE.md) - Internal design and module structure
- [Contributing](docs/CONTRIBUTING.md) - Development setup and guidelines
- [Comparison](docs/COMPARISON.md) - Comparison with similar tools
- [Changelog](CHANGELOG.md) - Release history
- [Roadmap](ROADMAP.md) - Planned features

## Troubleshooting

### "sudo: ttl: command not found"

sudo uses a restricted PATH. Use the full path or copy to a sudo-accessible location:

```bash
# Option 1: Use full path
sudo ~/.cargo/bin/ttl 8.8.8.8

# Option 2: Copy to /usr/local/bin (one-time)
sudo cp ~/.cargo/bin/ttl /usr/local/bin/

# Option 3: Symlink (updates automatically with cargo install)
sudo ln -sf ~/.cargo/bin/ttl /usr/local/bin/ttl
```

### Permission errors

Raw ICMP sockets require `CAP_NET_RAW` or root. See [Permissions](#permissions-linux).

### High packet loss

Try increasing probe interval: `ttl target -i 2.0`

Some routers rate-limit ICMP - look for the `[RL?]` indicator in the TUI.

### All hops showing `* * *`

Check firewall rules, VPN configuration, or try a different protocol: `ttl -p udp target`

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
