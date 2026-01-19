<p align="center">
  <img src="ttl.png" alt="ttl logo" width="200">
</p>

# ttl

Network diagnostic tool that goes beyond traceroute: MTU discovery, NAT detection, route flap alerts, IX identification, and more.

![ttl screenshot](ttlss.png)

[![Crates.io](https://img.shields.io/crates/v/ttl.svg)](https://crates.io/crates/ttl)
[![CI](https://github.com/lance0/ttl/actions/workflows/ci.yml/badge.svg)](https://github.com/lance0/ttl/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE-MIT)
[![Ko-fi](https://img.shields.io/badge/Ko--fi-tip-ff5e5b?logo=ko-fi)](https://ko-fi.com/lance0)

## Quick Start

```bash
# Basic usage
ttl 8.8.8.8                          # Linux (after setcap)
sudo ttl 8.8.8.8                     # macOS (always needs sudo)

# Common options
ttl -p udp google.com                # UDP probes
ttl --flows 8 cloudflare.com         # ECMP path discovery
ttl --pmtud 1.1.1.1                  # Path MTU discovery
ttl 8.8.8.8 1.1.1.1 9.9.9.9          # Multiple targets
```

See [Installation](#installation) below for setup instructions.

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

See [docs/FEATURES.md](docs/FEATURES.md) for detailed documentation, including optional setup for [GeoIP](docs/FEATURES.md#geoip-location) and [IX detection](docs/FEATURES.md#ix-detection).

## Installation

### Homebrew (macOS/Linux)

```bash
brew install lance0/tap/ttl
```

### From crates.io

Requires [Rust](https://www.rust-lang.org/tools/install):

```bash
cargo install ttl
```

### Pre-built Binaries

Download from [GitHub Releases](https://github.com/lance0/ttl/releases):

| Platform | Target |
|----------|--------|
| Linux x86_64 | `ttl-x86_64-unknown-linux-musl.tar.gz` |
| Linux ARM64 | `ttl-aarch64-unknown-linux-gnu.tar.gz` |
| macOS Apple Silicon | `ttl-aarch64-apple-darwin.tar.gz` |

```bash
# Download, verify, and install (Linux x86_64 example)
curl -LO https://github.com/lance0/ttl/releases/latest/download/ttl-x86_64-unknown-linux-musl.tar.gz
curl -LO https://github.com/lance0/ttl/releases/latest/download/SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing  # macOS: shasum -a 256 -c
tar xzf ttl-*.tar.gz && sudo mv ttl /usr/local/bin/
```

### From Source

```bash
git clone https://github.com/lance0/ttl
cd ttl && cargo build --release
sudo cp target/release/ttl /usr/local/bin/
```

### Quick Install Script

> **Note**: Piping scripts from the internet to sh is convenient but bypasses your ability to review the code first. Consider using one of the methods above, or [review the script](https://github.com/lance0/ttl/blob/master/install.sh) before running.

```bash
curl -fsSL https://raw.githubusercontent.com/lance0/ttl/master/install.sh | sh
```

### Permissions (Linux)

Raw sockets require elevated privileges. The easiest approach is to add the capability once:

```bash
# Add capability (works for any install location)
sudo setcap cap_net_raw+ep $(which ttl)

# Then run without sudo:
ttl 8.8.8.8
```

### Shell Completions

```bash
# Bash
ttl --completions bash > ~/.local/share/bash-completion/completions/ttl

# Zsh (add ~/.zfunc to fpath in .zshrc first)
ttl --completions zsh > ~/.zfunc/_ttl

# Fish
ttl --completions fish > ~/.config/fish/completions/ttl.fish

# PowerShell (add to $PROFILE)
ttl --completions powershell >> $PROFILE
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

## Real-World Use Cases

### Find MTU Blackholes in VPNs

VPN tunnels often have lower MTU than expected. Large packets get silently dropped, causing mysterious connection hangs.

```bash
sudo ttl --pmtud vpn-gateway.example.com
```

TTL binary-searches to find the maximum packet size that works. The `[MTU: 1400]` indicator shows exactly where fragmentation occurs.

### Detect Carrier-Grade NAT Breaking Your Flows

Running multi-flow traceroute but getting inconsistent results? NAT devices may be rewriting your source ports.

```bash
sudo ttl --flows 4 target.com
```

TTL detects when returned source ports don't match what was sent. The `[NAT]` indicator warns you, and hop details show which device is doing the rewriting.

### Identify Internet Exchange Points

See exactly where your traffic peers with other networks:

```bash
sudo ttl cloudflare.com
```

TTL queries PeeringDB to identify IX points. The hop detail view shows IX name, city, and country. Works out of the box; optionally set `PEERINGDB_API_KEY` for higher rate limits. See [docs/FEATURES.md](docs/FEATURES.md#ix-detection) for setup details.

### Catch Flapping Routes

Unstable BGP or failover issues cause intermittent problems that are hard to catch:

```bash
sudo ttl -i 0.5 production-server.com
```

TTL tracks when the responding IP at a hop changes. The `!` indicator flags route flaps, and hop details show change history.

### Detect Transparent Proxies

Some networks intercept traffic with transparent proxies that manipulate TTL values:

```bash
sudo ttl -p tcp --port 80 website.com
```

The `[TTL!]` indicator appears when TTL manipulation is detected.

### Distinguish Real Loss from ICMP Rate Limiting

That 30% packet loss at hop 5 might be fake - routers often rate-limit ICMP responses:

```bash
sudo ttl target.com
```

The `[RL?]` indicator and `50%RL` in the loss column tell you it's rate limiting, not actual packet drops.

### Compare Multiple Paths

```bash
sudo ttl 8.8.8.8 1.1.1.1 9.9.9.9
```

Trace multiple destinations at once. Press `Tab` to switch between them.

## Keybindings

| Key | Action |
|-----|--------|
| `q` / `Ctrl+C` | Quit |
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
| Windows (WSL2) | Full support |
| Windows (native) | Not supported |

*Pre-built binaries are built on `macos-latest` (Tahoe). Older macOS versions may have display issues - use `cargo install ttl` to compile from source.

### Windows via WSL2

```powershell
wsl --install                    # Install WSL if needed, then restart
wsl                              # Open Ubuntu
```

Then in Ubuntu:

```bash
# Option 1: Install via cargo (recommended)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
cargo install ttl
sudo ~/.cargo/bin/ttl 8.8.8.8

# Option 2: Pre-built binary via install script
curl -fsSL https://raw.githubusercontent.com/lance0/ttl/master/install.sh | sh
sudo ttl 8.8.8.8
```

## Known Issues

- **iTerm2 on macOS Sequoia**: Initial display may render incorrectly. Press `r` to reset, or use Terminal.app.

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
- [Scripting](docs/SCRIPTING.md) - CI/CD integration, JSON parsing, Docker usage
- [Architecture](docs/ARCHITECTURE.md) - Internal design and module structure
- [Contributing](docs/CONTRIBUTING.md) - Development setup and guidelines
- [Comparison](docs/COMPARISON.md) - Comparison with similar tools (including pathping)
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

### Theme/config not persisting (macOS)

As of v0.12.1, the config directory on macOS changed from `~/Library/Preferences/ttl/` to `~/Library/Application Support/ttl/` to align with Apple guidelines. If you have an existing config, move it:

```bash
mv ~/Library/Preferences/ttl ~/Library/Application\ Support/ttl
```

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
