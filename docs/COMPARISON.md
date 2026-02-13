# Comparison with Similar Tools

How ttl compares to other traceroute and network diagnostic tools.

## Feature Matrix

| Feature | ttl | [Trippy](https://trippy.rs/) | [MTR](https://github.com/traviscross/mtr) | [NextTrace](https://github.com/nxtrace/NTrace-core) | pathping |
|---------|:---:|:---:|:---:|:---:|:---:|
| **Protocols** ||||||
| ICMP | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| UDP | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :x: |
| TCP | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :x: |
| **Statistics** ||||||
| Loss % | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| Min/Avg/Max RTT | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| Jitter | :white_check_mark: | :white_check_mark: | :x: | :x: | :x: |
| Std deviation | :white_check_mark: | :white_check_mark: | :white_check_mark: | :x: | :x: |
| **Enrichment** ||||||
| Reverse DNS | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| ASN lookup | :white_check_mark: | :white_check_mark: | :x: | :white_check_mark: | :x: |
| GeoIP | :white_check_mark: | :white_check_mark: | :x: | :white_check_mark: | :x: |
| MPLS labels | :white_check_mark: | :white_check_mark: | :white_check_mark: | :x: | :x: |
| IX detection | :white_check_mark: | :x: | :x: | :x: | :x: |
| **ECMP** ||||||
| Multi-path detection | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :x: |
| Per-flow/per-packet classification | :white_check_mark: | :x: | :x: | :x: | :x: |
| Paris traceroute | :white_check_mark: | :white_check_mark: | :x: | :x: | :x: |
| **TUI** ||||||
| Interactive | :white_check_mark: | :white_check_mark: | :white_check_mark: | :x: | :x: |
| Themes | :white_check_mark: | :white_check_mark: | :x: | :x: | :x: |
| Theme persistence | :white_check_mark: | :white_check_mark: | :x: | :x: | :x: |
| Sparklines/charts | :white_check_mark: | :white_check_mark: | :x: | :x: | :x: |
| World map | :x: | :white_check_mark: | :x: | :white_check_mark: | :x: |
| **Export** ||||||
| JSON | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :x: |
| CSV | :white_check_mark: | :white_check_mark: | :white_check_mark: | :x: | :x: |
| Session replay | :white_check_mark: | :x: | :x: | :x: | :x: |
| **Advanced** ||||||
| Multiple targets | :white_check_mark: | :white_check_mark: | :x: | :x: | :x: |
| PMTUD | :white_check_mark: | :x: | :x: | :x: | :x: |
| NAT detection | :white_check_mark: | :x: | :x: | :x: | :x: |
| Rate limit detection | :white_check_mark: | :x: | :x: | :x: | :x: |
| Route flap detection | :white_check_mark: | :white_check_mark: | :x: | :x: | :x: |
| Asymmetric routing | :white_check_mark: | :x: | :x: | :x: | :x: |

:white_check_mark: = supported | :x: = not supported

## For Windows/Enterprise Users: TTL vs pathping

If you're coming from a Windows environment, you're probably familiar with `pathping`. Here's how ttl compares:

| Aspect | ttl | pathping |
|--------|-----|----------|
| **Speed** | Real-time continuous updates | Waits 25+ seconds per hop before showing stats |
| **Protocols** | ICMP, UDP, TCP | ICMP only |
| **Output** | Interactive TUI, JSON, CSV | Text only |
| **Enrichment** | ASN, GeoIP, IX, DNS | DNS only |
| **Analysis** | Rate limit detection, NAT detection, route flaps | Basic loss stats |
| **Cost** | Free, open source | Built into Windows |
| **Platforms** | Linux, macOS | Windows only |

**Why switch from pathping?**
- No more waiting 5+ minutes for results - ttl shows stats immediately
- Export to JSON/CSV for tickets and documentation
- Identify *why* there's packet loss (rate limiting vs real drops)
- See which ISP/AS each hop belongs to

### Running TTL on Windows via WSL

TTL works great on Windows through WSL2. Setup takes under 2 minutes:

```powershell
# 1. Install WSL (if not already installed)
wsl --install
# Restart your computer, then open Ubuntu from Start menu
```

```bash
# 2. In Ubuntu, install ttl (choose one):

# Option A: Pre-built binary (fastest)
curl -fsSL https://raw.githubusercontent.com/lance0/ttl/master/install.sh | sh

# Option B: Build from source
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
cargo install ttl

# 3. Run ttl
sudo ttl 8.8.8.8
```

WSL2 has full network stack access, so all ttl features work including ICMP, UDP, and TCP probes.

## When to Use Each Tool

### Use ttl when you need:
- Path MTU Discovery (PMTUD)
- NAT detection along the path
- Internet Exchange (IX) point identification
- Session replay for historical analysis
- Multiple simultaneous targets
- ICMP rate limit detection

### Use Trippy when you need:
- World map visualization
- More mature/stable tool
- Wider platform support

### Use MTR when you need:
- Available by default on most systems
- Simple, well-known interface
- Lightweight resource usage

### Use NextTrace when you need:
- China-optimized IP geolocation
- Multiple geolocation database support
- Map visualization

## Platform Support

| Platform | ttl | Trippy | MTR | NextTrace |
|----------|:---:|:------:|:---:|:---------:|
| Linux | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| macOS | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| Windows | :x: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| BSD | :construction: | :white_check_mark: | :white_check_mark: | :x: |
