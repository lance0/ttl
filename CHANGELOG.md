# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.2] - 2025-01-12

### Added
- Theme persistence: saves selected theme to `~/.config/ttl/config.toml`
- Theme automatically restored on next launch
- CLI `--theme` flag still overrides saved preference

## [0.1.1] - 2025-01-12

### Added
- Theme support with 11 built-in themes via `--theme` flag
- Themes: default, kawaii, cyber, dracula, monochrome, matrix, nord, gruvbox, catppuccin, tokyo_night, solarized
- Runtime theme cycling with `t` key in TUI
- Theme-aware UI rendering (borders, status colors, highlights)

## [0.1.0] - 2025-01-12

### Added
- Initial release
- ICMP Echo probing with TTL sweep (1-30 by default)
- IPv4 and IPv6 support with extension header handling
- Real-time TUI built with ratatui
- Hop statistics: loss%, min/avg/max RTT, standard deviation, jitter
- ECMP detection showing multiple responders per TTL
- Reverse DNS resolution for hop IPs
- Export formats: JSON, CSV, text report
- Session replay from saved JSON files
- Interactive TUI with j/k navigation, hop detail view
- Loss-aware sparkline visualization
- Pause/resume probing (p key)
- Stats reset (r key)
- Destination detection (automatically stops at actual hop count)
- Platform support documentation (Linux, macOS)

### Technical
- Welford's online algorithm for numerically stable mean/variance
- RFC 3550-style smoothed jitter calculation (measures RTT variance)
- Probe correlation via ICMP sequence field encoding
- IPv6 extension header parsing (Hop-by-Hop, Routing, Destination Options)
- ICMP checksum validation for IPv4 Echo Reply
- Graceful handling of receive buffer size limits

### Security
- Max TTL validation (capped at 64 to prevent resource exhaustion)
- Replay file size limit (10MB max to prevent DoS)

### Documentation
- Troubleshooting section in README (permissions, high loss, IPv6, DNS)

### Tests
- 32 unit tests covering ICMP parsing, stats calculation, session state
- Tests for IPv6 extension headers, ECMP scenarios, edge cases
