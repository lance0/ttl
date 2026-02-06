# Contributing

Thank you for your interest in contributing to ttl!

## Development Setup

### Prerequisites

- Rust 1.88+ (edition 2024)
- Linux or macOS (Windows not currently supported)
- `CAP_NET_RAW` capability or root access for testing

### Building

```bash
git clone https://github.com/lance0/ttl
cd ttl
cargo build
```

### Running

```bash
# Development build
sudo cargo run -- 8.8.8.8

# Or set capability on release binary
cargo build --release
sudo setcap cap_net_raw+ep target/release/ttl
./target/release/ttl 8.8.8.8
```

## Code Style

This project uses standard Rust formatting and linting:

```bash
# Format code
cargo fmt

# Run clippy with warnings as errors
cargo clippy -- -D warnings
```

All PRs must pass:
- `cargo build`
- `cargo test`
- `cargo clippy -- -D warnings`
- `cargo fmt -- --check`

## Testing

```bash
# Run all tests
cargo test

# Run tests with output
cargo test -- --nocapture
```

Note: Many features require raw socket access and are difficult to test in CI. Manual testing is often necessary.

## Project Structure

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for detailed module documentation.

Key directories:
- `src/probe/` - Packet crafting and ICMP parsing
- `src/trace/` - Probe orchestration and response handling
- `src/state/` - Session and hop state management
- `src/tui/` - Terminal user interface
- `src/lookup/` - ASN, GeoIP, DNS enrichment
- `src/export/` - Output formats (JSON, CSV, report)

## Pull Request Process

1. Fork the repository
2. Create a feature branch from `master`
3. Make your changes
4. Ensure all checks pass (`cargo build && cargo test && cargo clippy -- -D warnings && cargo fmt -- --check`)
5. Submit a pull request

### Commit Messages

- Use clear, descriptive commit messages
- Start with a verb (Add, Fix, Update, Remove, Refactor)
- Keep the first line under 72 characters

Good examples:
- `Add IPv6 support for TCP probes`
- `Fix PMTUD binary search off-by-one error`
- `Update ratatui to 0.30 for security fix`

### What to Include

- **Bug fixes**: Include steps to reproduce and verify the fix
- **New features**: Update README.md and relevant docs
- **Breaking changes**: Note in CHANGELOG.md

## Reporting Issues

When reporting bugs, please include:
- OS and version (e.g., Ubuntu 22.04, macOS 14)
- Rust version (`rustc --version`)
- ttl version (`ttl --version`)
- Steps to reproduce
- Expected vs actual behavior
- Any error messages

## License

By contributing, you agree that your contributions will be licensed under the same dual MIT/Apache-2.0 license as the project.
