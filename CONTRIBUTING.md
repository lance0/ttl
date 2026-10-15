# Contributing

Thank you for your interest in contributing to ttl!

## Development Setup

### Prerequisites

- Rust 1.88+ (edition 2024)
- Linux or macOS for live tracing (the crate builds and its tests run on native Windows, but tracing there needs WSL2)
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
cargo clippy --all-targets -- -D warnings
```

All PRs must pass:
- `cargo build`
- `cargo test`
- `cargo clippy --all-targets -- -D warnings`
- `cargo fmt -- --check`

### Pre-commit hooks

We ship a `.pre-commit-config.yaml` that runs `cargo fmt` and `cargo clippy`
on every commit and `cargo test --lib` on every push. Set it up once:

```bash
# Recommended: prek (fast Rust port, drop-in compatible)
cargo install --locked prek
prek install

# Or via standalone installer (no Rust toolchain needed)
curl -LsSf https://github.com/j178/prek/releases/latest/download/prek-installer.sh | sh

# Or with the original Python pre-commit
pipx install pre-commit
pre-commit install --hook-type pre-commit --hook-type pre-push
```

After install, hooks run automatically. To run them manually against staged
files: `prek run` (or `pre-commit run`).

## Minimum Supported Rust Version (MSRV)

ttl targets a **modest MSRV** rather than tracking the latest stable release. The
current floor is **Rust 1.88** (edition 2024), declared as `rust-version` in
`Cargo.toml` and enforced by the `msrv` CI job, which pins
`dtolnay/rust-toolchain@1.88` and runs `cargo check`.

Policy:

- **MSRV bumps are deliberate and manual — never automated.** Dependabot's
  `github-actions` group is configured to `ignore` `dtolnay/rust-toolchain`,
  because that action is tagged by *Rust version*: without the ignore, Dependabot
  reads the `@1.88` MSRV pin as a stale tag and tries to bump it to the newest
  Rust, silently defeating the check.
- **Dependency updates that raise the required Rust are caught, not merged
  blindly.** If a `cargo` update needs newer than the MSRV, the `msrv` job goes
  red. That's the decision point: pin the older dependency, or bump the MSRV on
  purpose. Edition 2024 also uses the MSRV-aware resolver, so `cargo update`
  prefers versions compatible with `rust-version` when one exists.
- **When to re-evaluate:** when the `msrv` job forces it, when you genuinely need
  a language/std feature stabilized after the current floor, or on a loose cadence
  (a quick glance each minor release). A reasonable "modest" target is the Rust
  shipped by current Debian stable / Ubuntu LTS, or roughly stable minus ~4
  releases — don't chase the newest.

To bump the MSRV when warranted, update **both** `rust-version` in `Cargo.toml`
and the pinned version in the `msrv` job in `.github/workflows/ci.yml` (and the
`Rust 1.88+` line under Prerequisites above). The `msrv` job then verifies the
new floor actually builds.

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
