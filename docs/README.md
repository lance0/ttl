# ttl documentation

Find the page for the task at hand. The [project README](../README.md) is a
short overview; everything else lives here.

## Use ttl

| Page | Scope |
|------|-------|
| [Installation](INSTALL.md) | Install channels, permissions (`setcap`, `sudo`), shell completions, Windows/WSL2, download verification, troubleshooting. |
| [Features](FEATURES.md) | Probing modes, detections and indicators, enrichment, TUI keys and settings, themes, config file, output formats, CLI reference. |
| [Scripting](SCRIPTING.md) | JSON fields and `jq` recipes, CI/CD examples, Docker, logging, exit codes. |
| [Comparison](COMPARISON.md) | ttl next to Trippy, MTR, NextTrace, and pathping. |

## Reference

| Page | Scope |
|------|-------|
| [CLI reference](FEATURES.md#cli-reference) | Every flag, its default and range, and which modes combine. |
| [Keybindings](FEATURES.md#tui-keybindings) | Main view, overlays, and [replay controls](FEATURES.md#replay-controls). |
| [Detection indicators](FEATURES.md#detection-indicators) | What the title flags (`NAT`, `RL?`, `ASYM`, `TTL!`, `MTU`, `max_ttl`), the `RL` loss tag, and the host markers `E`, `!`, `~`, `^`, `+` mean. |
| [Config file](FEATURES.md#config-file) | Location and keys of `config.toml`; [example](../examples/config.toml). |
| [Prometheus metrics](FEATURES.md#daemon-mode--prometheus-exporter) | Endpoints, metric names, and labels. |
| [Known issues](../KNOWN_ISSUES.md) | Limitations, edge cases, by-design behavior, and resolved issues. |

## Project

| Page | Scope |
|------|-------|
| [Architecture](ARCHITECTURE.md) | Module layout, data flow, threading model, key data structures, PMTUD algorithm. |
| [Contributing](../CONTRIBUTING.md) | Development setup, checks, MSRV policy, pull request process. |
| [Roadmap](../ROADMAP.md) | Completed work by version, planned features, non-goals. |
| [Changelog](../CHANGELOG.md) | Release history. |
| [Security policy](../SECURITY.md) | Supported versions and how to report a vulnerability. |
