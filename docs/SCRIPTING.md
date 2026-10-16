# Scripting and Integration Guide

How to use ttl in scripts, CI/CD pipelines, and monitoring. Format details for
each output mode are in [FEATURES.md](FEATURES.md#output-formats).

Choose one batch format (`--json`, `--csv`, or `--report`) per run.
`--diff` supports its default text output or `--json`. Animated replay requires
the interactive TUI and a finite speed between 0.1 and 1000; batch formats and
`--no-tui` cannot be combined with `--animate`.

## Non-Interactive Output Modes

```bash
# JSON output (full session data)
ttl 1.1.1.1 -c 10 --json

# CSV output (one row per hop, primary responder)
ttl 1.1.1.1 -c 10 --csv

# Text report (human-readable summary)
ttl 1.1.1.1 -c 10 --report

# Plain text per round, no TUI
ttl 1.1.1.1 -c 10 --no-tui

# One JSON event per probe, as it happens
ttl 1.1.1.1 --stream-json

# Headless with a Prometheus endpoint
ttl --daemon --prometheus :9090 1.1.1.1
```

With several targets, `--json` prints a JSON array with one session per
target; `--csv` and `--report` print one section per target under a
`=== Target N/M: <ip> ===` header.

## JSON Session Format

`--json` prints the same structure that `e` in the TUI saves and `--replay`
loads. The fields scripts use most:

| Path | Meaning |
|------|---------|
| `.target.original`, `.target.resolved` | Target as given, and the IP traced |
| `.complete` | `true` if the destination replied |
| `.dest_ttl` | Hop number of the destination, or `null` |
| `.hops[]` | One entry per TTL up to `--max-ttl`, including TTLs beyond the destination |
| `.hops[].ttl`, `.sent`, `.received`, `.timeouts` | Per-hop counters |
| `.hops[].primary` | IP of the most frequent responder, or `null` |
| `.hops[].responders` | Object keyed by responder IP |
| `.hops[].responders[ip].hostname`, `.asn`, `.geo`, `.ix` | Enrichment (`null` when unavailable) |
| `.hops[].responders[ip].mean_rtt`, `.min_rtt`, `.max_rtt` | RTT in microseconds |
| `.hops[].nat_info`, `.rate_limit`, `.route_changes` | Detection details, present only when there is data |
| `.pmtud.discovered_mtu` | Path MTU with `--pmtud`, or `null` if no size was confirmed |

Hop loss is `timeouts / (received + timeouts)`; there is no precomputed loss
field. Recorded probe events (`.events`) are included for replay.

## Parsing JSON Output

```bash
# Did the trace reach the destination? (exit status 0 if so)
ttl 1.1.1.1 -c 10 --json | jq -e '.complete' > /dev/null

# All responder IPs
ttl 1.1.1.1 -c 10 --json | jq -r '.hops[].responders[].ip'

# Path up to the destination: hop number and primary responder
ttl 1.1.1.1 -c 10 --json | jq -r '.dest_ttl as $d | .hops[]
  | select(.sent > 0 and .ttl <= ($d // 255)) | "\(.ttl)\t\(.primary // "*")"'

# Hops with more than 5% loss
ttl 1.1.1.1 -c 10 --json | jq -c '.hops[] | select(.received + .timeouts > 0)
  | {ttl, loss_pct: (100 * .timeouts / (.received + .timeouts))} | select(.loss_pct > 5)'

# Average RTT (ms) of each hop's primary responder
ttl 1.1.1.1 -c 10 --json | jq -c '.hops[] | select(.primary)
  | {ttl, ip: .primary, avg_ms: (.responders[.primary].mean_rtt / 1000)}'

# ASN per responder
ttl 1.1.1.1 -c 10 --json | jq -r '.hops[].responders[] | "\(.ip)\t\(.asn.number // "-")\t\(.asn.name // "unknown")"'

# Hops where NAT rewrote source ports (UDP/TCP probes)
ttl 1.1.1.1 -c 10 -p udp --flows 4 --json | jq -c '.hops[] | select(.nat_info.port_rewritten > 0) | {ttl, nat_info}'

# Internet exchange points in the path
ttl cloudflare.com -c 10 --json | jq -c '.hops[].responders[].ix | select(. != null)'
```

## CI/CD Pipeline Examples

### GitHub Actions

Test connectivity to critical endpoints as part of a deployment:

```yaml
name: Network Connectivity Check

on:
  push:
    branches: [main]

jobs:
  connectivity:
    runs-on: ubuntu-latest
    steps:
      - name: Install ttl
        run: cargo install ttl

      - name: Set capabilities
        run: sudo setcap cap_net_raw+ep ~/.cargo/bin/ttl

      - name: Check API endpoint reachability
        run: |
          ttl api.example.com -c 20 --json > trace.json

          # Fail if the destination was not reached
          if ! jq -e '.complete' trace.json > /dev/null; then
            echo "ERROR: Could not reach destination"
            exit 1
          fi

          # Warn on loss at the destination
          LOSS=$(jq '.dest_ttl as $d | .hops[] | select(.ttl == $d)
            | 100 * .timeouts / ([.received + .timeouts, 1] | max)' trace.json)
          if (( $(echo "$LOSS > 10" | bc -l) )); then
            echo "WARNING: ${LOSS}% loss at the destination"
          fi
```

### GitLab CI

```yaml
network-check:
  stage: test
  image: rust:latest
  before_script:
    - cargo install ttl
    - setcap cap_net_raw+ep /usr/local/cargo/bin/ttl
  script:
    - ttl $TARGET_HOST -c 10 --json > network-trace.json
  artifacts:
    paths:
      - network-trace.json
    when: always
```

## Docker Usage

The official image needs no Rust toolchain. Docker grants `NET_RAW` by default;
add `--cap-add NET_RAW` on stricter runtimes.

```bash
docker run --rm ghcr.io/lance0/ttl 1.1.1.1 -c 5 --report
docker run --rm ghcr.io/lance0/ttl 1.1.1.1 -c 5 --json > trace.json
```

Image tags and Kubernetes settings are in [INSTALL.md](INSTALL.md#docker).

## Shell Script Examples

### Basic connectivity check with alerting

```bash
#!/bin/bash
# check-connectivity.sh - Alert on network issues

TARGET="$1"
THRESHOLD_LOSS=10
THRESHOLD_RTT=100

result=$(ttl "$TARGET" -c 20 --json 2>/dev/null)

# Check if destination was reached
if ! echo "$result" | jq -e '.complete' > /dev/null; then
    echo "CRITICAL: Cannot reach $TARGET"
    exit 2
fi

# Loss and average RTT (ms) at the destination hop
dest='.dest_ttl as $d | .hops[] | select(.ttl == $d)'
loss=$(echo "$result" | jq "$dest | 100 * .timeouts / ([.received + .timeouts, 1] | max)")
rtt=$(echo "$result" | jq "$dest | .responders[.primary].mean_rtt / 1000")

if (( $(echo "$loss > $THRESHOLD_LOSS" | bc -l) )); then
    echo "WARNING: High packet loss to $TARGET: ${loss}%"
    exit 1
fi

if (( $(echo "$rtt > $THRESHOLD_RTT" | bc -l) )); then
    echo "WARNING: High latency to $TARGET: ${rtt}ms"
    exit 1
fi

echo "OK: $TARGET reachable, loss=${loss}%, rtt=${rtt}ms"
exit 0
```

### Compare paths to multiple targets

```bash
#!/bin/bash
# compare-paths.sh - Compare network paths

targets=("8.8.8.8" "1.1.1.1" "9.9.9.9")

for target in "${targets[@]}"; do
    echo "=== $target ==="
    ttl "$target" -c 10 --json | jq -r '
        .dest_ttl as $d | .hops[] | select(.sent > 0 and .ttl <= ($d // 255)) |
        (if .primary then .responders[.primary] else null end) as $p |
        "\(.ttl)\t\($p.ip // "*")\t\($p.asn.name // "-")\t\(if $p then (($p.mean_rtt / 100 | round) / 10 | tostring) + "ms" else "-" end)"
    ' | column -t -s $'\t'
    echo
done
```

For a before/after comparison of the same target, save two sessions and use
`ttl --diff before.json after.json` ([Trace Diff](FEATURES.md#trace-diff)).

### MTU discovery script

```bash
#!/bin/bash
# find-mtu.sh - Find path MTU to target

TARGET="$1"

echo "Discovering MTU to $TARGET..."
result=$(ttl "$TARGET" -p icmp --pmtud -c 30 --json 2>/dev/null)

mtu=$(echo "$result" | jq -r '.pmtud.discovered_mtu // "unknown"')
echo "Path MTU: $mtu bytes"

if [[ "$mtu" != "unknown" && "$mtu" -lt 1500 ]]; then
    echo "WARNING: MTU is below standard Ethernet MTU (1500)"
fi
```

## Integration with Logging Systems

### Send to syslog

```bash
ttl target.com -c 10 --json | jq -c . | logger -t ttl-trace
```

### Append to a JSON Lines file

```bash
ttl target.com -c 10 --json | jq -c --arg ts "$(date -Iseconds)" '{ts: $ts, trace: .}' >> /var/log/ttl-traces.jsonl
```

### Send to Elasticsearch

```bash
ttl target.com -c 10 --json | curl -X POST "localhost:9200/ttl-traces/_doc" \
  -H "Content-Type: application/json" \
  -d @-
```

### Stream events

```bash
ttl target.com --stream-json | jq -c 'select(.type == "timeout")'
```

## Session Replay

Save and replay sessions for historical analysis or sharing:

```bash
# Save a trace session
ttl 1.1.1.1 -c 100 --json > trace-$(date +%Y%m%d-%H%M%S).json

# Replay in TUI (final state)
ttl --replay trace-20240115-143022.json

# Animated replay (probe-by-probe discovery at 10x speed)
ttl --replay trace.json --animate

# Real-time animated replay
ttl --replay trace.json --animate --speed 1.0

# Replay and export as CSV
ttl --replay trace.json --csv > trace.csv
```

Replay keys are listed in [Replay Controls](FEATURES.md#replay-controls).

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | The run completed. This does not mean the destination was reached. |
| 1 | Runtime or validation error (permissions, resolution, invalid values such as `-m 100`) |
| 2 | Command-line usage error (unknown flag, conflicting options) |

Check reachability from the output instead of the exit code:

```bash
if ttl target.com -c 5 --json 2>/dev/null | jq -e '.complete' > /dev/null; then
    echo "Target reachable"
else
    echo "Target unreachable or error"
fi
```

## Tips for Scripting

1. **Always use `-c N`** with batch formats; without it ttl runs until stopped
2. **Use `--json`** for machine-readable output
3. **Use `--no-tui`** in headless environments to avoid terminal issues
4. **Set capabilities once** with `setcap` to avoid needing sudo in scripts
5. **Try another protocol** if a target ignores ICMP: `-p udp` or `-p tcp`
6. **Use `--no-update-check`** (or `DO_NOT_TRACK=1`) to skip the release check in automation

### Event retention in headless mode

`--daemon`, Prometheus-only and plain `--no-tui` runs keep aggregate hop
statistics without retaining replay events. `--stream-json` records events until
its next output drain. TUI and batch JSON sessions retain their replay history.
