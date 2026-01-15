# Scripting and Integration Guide

How to use ttl in scripts, CI/CD pipelines, and integrate with other tools.

## Non-Interactive Output Modes

TTL provides several output formats for scripting:

```bash
# JSON output (full session data)
ttl 1.1.1.1 -c 10 --json

# CSV output (hop statistics)
ttl 1.1.1.1 -c 10 --csv

# Text report (human-readable summary)
ttl 1.1.1.1 -c 10 --report

# Disable TUI for headless environments
ttl 1.1.1.1 -c 10 --no-tui
```

## CI/CD Pipeline Examples

### GitHub Actions

Test connectivity to critical endpoints as part of your deployment:

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

          # Fail if destination not reached
          if ! jq -e '.hops[] | select(.is_destination == true)' trace.json > /dev/null; then
            echo "ERROR: Could not reach destination"
            exit 1
          fi

          # Warn on high packet loss
          MAX_LOSS=$(jq '[.hops[].loss_percent] | max' trace.json)
          if (( $(echo "$MAX_LOSS > 10" | bc -l) )); then
            echo "WARNING: High packet loss detected: ${MAX_LOSS}%"
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

TTL requires `NET_RAW` capability to send ICMP packets:

```bash
# Run ttl in Docker
docker run --rm --cap-add=NET_RAW -it rust:latest bash -c "
  cargo install ttl &&
  ttl 1.1.1.1 -c 5 --report
"
```

Or in a Dockerfile:

```dockerfile
FROM rust:latest
RUN cargo install ttl
# Container needs --cap-add=NET_RAW at runtime
ENTRYPOINT ["ttl"]
```

```bash
docker build -t ttl .
docker run --rm --cap-add=NET_RAW ttl 1.1.1.1 -c 5 --report
```

## Parsing JSON Output

TTL's JSON output contains detailed hop information:

```bash
# Get all hop IPs
ttl 1.1.1.1 -c 10 --json | jq -r '.hops[].responders[].ip'

# Get hops with packet loss > 5%
ttl 1.1.1.1 -c 10 --json | jq '.hops[] | select(.loss_percent > 5)'

# Extract ASN information
ttl 1.1.1.1 -c 10 --json | jq -r '.hops[].responders[].asn.name // "unknown"'

# Get average RTT per hop
ttl 1.1.1.1 -c 10 --json | jq '.hops[] | {ttl: .ttl, avg_ms: .avg_ms}'

# Check for NAT detection
ttl 1.1.1.1 -c 10 --flows 4 --json | jq '.hops[] | select(.nat_detected == true)'

# Find IX points in path
ttl cloudflare.com -c 10 --json | jq '.hops[].responders[].ix | select(. != null)'
```

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

# Check packet loss
max_loss=$(echo "$result" | jq '[.hops[].loss_percent] | max')
if (( $(echo "$max_loss > $THRESHOLD_LOSS" | bc -l) )); then
    echo "WARNING: High packet loss to $TARGET: ${max_loss}%"
    exit 1
fi

# Check latency
max_rtt=$(echo "$result" | jq '[.hops[].avg_ms // 0] | max')
if (( $(echo "$max_rtt > $THRESHOLD_RTT" | bc -l) )); then
    echo "WARNING: High latency to $TARGET: ${max_rtt}ms"
    exit 1
fi

echo "OK: $TARGET reachable, loss=${max_loss}%, rtt=${max_rtt}ms"
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
        .hops[] |
        "\(.ttl)\t\(.responders[0].ip // "*")\t\(.responders[0].asn.name // "-")\t\(.avg_ms // "-")ms"
    ' | column -t
    echo
done
```

### MTU discovery script

```bash
#!/bin/bash
# find-mtu.sh - Find path MTU to target

TARGET="$1"

echo "Discovering MTU to $TARGET..."
result=$(ttl "$TARGET" --pmtud -c 30 --json 2>/dev/null)

mtu=$(echo "$result" | jq -r '.pmtud.discovered_mtu // "unknown"')
echo "Path MTU: $mtu bytes"

if [[ "$mtu" != "unknown" && "$mtu" -lt 1500 ]]; then
    echo "WARNING: MTU is below standard Ethernet MTU (1500)"
    echo "Consider adjusting MTU settings for this path"
fi
```

## Integration with Logging Systems

### Send to syslog

```bash
ttl target.com -c 10 --json | logger -t ttl-trace
```

### Append to log file with timestamp

```bash
echo "$(date -Iseconds) $(ttl target.com -c 10 --json)" >> /var/log/ttl-traces.jsonl
```

### Send to Elasticsearch

```bash
ttl target.com -c 10 --json | curl -X POST "localhost:9200/ttl-traces/_doc" \
  -H "Content-Type: application/json" \
  -d @-
```

## Session Replay

Save and replay sessions for historical analysis or sharing:

```bash
# Save a trace session
ttl 1.1.1.1 -c 100 --json > trace-$(date +%Y%m%d-%H%M%S).json

# Replay in TUI
ttl --replay trace-20240115-143022.json

# Replay and export as CSV
ttl --replay trace.json --csv > trace.csv
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Error (network, permissions, etc.) |
| 2 | Invalid arguments |

Use in scripts:

```bash
if ttl target.com -c 5 --no-tui > /dev/null 2>&1; then
    echo "Target reachable"
else
    echo "Target unreachable or error"
fi
```

## Tips for Scripting

1. **Always use `-c N`** to limit probe count - otherwise ttl runs indefinitely
2. **Use `--json`** for machine-readable output
3. **Use `--no-tui`** in headless environments to avoid terminal issues
4. **Set capabilities once** with `setcap` to avoid needing sudo in scripts
5. **Handle timeouts** - some targets may not respond to ICMP, try `-p udp` or `-p tcp`
