# Architecture

This document describes the internal architecture of ttl.

## Module Overview

```
src/
├── main.rs              # Entry point, mode dispatch (TUI, batch, streaming, replay, diff)
├── cli.rs               # Clap argument definitions and validation
├── config.rs            # Runtime probe configuration derived from CLI args
├── lib.rs               # Library entry point
├── prefs.rs             # User preferences (config.toml)
├── persistence.rs       # Atomic file writes for preferences and exports
├── update.rs            # Startup release check and install-method detection
├── metrics.rs           # Prometheus/OpenMetrics endpoint (/metrics, /healthz)
├── probe/               # Packet crafting and ICMP parsing
│   ├── icmp.rs          # ICMP Echo probe construction
│   ├── udp.rs           # UDP probe construction
│   ├── tcp.rs           # TCP SYN probe construction
│   ├── rawip.rs         # IPv4 header construction for IP_HDRINCL sends
│   ├── socket.rs        # Socket creation and permission checks
│   ├── correlate.rs     # ICMP response parsing and ICMP extensions
│   └── interface.rs     # Network interface binding
├── trace/               # Probe orchestration
│   ├── engine.rs        # Per-target probe scheduler (and PMTUD)
│   ├── receiver.rs      # Shared ICMP response handler
│   └── pending.rs       # Pending probe correlation map
├── state/               # Session and hop state
│   ├── session.rs       # Session, Hop, ResponderStats, ProbeId, PMTUD state
│   ├── ratelimit.rs     # ICMP rate limit detection
│   └── mod.rs           # Re-exports
├── lookup/              # Enrichment lookups
│   ├── asn.rs           # Team Cymru ASN lookup
│   ├── rdns.rs          # Reverse DNS resolution
│   ├── geo.rs           # MaxMind GeoIP lookup
│   └── ix.rs            # PeeringDB IX detection
├── tui/                 # Terminal user interface
│   ├── app.rs           # TUI main loop and event handling
│   ├── theme.rs         # Color themes
│   ├── views/           # Main table, hop detail, help, settings, target list, add-target input
│   └── widgets/         # Custom widgets (sparkline)
└── export/              # Output formats
    ├── json.rs          # JSON export
    ├── csv.rs           # CSV export
    ├── report.rs        # Text report
    ├── stream.rs        # Line-delimited JSON events (--stream-json)
    └── diff.rs          # Session comparison (--diff)
```

## Data Flow

```
                    ┌─────────────────────────────────────────────┐
                    │                  main.rs                     │
                    │  (parse args, create sessions, spawn tasks)  │
                    └─────────────────┬───────────────────────────┘
                                      │
              ┌───────────────────────┼───────────────────────┐
              │                       │                       │
              ▼                       ▼                       ▼
     ┌────────────────┐      ┌────────────────┐      ┌────────────────┐
     │  Engine (T1)   │      │  Engine (T2)   │      │  Engine (Tn)   │
     │  (tokio task)  │      │  (tokio task)  │      │  (tokio task)  │
     └───────┬────────┘      └───────┬────────┘      └───────┬────────┘
             │                       │                       │
             │ send probe            │ send probe            │ send probe
             │ + register in         │ + register in         │ + register in
             │ pending map           │ pending map           │ pending map
             │                       │                       │
             └───────────────────────┼───────────────────────┘
                                     │
                                     ▼
                         ┌────────────────────────┐
                         │     PendingMap         │
                         │  (Arc<RwLock<HashMap>>)│
                         └───────────┬────────────┘
                                     │
                                     ▼
                         ┌────────────────────────┐
                         │      Receiver          │
                         │   (dedicated thread)   │
                         │  - recv ICMP responses │
                         │  - correlate to probes │
                         │  - update session state│
                         │  - handle timeouts     │
                         └────────────────────────┘
```

## Threading Model

ttl uses a hybrid async/sync model:

1. **Main tokio runtime** - Orchestrates async tasks
2. **Engine tasks (async)** - One per target, sends probes at intervals
3. **Receiver thread (sync)** - Dedicated OS thread for blocking socket I/O
4. **Enrichment tasks (async)** - ASN, rDNS, GeoIP, IX lookups

The receiver runs on a dedicated thread because:
- Raw ICMP sockets use blocking I/O (no async support in socket2)
- Ensures responses are processed with low latency
- Avoids blocking the tokio runtime

## Key Data Structures

### Session (`state/session.rs`)

Per-target session containing:
- `target: Target` - Target as given, resolved IP, and hostname
- `hops: Vec<Hop>` - One entry per TTL up to `--max-ttl`
- `complete: bool` - Whether destination was reached
- `dest_ttl: Option<u8>` - TTL at which destination was reached
- `pmtud: Option<PmtudState>` - Path MTU discovery state
- `events: Vec<ProbeEvent>` - Recorded probe outcomes for replay (not kept in `--daemon`, Prometheus-only, or plain `--no-tui` runs)

### Hop (`state/session.rs`)

Per-hop statistics:
- `responders: HashMap<IpAddr, ResponderStats>` - Per-IP stats for ECMP, each with RTT/jitter stats, the last 256 RTT samples for percentiles, enrichment, MPLS labels, and RFC 5837 interface data
- `flow_paths: HashMap<u8, FlowPathStats>` - Per-flow stats for Paris traceroute
- `nat_info`, `rate_limit`, `route_changes`, `asymmetry`, `ttl_manip` - Detection state

### PendingMap (`trace/pending.rs`)

Maps `(ProbeId, flow_id, target, is_pmtud)` to `PendingProbe`:
- Shared between all engines and the receiver
- Engines insert before sending probes
- Receiver removes when responses arrive or timeout

### ProbeId (`state/session.rs`)

Identifies a probe:
- `ttl: u8` - TTL/hop-limit of the probe
- `seq: u8` - Round sequence number (wraps at 256)

Both are packed into a 16-bit value (`ttl << 8 | seq`) carried in the ICMP Echo sequence field, the first two bytes of the UDP payload, or the upper half of the TCP sequence number.

## PMTUD Algorithm

Path MTU Discovery uses binary search:

1. Start with `min=68` (IPv4) or `min=1280` (IPv6) and `max=1500` (9216 with `--jumbo`); probe `max` first, DF set, at the destination TTL
2. Two destination Echo Replies at a size: `min = size`, record it as `confirmed_size`
3. Two failures (timeout, intermediate reply) or one local EMSGSIZE: `max = size - 1`
4. Frag Needed / Packet Too Big with an MTU between `min` and the probe size: `max = reported_mtu` and probe it next (a later link may be smaller); other MTU values count as a failure
5. Next probe is `(min + max) / 2`; once `max - min < 8`, an unconfirmed `min` is probed before finishing
6. Result: `confirmed_size`, or none (`MTU: unconfirmed`) if no size was ever confirmed

PMTUD probes use a separate `is_pmtud` flag in the pending map key to avoid collisions with normal probes.

## Paris/Dublin Traceroute

Multi-flow probing for ECMP path enumeration:

- Each flow uses source port `base + flow_id`
- ECMP routers hash on (src_ip, dst_ip, src_port, dst_port, protocol)
- Different source ports cause different path selections
- Flow ID derived from returned source port in ICMP error payload
- TUI shows a "Paths" column when `--flows > 1`; flows require UDP or TCP probes

### Enrichment progress and shutdown

DNS, ASN, GeoIP and IX workers exclude fresh negative cache entries before
applying their batch limit. Missing data on early hops therefore does not block
later addresses. In-flight DNS/ASN/IX batches are cancelled on shutdown without
waiting for the remote resolver or API timeout.
