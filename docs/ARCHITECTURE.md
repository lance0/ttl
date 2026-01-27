# Architecture

This document describes the internal architecture of ttl.

## Module Overview

```
src/
├── main.rs              # Entry point, CLI parsing, mode dispatch
├── cli.rs               # Clap argument definitions
├── lib.rs               # Library entry point
├── prefs.rs             # User preferences (theme persistence)
├── probe/               # Packet crafting and ICMP parsing
│   ├── icmp.rs          # ICMP Echo probe construction
│   ├── udp.rs           # UDP probe construction
│   ├── tcp.rs           # TCP SYN probe construction
│   ├── socket.rs        # Raw socket creation
│   ├── correlate.rs     # ICMP response parsing
│   └── interface.rs     # Network interface binding
├── trace/               # Probe orchestration
│   ├── engine.rs        # Per-target probe scheduler
│   ├── receiver.rs      # Shared ICMP response handler
│   └── pending.rs       # Pending probe correlation map
├── state/               # Session and hop state
│   ├── session.rs       # Per-target session state
│   ├── ratelimit.rs     # ICMP rate limit detection
│   └── mod.rs           # Hop, FlowStats, PMTUD types
├── lookup/              # Enrichment lookups
│   ├── asn.rs           # Team Cymru ASN lookup
│   ├── rdns.rs          # Reverse DNS resolution
│   ├── geo.rs           # MaxMind GeoIP lookup
│   └── ix.rs            # PeeringDB IX detection
├── tui/                 # Terminal user interface
│   ├── app.rs           # TUI main loop and event handling
│   ├── theme.rs         # Color themes
│   ├── views/           # Main view, hop detail, help
│   └── widgets/         # Custom widgets (sparkline)
└── export/              # Output formats
    ├── json.rs          # JSON export
    ├── csv.rs           # CSV export
    └── report.rs        # Text report
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
- `target: IpAddr` - Destination IP
- `hops: Vec<Option<Hop>>` - Hop data indexed by TTL
- `complete: bool` - Whether destination was reached
- `dest_ttl: Option<u8>` - TTL at which destination was reached
- `pmtud: Option<PmtudState>` - Path MTU discovery state

### Hop (`state/mod.rs`)

Per-hop statistics:
- `responders: HashMap<IpAddr, ResponseStats>` - Per-IP stats for ECMP
- `flow_stats: Vec<FlowStats>` - Per-flow stats for Paris traceroute
- `samples: VecDeque<Duration>` - RTT history for percentiles
- NAT detection, MPLS labels, rate limit detection

### PendingMap (`trace/pending.rs`)

Maps `(ProbeId, flow_id, target, is_pmtud)` to `PendingProbe`:
- Shared between all engines and the receiver
- Engines insert before sending probes
- Receiver removes when responses arrive or timeout

### ProbeId (`state/mod.rs`)

Identifies a probe:
- `ttl: u8` - TTL/hop-limit of the probe
- `seq: u16` - Sequence number (ICMP) or checksum (UDP)

## PMTUD Algorithm

Path MTU Discovery uses binary search:

1. Start with `min=68` (IPv4) or `min=1280` (IPv6), `max=9216`
2. Send probe with size `mid = (min + max) / 2`, DF flag set
3. On success: `min = mid + 1`
4. On Frag Needed: `max = reported_mtu - 1` (or `mid - 1` if no MTU)
5. On timeout: retry up to 3 times, then `max = mid - 1`
6. Repeat until `min > max`
7. Result: last successful size (or min-1 if none succeeded)

PMTUD probes use a separate `is_pmtud` flag in the pending map key to avoid collisions with normal probes.

## Paris/Dublin Traceroute

Multi-flow probing for ECMP path enumeration:

- Each flow uses source port `base + flow_id`
- ECMP routers hash on (src_ip, dst_ip, src_port, dst_port, protocol)
- Different source ports cause different path selections
- Flow ID derived from returned source port in ICMP error payload
- TUI shows "Paths" column when multiple responders per hop/flow
