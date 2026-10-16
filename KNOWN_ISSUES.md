# Known Issues

This document tracks known limitations and edge cases that are documented but not yet addressed.

## Limitations

### Privileges Required

- **Linux:** needs the `CAP_NET_RAW` capability or root ([setup](docs/INSTALL.md#permissions)).
- **macOS, FreeBSD, NetBSD:** needs root (`sudo ttl <target>`). ttl receives ICMP replies through raw sockets on these platforms, and raw sockets require root.

### Protocol Limitations

- **ICMP:** some networks filter ICMP; try `-p udp` or `-p tcp`.
- **TCP:** probes are SYN only; ttl never completes a connection.
- **UDP:** high destination ports may be filtered by firewalls; set a port with `--port` (and `--fixed-port`).

### Multi-flow Mode Behind NAT

NAT devices may rewrite source ports, which breaks flow correlation for `--flows`. ttl detects this and shows the `NAT` title flag ([NAT Detection](docs/FEATURES.md#nat-detection)).

### PMTUD Requires ICMP Probing

`--pmtud` sends ICMP Echo probes, so it works only when ttl probes with ICMP (`-p icmp`, or `-p auto` when it selects ICMP). `--pmtud` with `-p udp` or `-p tcp` is rejected at startup.

### Interface Binding Unavailable on FreeBSD/NetBSD

`--interface` is rejected on FreeBSD and NetBSD, which lack `SO_BINDTODEVICE`/`IP_BOUND_IF`. Use `--source-ip` instead.

### No Live Tracing on Native Windows

The crate builds on native Windows and `--replay`/`--diff` work there, but probing is not implemented; ttl exits with a pointer to WSL2. There are no pre-built Windows binaries ([Windows setup](docs/INSTALL.md#windows)).

### iTerm2 on macOS Sequoia

The initial display may render incorrectly in iTerm2 on macOS Sequoia. Press `r` to reset, or use Terminal.app.

---

## Low Priority / Edge Cases

### macOS DGRAM Identifier Override

**Issue:** macOS DGRAM ICMP sockets can override the ICMP identifier field in outgoing Echo Requests.

**Impact:** If a router quotes only the minimum 8 bytes of the original packet (RFC 792) AND macOS rewrites the identifier, that hop becomes unmatchable and appears as a timeout.

**Mitigation:** Payload-based correlation fallback extracts the identifier from embedded payload bytes. Only fails in the rare combination of minimum-quoting router + identifier rewrite.

---

### FreeBSD Gateway Detection Unavailable

**Issue:** Gateway detection uses `getifs` which relies on macOS-specific APIs (`NET_RT_IFLIST2`, `rt_msghdr`) that don't exist in FreeBSD's libc bindings.

**Impact:** TUI title bar won't show the gateway IP on FreeBSD. Traceroute functionality is unaffected.

**Workaround:** None needed — gateway info is cosmetic.

---

### IPv6 Fragmented Responses Rejected

**Issue:** IPv6 responses containing Fragment extension headers are discarded during parsing.

**Impact:** If a router sends a fragmented ICMPv6 Time Exceeded response, that hop appears as a timeout. Extremely rare in practice since ICMPv6 error messages are small.

**Mitigation:** None needed.

---

### PeeringDB Anonymous Rate Limiting

**Issue:** Anonymous PeeringDB API access is rate-limited to ~1 request/hour for large queries (full IX prefix list).

**Impact:** IX detection may fail on first run if another query was made recently. Data is cached locally for 24 hours after a successful fetch.

**Workaround:** Set `PEERINGDB_API_KEY` environment variable or configure via the settings modal (`s` key) for 40 requests/minute.

---

### ProbeId Sequence Wrap at 256

**Issue:** `ProbeId.seq` is a `u8` (0-255). If `--timeout` exceeds 256 × `--interval`, old probes may still be pending when the sequence wraps, causing mis-correlation.

**Impact:** Only affects unusual configurations with very long timeouts relative to probe interval.

**Mitigation:** CLI validation rejects `--timeout` ≥ 256 × `--interval` with a clear error message.

---

### MaxMind GeoLite2 Database Not Bundled

**Issue:** GeoIP lookup requires a MaxMind GeoLite2-City.mmdb database file that must be downloaded separately (requires free MaxMind account).

**Impact:** GeoIP enrichment is unavailable without the database.

**Workaround:** Download it from MaxMind and place it in one of the [auto-discovery paths](docs/FEATURES.md#geoip-location), or pass `--geoip-db`. Disable with `--no-geo` to suppress warnings.

---

### Max TTL Capped at 64

**Issue:** `--max-ttl` is limited to 64 to prevent resource exhaustion (each TTL = 1 probe per round).

**Impact:** Paths longer than 64 hops cannot be fully traced. In practice, internet paths rarely exceed 30 hops.

**Workaround:** None. This is a deliberate safety limit.

---

## By Design

### `--flows` Has No Effect with ICMP Protocol

ICMP probes have no source/destination port to vary, so all probes are sent as flow 0 regardless of the `--flows` value. Multi-flow ECMP detection requires `--protocol udp` or `--protocol tcp`. ttl warns at runtime when `--flows > 1` resolves to effective ICMP probing.

### macOS Requires Root

On macOS, ttl receives replies through a RAW ICMP socket, and RAW sockets need root privileges. Linux users can run without sudo by granting the binary the `cap_net_raw` capability; Linux's unprivileged ICMP sockets (`ping_group_range`) are not used.

### Mixed IPv4/IPv6 with --source-ip Not Supported

When `--resolve-all` produces both IPv4 and IPv6 targets, `--source-ip` cannot be used because a source IP is inherently single-family. An error is shown suggesting `-4` or `-6` to constrain the family.

### NetBSD UDP Source IP Auto-Detection

NetBSD's kernel returns EHOSTUNREACH when sending from a UDP DGRAM socket bound to `0.0.0.0` (unspecified source). This differs from Linux and macOS which handle source address selection transparently. ttl auto-detects the correct source IP on NetBSD using `connect()` + `getsockname()` before binding UDP sockets. If auto-detection fails, the error is surfaced to the user.

### Rate Limit Detection Skipped at Destination

The "isolated hop loss" heuristic requires a downstream hop for comparison. At the final hop, there's no downstream to compare against. High loss at the destination is often legitimate (firewall filtering, probe type rejection) rather than rate limiting.

### IPv6 Echo Reply Polling (Linux Only)

Linux delivers ICMPv6 Echo Reply only to the socket that sent the request, not to the separate receive socket. The engine polls the send socket for Echo Replies after each probe round. macOS delivers to any raw ICMPv6 socket, so the receiver handles it there.

### Replies Behind Destination NAT Need a Single Target

Past a destination NAT (for example a load-balancer VIP), routers quote the translated address in their Time Exceeded messages. With one target, ttl still attributes those replies to it. With several targets the quoted destination is ambiguous, so such replies are dropped and those hops appear as timeouts. Trace a DNAT'd address on its own to see them.

### Last RTT Not Persisted in JSON

`last_rtt` is intentionally `#[serde(skip)]` — it represents a live-only sample. The `Last` column in TUI and `last_ms` in CSV are sourced from the current primary responder's `last_rtt`, and will show "-"/empty for replayed sessions. All other RTT and jitter stats are persisted and display correctly.

---

## Previously Known Issues (Resolved)

The following issues have been fixed and are listed here for reference.

- **macOS probes sent with wrong TTL in initial burst** (#12) — Rapid `setsockopt(IP_TTL)` calls were batched by macOS kernel. Fixed with 200µs (later 500µs) minimum inter-probe delay.
- **Startup false drops** — Fast ICMP responses arrived before probe was registered. Fixed with insert-before-send pattern using shared pending map.
- **PMTUD probe ID collision** — Normal and PMTUD probes with same ProbeId collided. Fixed by adding `is_pmtud` flag to pending map key.
- **FreeBSD ICMP sockets** (#14) — FreeBSD doesn't support `SOCK_DGRAM + IPPROTO_ICMP`. Fixed by using RAW sockets directly on FreeBSD.
- **Dual-stack --resolve-all** (#11) — `--resolve-all` silently dropped one address family. Fixed by spawning dual receivers when both families present.
- **Sent count double-counting** — IPv6 Echo Reply handler incremented sent count on response, duplicating the engine-side count. Fixed by removing receiver-side counting.
- **DFZ router startup hang** (#16) — Gateway detection shelled out to `ip route` which hung on systems with millions of routes. Fixed with direct kernel API calls (netlink/sysctl).
- **ICMPv6 checksum computation** — IPv6 traceroute didn't detect destinations due to checksum 0. Fixed with manual ICMPv6 checksum using RFC 8200 pseudo-header.
- **Concurrent ttl instances picked up each other's replies** — The ICMP identifier was the process ID, so instances in separate containers (all PID 1) shared it. Each process now picks a random identifier, and replies are matched only against the destination they quote, never another target's probes.
- **Silent hops flagged as rate limited** — A hop that never answered showed `100% RL` and put `RL?` in the title. Rate-limit detection now requires at least one reply.
- **macOS/FreeBSD/NetBSD minimum inter-probe delay** — A 500µs delay masked BSD kernels sending queued probes with a stale TTL. Retired once IPv4 moved to `IP_HDRINCL` (TTL in the header) and IPv6 to per-probe sockets on BSD-derived platforms; only the `--rate` delay remains.
- **NetBSD IPv4 PMTUD unavailable** — NetBSD lacks `IP_DONTFRAG`. IPv4 now sets Don't Fragment in the hand-built IP header, so IPv4 PMTUD works on NetBSD.
- **TCP probes ignored `--rate`** — TCP probing now applies the `--rate` delay like ICMP and UDP.
- **One-at-a-time sent counting** — Sent counter updated only when responses arrived, not when probes were sent. Fixed by moving sent counting to engine at send time (#17).

---

## Future Improvements

Some issues listed here may be addressed in future releases. See the [ROADMAP.md](ROADMAP.md) for items under consideration.

---

## Reporting Issues

Found a bug not listed here? Please report it at: https://github.com/lance0/ttl/issues
