# Known Issues

This document tracks known limitations and edge cases that are documented but not yet addressed.

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

**Mitigation:** CLI validation rejects `--timeout` > 256 × `--interval` with a clear error message.

---

### MaxMind GeoLite2 Database Not Bundled

**Issue:** GeoIP lookup requires a MaxMind GeoLite2-City.mmdb database file that must be downloaded separately (requires free MaxMind account).

**Impact:** GeoIP enrichment is unavailable without the database. Auto-discovered from `~/.local/share/ttl/`, `/usr/share/GeoIP/`, or specified via `--geoip-db`.

**Workaround:** Download from MaxMind and place in one of the auto-discovery paths. Disable with `--no-geo` to suppress warnings.

---

### Max TTL Capped at 64

**Issue:** `--max-ttl` is limited to 64 to prevent resource exhaustion (each TTL = 1 probe per round).

**Impact:** Paths longer than 64 hops cannot be fully traced. In practice, internet paths rarely exceed 30 hops.

**Workaround:** None. This is a deliberate safety limit.

---

## By Design

### macOS Requires Root

macOS DGRAM ICMP sockets cannot receive Time Exceeded messages from intermediate routers, so a RAW receive socket is required. RAW sockets need root privileges on macOS.

Linux users can run without sudo by setting `cap_net_raw` capability or configuring `ping_group_range`.

### Mixed IPv4/IPv6 with --source-ip Not Supported

When `--resolve-all` produces both IPv4 and IPv6 targets, `--source-ip` cannot be used because a source IP is inherently single-family. An error is shown suggesting `-4` or `-6` to constrain the family.

### macOS/FreeBSD Minimum Inter-Probe Delay

A 500µs minimum delay between probes is automatically applied on macOS and FreeBSD. BSD-derived kernels batch rapid `setsockopt(IP_TTL)` calls, causing packets to be sent with stale TTL values. This delay ensures each TTL change takes effect before the next send.

### Rate Limit Detection Skipped at Destination

The "isolated hop loss" heuristic requires a downstream hop for comparison. At the final hop, there's no downstream to compare against. High loss at the destination is often legitimate (firewall filtering, probe type rejection) rather than rate limiting.

### IPv6 Echo Reply Polling (Linux Only)

Linux delivers ICMPv6 Echo Reply only to the socket that sent the request, not to the separate receive socket. The engine polls the send socket for Echo Replies after each probe round. macOS delivers to any raw ICMPv6 socket, so the receiver handles it there.

### Last RTT Not Persisted in JSON

`last_rtt` is intentionally `#[serde(skip)]` — it represents the most recent probe response and is inherently a live-only metric. The `Last` column in TUI and `last_ms` in CSV will show "-"/empty for replayed sessions. All other RTT and jitter stats are persisted and display correctly.

### TCP Bitrate Not Paced

TCP mode ignores the `--rate` flag. TCP should run at the kernel's congestion-controlled rate. Rate limiting is only meaningful for ICMP and UDP probing modes.

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
- **One-at-a-time sent counting** — Sent counter updated only when responses arrived, not when probes were sent. Fixed by moving sent counting to engine at send time (#17).

---

## Future Improvements

Some issues listed here may be addressed in future releases. See the [ROADMAP.md](ROADMAP.md) for items under consideration.

---

## Reporting Issues

Found a bug not listed here? Please report it at: https://github.com/lance0/ttl/issues
