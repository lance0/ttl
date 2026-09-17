# fakertr — a fake RFC 5837 router for end-to-end smoke tests

Runs the real `ttl` binary against a router that appends RFC 5837 Interface
Information Objects to its ICMP Time Exceeded messages, so the whole receive
path (raw socket → receiver → extension parser → hop state → TUI / `--json`)
is exercised with real packets. No RFC 5837-capable hardware needed.

Topology, all inside one privileged container:

```
main netns                      rtr netns
ttl ── veth0 10.200.0.1 ───── veth1 10.200.0.2 (fakertr.py)
       route 10.250.0.0/24 via 10.200.0.2
```

- TTL=1 probes to `10.250.0.9` → Time Exceeded from `10.200.0.2` with two
  Interface Information Objects (incoming `Ethernet1@fake-rt1`, outgoing
  `Ethernet2@fake-rt1`).
- TTL≥2 probes → Echo Reply spoofed from `10.250.0.9`, so ttl sees a 2-hop path.

## Usage

```sh
cargo build --release
docker build -t ttl-fakertr scripts/fakertr

# JSON export: hop 1 should carry interface_info with both objects
docker run --rm --privileged -v "$PWD:/w" -w /w ttl-fakertr \
  ./target/release/ttl --no-dns --no-asn --no-geo --no-ix --no-update-check \
  -p icmp -c 3 --max-ttl 4 --json 10.250.0.9

# TUI: press Down, then Enter on hop 1 for the "Interface (RFC 5837)" lines
docker run --rm -it --privileged -v "$PWD:/w" -w /w ttl-fakertr \
  ./target/release/ttl --no-dns --no-asn --no-geo --no-ix --no-update-check -p icmp 10.250.0.9
```

`--privileged` is needed for `ip netns` inside the container. `setup.sh`
turns off `ip_forward` in the `rtr` namespace on purpose: a privileged
container inherits `1`, and the kernel would then answer probes with its own
Destination Unreachables before the responder does.

`sniff.py <seconds>` logs every inbound ICMP on ttl's side (type, source,
quoted probe seq) — run it in the background inside the container when a
result looks off.

Nothing here is part of the crate or the binary; it is excluded from
`cargo publish`.
