//! Build script.
//!
//! Defines the `per_probe_send` cfg: platforms where `sendto` is asynchronous enough
//! that a shared socket plus `setsockopt(IP_TTL / IPV6_UNICAST_HOPS)` per probe can
//! race — the kernel may stamp queued datagrams with a stale TTL, collapsing a trace to
//! a single hop (issue #12). On these platforms the engine sends each probe from a fresh
//! socket. IPv4 avoids this entirely via IP_HDRINCL; `per_probe_send` governs the IPv6
//! send path. Linux is excluded (its `sendto` does not exhibit the race).

fn main() {
    println!("cargo::rustc-check-cfg=cfg(per_probe_send)");
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if matches!(target_os.as_str(), "macos" | "freebsd" | "netbsd") {
        println!("cargo::rustc-cfg=per_probe_send");
    }
}
