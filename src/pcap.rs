//! `--pcap`: write the probes ttl sends and the ICMP it reads to a classic pcap
//! file for Wireshark or tcpdump.
//!
//! The file uses LINKTYPE_RAW (101): each record is a bare IPv4 or IPv6 packet,
//! so one capture holds both families. IPv4 probes are recorded exactly as
//! built for IP_HDRINCL. For IPv6 (and IPv4 ICMP read without its IP header)
//! the kernel owns the IP header, so one is synthesized from the socket's
//! local address, the peer, the hop limit and traffic class, and the payload.
//!
//! The probing hot path never blocks: packets go through a bounded queue to a
//! writer thread, and any that do not fit are counted and reported at exit.
//! The writer flushes after every burst, so an interrupted run still leaves a
//! readable file.

use anyhow::{Context, Result};
use socket2::Socket;
use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::sync::Mutex;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::probe::rawip::{HDRINCL_HOST_ORDER_LEN_OFF, build_ipv4_header, internet_checksum};

const LINKTYPE_RAW: u32 = 101;
const SNAPLEN: u32 = 65535;
/// Packets queued for the writer before new ones are dropped.
const QUEUE_CAPACITY: usize = 4096;
const IPPROTO_ICMP: u8 = 1;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_ICMPV6: u8 = 58;

enum Msg {
    Packet(Duration, Vec<u8>),
    Stop,
}

static SINK: OnceLock<SyncSender<Msg>> = OnceLock::new();
static DROPPED: AtomicU64 = AtomicU64::new(0);
/// Last known local address per family, for headers ttl has to synthesize
/// when the socket at hand is unbound (UDP/TCP sends, the receive socket).
static LOCAL: Mutex<(Option<Ipv4Addr>, Option<Ipv6Addr>)> = Mutex::new((None, None));

/// An open capture. Dropping it stops the writer, flushes the file, and
/// reports write errors or dropped packets on stderr.
pub(crate) struct Capture {
    path: String,
    writer: Option<JoinHandle<io::Result<()>>>,
}

/// Create `path` (refusing a symlink), write the pcap header, and start
/// recording. Only one capture can be started per process.
pub(crate) fn start(path: &str) -> Result<Capture> {
    let (tx, writer) = spawn_writer(Path::new(path))?;
    if SINK.set(tx).is_err() {
        anyhow::bail!("a pcap capture is already running");
    }
    Ok(Capture {
        path: path.to_string(),
        writer: Some(writer),
    })
}

impl Drop for Capture {
    fn drop(&mut self) {
        if let Some(tx) = SINK.get() {
            let _ = tx.send(Msg::Stop);
        }
        if let Some(Ok(Err(e))) = self.writer.take().map(JoinHandle::join) {
            eprintln!("Warning: writing {} failed: {e}", self.path);
        }
        let dropped = DROPPED.load(Ordering::Relaxed);
        if dropped > 0 {
            eprintln!(
                "Warning: {dropped} packets were not written to {} (capture queue full)",
                self.path
            );
        }
    }
}

fn spawn_writer(path: &Path) -> Result<(SyncSender<Msg>, JoinHandle<io::Result<()>>)> {
    let mut out = BufWriter::new(create_no_follow(path)?);
    out.write_all(&global_header())?;
    out.flush()?;
    let (tx, rx) = sync_channel(QUEUE_CAPACITY);
    let writer = std::thread::Builder::new()
        .name("pcap-writer".into())
        .spawn(move || write_loop(out, rx))?;
    Ok((tx, writer))
}

/// Captures are written under a user-chosen name, often in a shared directory;
/// like exports, never follow a symlink planted there.
fn create_no_follow(path: &Path) -> Result<File> {
    if std::fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_symlink()) {
        anyhow::bail!(
            "Refusing to write through the symlink {}; remove it or choose another path",
            path.display()
        );
    }
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // Closes the gap between the check above and the open
        options.custom_flags(libc::O_NOFOLLOW);
    }
    options
        .open(path)
        .with_context(|| format!("Failed to create {}", path.display()))
}

fn write_loop(mut out: impl Write, rx: Receiver<Msg>) -> io::Result<()> {
    while let Ok(first) = rx.recv() {
        let mut next = Some(first);
        while let Some(msg) = next {
            match msg {
                Msg::Packet(ts, packet) => {
                    out.write_all(&record_header(ts, packet.len()))?;
                    out.write_all(&packet)?;
                }
                Msg::Stop => return out.flush(),
            }
            next = rx.try_recv().ok();
        }
        // Flush each burst so an interrupted run leaves whole records on disk
        out.flush()?;
    }
    out.flush()
}

/// Classic pcap global header: little-endian, microsecond timestamps, v2.4.
fn global_header() -> [u8; 24] {
    let mut h = [0u8; 24];
    h[0..4].copy_from_slice(&0xa1b2_c3d4u32.to_le_bytes());
    h[4..6].copy_from_slice(&2u16.to_le_bytes());
    h[6..8].copy_from_slice(&4u16.to_le_bytes());
    // thiszone and sigfigs stay zero
    h[16..20].copy_from_slice(&SNAPLEN.to_le_bytes());
    h[20..24].copy_from_slice(&LINKTYPE_RAW.to_le_bytes());
    h
}

fn record_header(ts: Duration, len: usize) -> [u8; 16] {
    let len = len as u32;
    let mut h = [0u8; 16];
    h[0..4].copy_from_slice(&(ts.as_secs() as u32).to_le_bytes());
    h[4..8].copy_from_slice(&ts.subsec_micros().to_le_bytes());
    h[8..12].copy_from_slice(&len.to_le_bytes());
    h[12..16].copy_from_slice(&len.to_le_bytes());
    h
}

fn push(packet: Vec<u8>) {
    let Some(tx) = SINK.get() else { return };
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    // Disconnected means the capture already stopped (or failed and said so)
    if let Err(TrySendError::Full(_)) = tx.try_send(Msg::Packet(ts, packet)) {
        DROPPED.fetch_add(1, Ordering::Relaxed);
    }
}

fn enabled() -> bool {
    SINK.get().is_some()
}

/// A full IPv4 packet sent through IP_HDRINCL.
pub(crate) fn sent_ipv4(packet: &[u8]) {
    if !enabled() || packet.len() < 20 {
        return;
    }
    let mut packet = packet.to_vec();
    normalize_ipv4(&mut packet, HDRINCL_HOST_ORDER_LEN_OFF);
    remember(IpAddr::V4(Ipv4Addr::new(
        packet[12], packet[13], packet[14], packet[15],
    )));
    push(packet);
}

/// An ICMP/ICMPv6 message whose IP header the kernel adds.
pub(crate) fn sent_icmp(socket: &Socket, message: &[u8], target: IpAddr) {
    let protocol = if target.is_ipv6() {
        IPPROTO_ICMPV6
    } else {
        IPPROTO_ICMP
    };
    sent_transport(socket, protocol, message, target);
}

/// A TCP segment (ttl builds the header) whose IP header the kernel adds.
pub(crate) fn sent_tcp(socket: &Socket, segment: &[u8], target: IpAddr) {
    sent_transport(socket, IPPROTO_TCP, segment, target);
}

/// A UDP payload sent on a datagram socket: the kernel adds both the UDP and
/// the IP header, so both are synthesized.
pub(crate) fn sent_udp(socket: &Socket, payload: &[u8], target: IpAddr, port: u16) {
    if !enabled() {
        return;
    }
    let src_port = socket
        .local_addr()
        .ok()
        .and_then(|a| a.as_socket())
        .map_or(0, |a| a.port());
    let src = local_source(Some(socket), target);
    let datagram = udp_datagram(src, target, src_port, port, payload);
    sent_transport(socket, IPPROTO_UDP, &datagram, target);
}

fn sent_transport(socket: &Socket, protocol: u8, payload: &[u8], target: IpAddr) {
    if !enabled() {
        return;
    }
    let src = local_source(Some(socket), target);
    let packet = match (src, target) {
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            let hop_limit = socket.unicast_hops_v6().unwrap_or(0) as u8;
            #[cfg(unix)]
            let traffic_class = socket.tclass_v6().unwrap_or(0) as u8;
            #[cfg(not(unix))]
            let traffic_class = 0;
            ipv6_packet(src, dst, protocol, hop_limit, traffic_class, payload)
        }
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            let ttl = socket.ttl_v4().unwrap_or(0) as u8;
            let tos = socket.tos_v4().unwrap_or(0) as u8;
            ipv4_packet(src, dst, protocol, ttl, tos, payload)
        }
        _ => return,
    };
    push(packet);
}

/// ICMP read from a receive socket. IPv4 raw sockets include the IP header;
/// IPv6 sockets and IPv4 datagram sockets do not, so it is synthesized with
/// the responder as source and the response TTL/hop limit when known.
pub(crate) fn received(data: &[u8], from: IpAddr, response_ttl: Option<u8>) {
    if !enabled() || data.is_empty() {
        return;
    }
    let local = local_source(None, from);
    push(received_packet(data, from, local, response_ttl));
}

fn received_packet(data: &[u8], from: IpAddr, local: IpAddr, ttl: Option<u8>) -> Vec<u8> {
    // No ICMP type has 4 in its high nibble, so this tells a raw IPv4 read
    // (header included) from a datagram read (bare ICMP)
    if from.is_ipv4() && data[0] >> 4 == 4 && data.len() >= 20 {
        let mut packet = data.to_vec();
        // BSD kernels hand raw reads up with ip_len rewritten; the buffer is
        // the whole packet, so restore the on-wire length from it
        normalize_ipv4(&mut packet, false);
        return packet;
    }
    let ttl = ttl.unwrap_or(64);
    match (from, local) {
        (IpAddr::V6(src), IpAddr::V6(dst)) => ipv6_packet(src, dst, IPPROTO_ICMPV6, ttl, 0, data),
        (IpAddr::V4(src), IpAddr::V4(dst)) => ipv4_packet(src, dst, IPPROTO_ICMP, ttl, 0, data),
        (IpAddr::V6(src), _) => {
            ipv6_packet(src, Ipv6Addr::UNSPECIFIED, IPPROTO_ICMPV6, ttl, 0, data)
        }
        (IpAddr::V4(src), _) => ipv4_packet(src, Ipv4Addr::UNSPECIFIED, IPPROTO_ICMP, ttl, 0, data),
    }
}

/// The socket's bound address when it has one, else the last local address
/// seen for the family, else the kernel's route choice toward `peer`.
// ponytail: one cached source per family; a multi-homed run with --interface
// may record the default route's source. Thread the engine's src_ip through if
// that matters.
fn local_source(socket: Option<&Socket>, peer: IpAddr) -> IpAddr {
    if let Some(ip) = socket
        .and_then(|s| s.local_addr().ok())
        .and_then(|a| a.as_socket())
        .map(|a| a.ip())
        .filter(|ip| !ip.is_unspecified())
    {
        remember(ip);
        return ip;
    }
    let cached = {
        let local = LOCAL.lock().unwrap_or_else(|e| e.into_inner());
        match peer {
            IpAddr::V4(_) => local.0.map(IpAddr::V4),
            IpAddr::V6(_) => local.1.map(IpAddr::V6),
        }
    };
    cached.unwrap_or_else(|| {
        let ip = crate::probe::get_local_addr(peer);
        remember(ip);
        ip
    })
}

fn remember(ip: IpAddr) {
    if ip.is_unspecified() {
        return;
    }
    let mut local = LOCAL.lock().unwrap_or_else(|e| e.into_inner());
    match ip {
        IpAddr::V4(v4) => local.0 = Some(v4),
        IpAddr::V6(v6) => local.1 = Some(v6),
    }
}

/// Put an IPv4 header in on-wire form: total length from the buffer, flags
/// and fragment offset in network order, and a valid header checksum (the
/// kernel fills the checksum for HDRINCL sends; the IP ID it may assign is
/// not visible here and stays as built).
fn normalize_ipv4(packet: &mut [u8], off_in_host_order: bool) {
    let ihl = usize::from(packet[0] & 0x0f) * 4;
    if ihl < 20 || packet.len() < ihl || packet.len() > usize::from(u16::MAX) {
        return;
    }
    let total_len = packet.len() as u16;
    packet[2..4].copy_from_slice(&total_len.to_be_bytes());
    if off_in_host_order {
        let off = u16::from_ne_bytes([packet[6], packet[7]]);
        packet[6..8].copy_from_slice(&off.to_be_bytes());
    }
    packet[10..12].fill(0);
    let checksum = internet_checksum(&packet[..ihl]);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
}

fn ipv4_packet(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    protocol: u8,
    ttl: u8,
    tos: u8,
    payload: &[u8],
) -> Vec<u8> {
    let len = (20 + payload.len()).min(usize::from(u16::MAX)) as u16;
    let header = build_ipv4_header(src, dst, protocol, ttl, tos, len, 0, false);
    let mut packet = [&header[..], payload].concat();
    normalize_ipv4(&mut packet, HDRINCL_HOST_ORDER_LEN_OFF);
    packet
}

fn ipv6_packet(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    next_header: u8,
    hop_limit: u8,
    traffic_class: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut packet = Vec::with_capacity(40 + payload.len());
    // Version 6, traffic class, flow label 0
    packet.extend_from_slice(&(0x6000_0000u32 | u32::from(traffic_class) << 20).to_be_bytes());
    packet.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    packet.push(next_header);
    packet.push(hop_limit);
    packet.extend_from_slice(&src.octets());
    packet.extend_from_slice(&dst.octets());
    packet.extend_from_slice(payload);
    packet
}

/// A UDP header + payload with a valid checksum for either family.
fn udp_datagram(src: IpAddr, dst: IpAddr, src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let len = (8 + payload.len()) as u16;
    let mut datagram = Vec::with_capacity(usize::from(len));
    datagram.extend_from_slice(&src_port.to_be_bytes());
    datagram.extend_from_slice(&dst_port.to_be_bytes());
    datagram.extend_from_slice(&len.to_be_bytes());
    datagram.extend_from_slice(&[0, 0]);
    datagram.extend_from_slice(payload);
    let mut pseudo = Vec::with_capacity(40 + datagram.len());
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            pseudo.extend_from_slice(&s.octets());
            pseudo.extend_from_slice(&d.octets());
            pseudo.extend_from_slice(&[0, IPPROTO_UDP]);
            pseudo.extend_from_slice(&len.to_be_bytes());
        }
        (s, d) => {
            let as_v6 = |ip: IpAddr| match ip {
                IpAddr::V6(v6) => v6,
                IpAddr::V4(v4) => v4.to_ipv6_mapped(),
            };
            pseudo.extend_from_slice(&as_v6(s).octets());
            pseudo.extend_from_slice(&as_v6(d).octets());
            pseudo.extend_from_slice(&u32::from(len).to_be_bytes());
            pseudo.extend_from_slice(&[0, 0, 0, IPPROTO_UDP]);
        }
    }
    pseudo.extend_from_slice(&datagram);
    // A computed 0 is sent as 0xFFFF (RFC 768; mandatory for IPv6)
    let checksum = match internet_checksum(&pseudo) {
        0 => 0xFFFF,
        c => c,
    };
    datagram[6..8].copy_from_slice(&checksum.to_be_bytes());
    datagram
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn global_and_record_headers_are_byte_exact() {
        assert_eq!(
            global_header(),
            [
                0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 101,
                0, 0, 0
            ]
        );
        let ts = Duration::new(0x0102_0304, 567_890_123);
        assert_eq!(
            record_header(ts, 84),
            [4, 3, 2, 1, 0x52, 0xaa, 0x08, 0, 84, 0, 0, 0, 84, 0, 0, 0]
        );
    }

    #[test]
    fn ipv6_header_synthesis() {
        let src: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let dst: Ipv6Addr = "2001:db8::2".parse().unwrap();
        let packet = ipv6_packet(src, dst, IPPROTO_ICMPV6, 7, 0xb8, &[128, 0, 0, 0]);
        assert_eq!(packet.len(), 44);
        // version 6, traffic class 0xb8 (DSCP 46), flow label 0
        assert_eq!(&packet[0..4], &[0x6b, 0x80, 0, 0]);
        assert_eq!(&packet[4..6], &[0, 4]); // payload length
        assert_eq!(packet[6], 58); // next header
        assert_eq!(packet[7], 7); // hop limit
        assert_eq!(&packet[8..24], &src.octets());
        assert_eq!(&packet[24..40], &dst.octets());
        assert_eq!(&packet[40..], &[128, 0, 0, 0]);
    }

    #[test]
    fn ipv4_headers_are_normalized_to_wire_form() {
        let src = Ipv4Addr::new(192, 0, 2, 1);
        let dst = Ipv4Addr::new(198, 51, 100, 7);
        let packet = ipv4_packet(src, dst, IPPROTO_ICMP, 3, 0, &[8, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(&packet[2..4], &28u16.to_be_bytes());
        assert_eq!(&packet[6..8], &[0, 0]);
        assert_eq!(
            internet_checksum(&packet[..20]),
            0,
            "header checksum must verify"
        );

        // A BSD-style host-order header: ip_off DF in native order
        let mut bsd = packet.clone();
        bsd[6..8].copy_from_slice(&0x4000u16.to_ne_bytes());
        normalize_ipv4(&mut bsd, true);
        assert_eq!(&bsd[6..8], &[0x40, 0]);
    }

    #[test]
    fn received_ipv6_and_dgram_ipv4_get_a_header_raw_ipv4_is_kept() {
        let responder: IpAddr = "2001:db8::9".parse().unwrap();
        let local: IpAddr = "2001:db8::1".parse().unwrap();
        let icmp = [3, 0, 0, 0, 0, 0, 0, 0];
        let packet = received_packet(&icmp, responder, local, Some(61));
        assert_eq!(packet.len(), 48);
        assert_eq!(packet[6], 58);
        assert_eq!(packet[7], 61);
        assert_eq!(
            &packet[8..24],
            &"2001:db8::9".parse::<Ipv6Addr>().unwrap().octets()
        );
        assert_eq!(
            &packet[24..40],
            &"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets()
        );

        let responder = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5));
        let local = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let bare = received_packet(&[11, 0, 0, 0, 0, 0, 0, 0], responder, local, Some(250));
        assert_eq!(bare.len(), 28);
        assert_eq!((bare[0], bare[8], bare[9]), (0x45, 250, IPPROTO_ICMP));
        assert_eq!(&bare[12..16], &[203, 0, 113, 5]);

        let raw = received_packet(&bare, responder, local, None);
        assert_eq!(raw, bare, "a raw IPv4 read already carries its header");
    }

    #[test]
    fn udp_checksum_verifies_for_both_families() {
        for (src, dst) in [
            ("192.0.2.1", "198.51.100.7"),
            ("2001:db8::1", "2001:db8::2"),
        ] {
            let (src, dst): (IpAddr, IpAddr) = (src.parse().unwrap(), dst.parse().unwrap());
            let datagram = udp_datagram(src, dst, 50000, 33434, b"probe");
            assert_eq!(&datagram[0..6], &[0xc3, 0x50, 0x82, 0x9a, 0, 13]);
            // Re-summing with the checksum in place must yield zero
            let mut check = Vec::new();
            match (src, dst) {
                (IpAddr::V4(s), IpAddr::V4(d)) => {
                    check.extend_from_slice(&s.octets());
                    check.extend_from_slice(&d.octets());
                    check.extend_from_slice(&[0, 17, 0, 13]);
                }
                (IpAddr::V6(s), IpAddr::V6(d)) => {
                    check.extend_from_slice(&s.octets());
                    check.extend_from_slice(&d.octets());
                    check.extend_from_slice(&[0, 0, 0, 13, 0, 0, 0, 17]);
                }
                _ => unreachable!(),
            }
            check.extend_from_slice(&datagram);
            assert_eq!(internet_checksum(&check), 0, "{src} -> {dst}");
        }
    }

    #[test]
    fn writer_produces_a_parseable_capture() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.pcap");
        let (tx, writer) = spawn_writer(&path).unwrap();
        let v4 = ipv4_packet(
            Ipv4Addr::new(192, 0, 2, 1),
            Ipv4Addr::new(198, 51, 100, 7),
            IPPROTO_ICMP,
            1,
            0,
            &[8, 0, 0, 0, 0, 0, 0, 0],
        );
        let v6 = ipv6_packet(
            "2001:db8::1".parse().unwrap(),
            "2001:db8::2".parse().unwrap(),
            IPPROTO_ICMPV6,
            1,
            0,
            &[128, 0, 0, 0, 0, 0, 0, 0],
        );
        for (i, packet) in [&v4, &v6].into_iter().enumerate() {
            tx.send(Msg::Packet(
                Duration::new(1_700_000_000 + i as u64, 1_000),
                packet.clone(),
            ))
            .unwrap();
        }
        tx.send(Msg::Stop).unwrap();
        writer.join().unwrap().unwrap();

        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(&bytes[..24], &global_header());
        let mut rest = &bytes[24..];
        let mut records = Vec::new();
        while !rest.is_empty() {
            let u32_at = |o: usize| u32::from_le_bytes(rest[o..o + 4].try_into().unwrap());
            let (secs, micros, incl, orig) = (u32_at(0), u32_at(4), u32_at(8), u32_at(12));
            assert_eq!(incl, orig);
            records.push((secs, micros, rest[16..16 + incl as usize].to_vec()));
            rest = &rest[16 + incl as usize..];
        }
        assert_eq!(
            records,
            vec![(1_700_000_000, 1, v4), (1_700_000_001, 1, v6)]
        );
    }

    #[cfg(unix)]
    #[test]
    fn capture_refuses_a_symlinked_destination() {
        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("victim");
        std::fs::write(&victim, b"keep").unwrap();
        let link = dir.path().join("t.pcap");
        std::os::unix::fs::symlink(&victim, &link).unwrap();
        let error = spawn_writer(&link)
            .map(|_| ())
            .expect_err("must not follow a symlink");
        assert!(error.to_string().contains("symlink"), "{error}");
        assert_eq!(std::fs::read(&victim).unwrap(), b"keep");
    }
}
