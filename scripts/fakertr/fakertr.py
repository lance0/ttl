"""Fake RFC 5837 router. Runs inside the `rtr` netns on veth1.

TTL=1 echo requests to the fake destination get an ICMP Time Exceeded from
10.200.0.2 carrying an RFC 4884 extension with two RFC 5837 Interface
Information Objects (incoming + outgoing). TTL>=2 requests get an Echo Reply
spoofed from the destination 10.250.0.9, so ttl sees a 2-hop path.
"""
import socket, struct

ROUTER = "10.200.0.2"
DEST = "10.250.0.9"

def csum(b):
    if len(b) % 2: b += b"\0"
    s = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    s = (s >> 16) + (s & 0xFFFF); s += s >> 16
    return (~s) & 0xFFFF

def iface_obj(role, ifindex, ip, name, mtu):
    nm = name.encode()
    nlen = 1 + len(nm); nlen += (-nlen) % 4          # length octet included, pad to 4
    body = struct.pack("!I", ifindex)
    body += struct.pack("!HH4s", 1, 0, socket.inet_aton(ip))
    body += bytes([nlen]) + nm + b"\0" * (nlen - 1 - len(nm))
    body += struct.pack("!I", mtu)
    ctype = (role << 6) | 0x0F
    return struct.pack("!HBB", 4 + len(body), 2, ctype) + body

def time_exceeded(orig_ip):
    quoted = (orig_ip[:128] + b"\0" * 128)[:128]
    ext = struct.pack("!BBH", 0x20, 0, 0)
    ext += iface_obj(0, 1, ROUTER, "Ethernet1@fake-rt1", 1500)
    ext += iface_obj(2, 2, "10.250.0.1", "Ethernet2@fake-rt1", 9000)
    ext = ext[:2] + struct.pack("!H", csum(ext)) + ext[4:]
    icmp = struct.pack("!BBHBBH", 11, 0, 0, 0, 32, 0) + quoted + ext   # byte5: 32 words = 128 B
    icmp = icmp[:2] + struct.pack("!H", csum(icmp)) + icmp[4:]
    return icmp

def echo_reply(orig_icmp):
    icmp = b"\0\0\0\0" + orig_icmp[4:]
    return icmp[:2] + struct.pack("!H", csum(icmp)) + icmp[4:]

def ipv4(src, dst, payload):
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 0, 0, 64, 1, 0,
                      socket.inet_aton(src), socket.inet_aton(dst))
    return hdr + payload

sniff = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
sniff.bind(("veth1", 0))
out = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
out.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
print("fakertr: up on veth1", flush=True)
while True:
    frame, _ = sniff.recvfrom(65535)
    ip = frame[14:]
    if len(ip) < 28 or ip[9] != 1: continue
    ihl = (ip[0] & 0xF) * 4
    dst = socket.inet_ntoa(ip[16:20]); src = socket.inet_ntoa(ip[12:16]); ttl = ip[8]
    icmp = ip[ihl:]
    if dst != DEST or icmp[0] != 8: continue
    if ttl == 1:
        out.sendto(ipv4(ROUTER, src, time_exceeded(ip)), (src, 0))
        print("TE(ttl=1)+RFC5837 -> %s" % src, flush=True)
    else:
        out.sendto(ipv4(DEST, src, echo_reply(icmp)), (src, 0))
        print("EchoReply(ttl=%d) -> %s" % (ttl, src), flush=True)
