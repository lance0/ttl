import socket, struct, sys, time
NAMES={0:"EchoReply",3:"DestUnreach",8:"EchoReq",11:"TimeExceeded"}
s=socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800)); s.bind(("veth0",0)); s.settimeout(0.5)
t0=time.time(); n=0
while time.time()-t0 < float(sys.argv[1]):
    try: f,_=s.recvfrom(65535)
    except socket.timeout: continue
    ip=f[14:]; ihl=(ip[0]&0xF)*4
    if ip[9]!=1: continue
    src=socket.inet_ntoa(ip[12:16]); dst=socket.inet_ntoa(ip[16:20]); icmp=ip[ihl:]
    if dst!="10.200.0.1": continue   # inbound to ttl only
    t,c=icmp[0],icmp[1]; extra=""
    if t in (3,11):
        q=icmp[8:]; qihl=(q[0]&0xF)*4; qi=q[qihl:qihl+8]
        if len(qi)>=8: extra=" quoted: type=%d id=%d seq=0x%04x (ttl=%d seq=%d)" % (qi[0], struct.unpack("!H",qi[4:6])[0], struct.unpack("!H",qi[6:8])[0], qi[6], qi[7])
    else:
        extra=" seq=0x%04x" % struct.unpack("!H",icmp[6:8])[0]
    n+=1; print("%6.1fms  from %-11s %-13s code=%d%s" % ((time.time()-t0)*1000, src, NAMES.get(t,t), c, extra), flush=True)
print("total inbound ICMP:", n)
