#!/usr/bin/env python3
import sys
from pathlib import Path

# Scapy imports
from scapy.all import Ether, IP, UDP, ICMP, DNS, DNSQR, DNSRR, Raw, wrpcap  # type: ignore

out = Path(sys.argv[1] if len(sys.argv) > 1 else "pcaps/input.pcap")
out.parent.mkdir(parents=True, exist_ok=True)

pkts = []

# 1) ICMP echo req/rep (gives Zeek a conn.log entry even without TCP)
ip_a, ip_b = "192.0.2.10", "198.51.100.1"
pkts.append(Ether()/IP(src=ip_a, dst=ip_b)/ICMP()/Raw(load=b"ping"))
pkts.append(Ether()/IP(src=ip_b, dst=ip_a)/ICMP(type="echo-reply")/Raw(load=b"pong"))

# 2) DNS query/answer (generates Zeek dns.log and Suricata DNS events)
client, dns = "192.0.2.20", "198.51.100.53"
qid = 0x1337
sport = 12345
qname = "example.com."
pkts.append(Ether()/IP(src=client, dst=dns)/UDP(sport=sport, dport=53)/DNS(rd=1, id=qid, qd=DNSQR(qname=qname, qtype="A")))
pkts.append(Ether()/IP(src=dns, dst=client)/UDP(sport=53, dport=sport)
           /DNS(id=qid, qr=1, aa=1, rd=1, ra=1, qd=DNSQR(qname=qname),
                an=DNSRR(rrname=qname, type="A", ttl=60, rdata="93.184.216.34")))

wrpcap(str(out), pkts)
print(f"Wrote {len(pkts)} packets to {out}")
