#!/usr/bin/env python3
"""
Generate a deterministic PCAP with three periodic beacon endpoints + noise.

Endpoints (dst_ip:dst_port) and periods:
  A) 203.0.113.55:443  every 60s,  count=10
  B) 198.51.100.9:80   every 30s,  count=12
  C) 203.0.113.99:22   every 45s,  count=8

We use UDP request/response pairs (Zeek logs them as separate connections over time).
Also emit a DNS A record mapping c2.netlab.example -> 203.0.113.55 once.

The file is deterministic (no randomness) so the grader & CI are stable.
"""
from pathlib import Path
import sys
from scapy.all import Ether, IP, UDP, DNS, DNSQR, DNSRR, Raw, wrpcap  # type: ignore

def emit_udp_pair(src, sport, dst, dport, t, payload=b"x"):
    req = Ether()/IP(src=src, dst=dst)/UDP(sport=sport, dport=dport)/Raw(load=payload)
    rsp = Ether()/IP(src=dst, dst=src)/UDP(sport=dport, dport=sport)/Raw(load=payload)
    req.time = t
    rsp.time = t + 0.010  # 10ms later
    return [req, rsp]

def emit_dns(qtime, client, server, name, ip):
    qid = 0x4242
    sport = 5555
    q = Ether()/IP(src=client, dst=server)/UDP(sport=sport, dport=53)/DNS(rd=1, id=qid, qd=DNSQR(qname=name, qtype="A"))
    a = Ether()/IP(src=server, dst=client)/UDP(sport=53, dport=sport)/DNS(
        id=qid, qr=1, aa=1, rd=1, ra=1, qd=DNSQR(qname=name),
        an=DNSRR(rrname=name, type="A", ttl=60, rdata=ip)
    )
    q.time = qtime
    a.time = qtime + 0.005
    return [q, a]

def main(out_path: Path):
    pkts = []
    t0 = 1_700_000_000.0  # fixed base epoch for determinism

    # One DNS mapping for cross-checks in the lab
    pkts += emit_dns(t0 + 1.0, "192.0.2.20", "198.51.100.53", "c2.netlab.example.", "203.0.113.55")

    # Beacon A: 60s period, 10 hits
    for i in range(10):
        pkts += emit_udp_pair("192.0.2.10", 40000+i, "203.0.113.55", 443, t0 + 5 + 60*i, b"A")

    # Beacon B: 30s period, 12 hits
    for i in range(12):
        pkts += emit_udp_pair("192.0.2.30", 41000+i, "198.51.100.9", 80, t0 + 7 + 30*i, b"B")

    # Beacon C: 45s period, 8 hits
    for i in range(8):
        pkts += emit_udp_pair("192.0.2.40", 42000+i, "203.0.113.99", 22, t0 + 9 + 45*i, b"C")

    # A bit of non-periodic noise
    noise_times = [13, 14.2, 17.8, 33.3, 101.5]
    for j, dt in enumerate(noise_times):
        pkts += emit_udp_pair("192.0.2.200", 50000+j, "203.0.113.200", 9999, t0 + dt, b"N")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(out_path), pkts)
    print(f"Wrote {len(pkts)} packets to {out_path}")

if __name__ == "__main__":
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "pcaps/input.pcap")
    main(out)
