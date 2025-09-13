#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Lab 03 DNS PCAP generator (for Zeek dns.log):
- Benign A queries
- Suspicious:
  * Very long first label (NXDOMAIN)
  * Deep label chain (many labels)
  * TXT query (possible exfil)
  * High-entropy (DGA-like) label (NXDOMAIN)

Output: pcaps/input.pcap (overwrite)
"""

from pathlib import Path
import sys
from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, wrpcap  # type: ignore


def build_pkts():
    server = "203.0.113.53"  # TEST-NET-3
    clients = [f"192.0.2.{n}" for n in range(10, 15)]
    sport = 53000
    base_ts = 1700000000.0
    pkts = []

    def add_query(cip, name, qtype="A", rcode=0, answer=None, dt=0.0):
        nonlocal sport, base_ts
        sport += 1
        q = DNS(id=(sport & 0xFFFF), rd=1, qd=DNSQR(qname=name, qtype=qtype))
        req = IP(src=cip, dst=server) / UDP(sport=sport, dport=53) / q
        req.time = base_ts + dt
        pkts.append(req)

        if rcode == 0:
            if answer is None:
                if qtype == "A":
                    ans = DNSRR(rrname=name, type="A", rdata="198.51.100.200", ttl=60)
                elif qtype == "TXT":
                    ans = DNSRR(rrname=name, type="TXT", rdata="ok", ttl=60)
                else:
                    ans = None
            else:
                ans = answer
            resp = DNS(
                id=q.id, qr=1, aa=1, rd=1, ra=1, qd=q.qd, an=ans if ans else None
            )
        else:
            resp = DNS(id=q.id, qr=1, aa=1, rd=1, ra=1, rcode=rcode, qd=q.qd)

        r = IP(src=server, dst=cip) / UDP(sport=53, dport=sport) / resp
        r.time = req.time + 0.01
        pkts.append(r)

    # Benign A queries
    benign = [
        "www.example.com.",
        "www.iana.org.",
        "opensearch.org.",
        "www.zeek.org.",
        "www.suricata.io.",
    ]
    t = 0.0
    for i, name in enumerate(benign):
        add_query(clients[i % len(clients)], name, "A", rcode=0, dt=t)
        t += 0.05

    # Suspicious set
    longlabel = "x" * 52 + ".exfil.lab.test."
    deep = "a1.a2.a3.a4.a5.a6.a7.a8.deep.lab.test."
    txtq = "large-txt.data.test."
    # High-entropy/DGA-like label (mix letters/digits)
    dga = "k3j9qv7apd0zmxwq2y8n3b5.dga.lab.test."

    add_query(clients[0], longlabel, "A", rcode=3, dt=t)
    t += 0.05  # NXDOMAIN
    add_query(clients[1], deep, "A", rcode=0, dt=t)
    t += 0.05  # OK but deep
    add_query(clients[2], txtq, "TXT", rcode=0, dt=t)
    t += 0.05  # TXT
    add_query(clients[3], dga, "A", rcode=3, dt=t)
    t += 0.05  # NXDOMAIN + entropy

    return pkts


def main():
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("pcaps/input.pcap")
    out.parent.mkdir(parents=True, exist_ok=True)
    pkts = build_pkts()
    wrpcap(str(out), pkts)
    print(f"Wrote {len(pkts)} packets to {out}")


if __name__ == "__main__":
    main()
