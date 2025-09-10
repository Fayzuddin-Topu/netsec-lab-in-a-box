#!/usr/bin/env python3
"""
Generate a deterministic PCAP with multiple TLS flows that carry ALPN.

ALPN profiles and counts:
  - b"h2"         → 12 flows
  - b"http/1.1"   → 8 flows
  - b"acme-tls/1" → 2 flows   (rare → anomalous)

We hand‑craft BOTH ClientHello and ServerHello (no scapy.tls / cryptography).
Suricata will then emit `event_type:"tls"` with ALPN data.
"""

from pathlib import Path
import sys
import struct
from typing import List

from scapy.all import IP, TCP, wrpcap  # type: ignore


# ------------------- TLS extension builders -------------------

def _ext_sni(hostname: bytes) -> bytes:
    # server_name = name_type(0) + host_name_len + host_name
    server_name = b"\x00" + struct.pack("!H", len(hostname)) + hostname
    server_name_list = struct.pack("!H", len(server_name)) + server_name
    return struct.pack("!HH", 0x0000, len(server_name_list)) + server_name_list  # type 0x0000

def _ext_supported_versions(versions: List[int]) -> bytes:
    # SupportedVersions: 1-byte vector length, then 2-byte versions
    vbytes = b"".join(struct.pack("!H", v) for v in versions)
    body = struct.pack("!B", len(vbytes)) + vbytes
    return struct.pack("!HH", 0x002B, len(body)) + body  # type 0x002b

def _ext_signature_algorithms(algs: List[int]) -> bytes:
    # SignatureSchemeList: 2-byte list length, then 2-byte items
    abytes = b"".join(struct.pack("!H", a) for a in algs)
    body = struct.pack("!H", len(abytes)) + abytes
    return struct.pack("!HH", 0x000D, len(body)) + body  # type 0x000d

def _ext_supported_groups(groups: List[int]) -> bytes:
    gbytes = b"".join(struct.pack("!H", g) for g in groups)
    body = struct.pack("!H", len(gbytes)) + gbytes
    return struct.pack("!HH", 0x000A, len(body)) + body  # type 0x000a

def _ext_ec_point_formats() -> bytes:
    # ECPointFormats (len=1 list with 'uncompressed'=0)
    body = b"\x01\x00"
    return struct.pack("!HH", 0x000B, len(body)) + body  # type 0x000b

def _ext_alpn_client(alpns: List[bytes]) -> bytes:
    # ClientHello ALPN: ProtocolNameList = 2-byte length + repeated (len + name)
    plist = b"".join(bytes([len(p)]) + p for p in alpns)
    body = struct.pack("!H", len(plist)) + plist
    return struct.pack("!HH", 0x0010, len(body)) + body  # type 0x0010

def _ext_alpn_server(selected: bytes) -> bytes:
    # ServerHello ALPN also uses a ProtocolNameList but with a single selection
    pname = bytes([len(selected)]) + selected
    plist = struct.pack("!H", len(pname)) + pname
    return struct.pack("!HH", 0x0010, len(plist)) + plist  # type 0x0010


# ------------------- Handshake builders -------------------

def build_client_hello_bytes(hostname: bytes, alpns: List[bytes]) -> bytes:
    """
    Realistic ClientHello (TLS 1.2) with common ciphers and extensions.
    Record header uses TLS 1.2 (0x0303), handshake version 0x0303.
    """
    # Body
    body = b"\x03\x03"               # client_version TLS 1.2
    body += b"\x22" * 32             # random
    body += b"\x00"                  # session_id length = 0

    # Ciphers: include TLS1.3 and common TLS1.2 to look realistic
    ciphers = [0x1301, 0x1302, 0x1303, 0xC02F, 0xC030, 0x009E]
    cs = b"".join(struct.pack("!H", c) for c in ciphers)
    body += struct.pack("!H", len(cs)) + cs

    body += b"\x01\x00"              # compression methods: null

    # Extensions
    exts = b"".join([
        _ext_sni(hostname),
        _ext_supported_versions([0x0304, 0x0303]),       # TLS1.3, TLS1.2
        _ext_signature_algorithms([0x0804, 0x0403]),     # rsa_pss_rsae_sha256, ecdsa_secp256r1_sha256
        _ext_supported_groups([0x001D, 0x0017]),         # x25519, secp256r1
        _ext_ec_point_formats(),
        _ext_alpn_client(alpns),
    ])
    body += struct.pack("!H", len(exts)) + exts

    # Handshake header: ClientHello(type=1) + len(3 bytes)
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    # Record header: Handshake(22) + TLS1.2 + len
    record = b"\x16\x03\x03" + struct.pack("!H", len(handshake)) + handshake
    return record


def build_server_hello_bytes(selected_cipher: int, selected_alpn: bytes) -> bytes:
    """
    Minimal ServerHello that selects a cipher and ALPN.
    """
    body = b"\x03\x03"                # server_version TLS 1.2
    body += b"\x33" * 32              # random
    body += b"\x00"                   # session_id length = 0
    body += struct.pack("!H", selected_cipher)
    body += b"\x00"                   # compression method: null

    exts = _ext_alpn_server(selected_alpn)
    body += struct.pack("!H", len(exts)) + exts

    handshake = b"\x02" + len(body).to_bytes(3, "big") + body  # ServerHello(type=2)
    record = b"\x16\x03\x03" + struct.pack("!H", len(handshake)) + handshake
    return record


# ------------------- Flow builder -------------------

def emit_flow(pkts: list, t0: float, src: str, sport: int, dst: str, dport: int,
              ch: bytes, sh: bytes):
    """
    SYN, SYN/ACK, ACK, ClientHello, ServerHello, final ACK.
    Sequence/ACK arithmetic is correct so Suricata's parser is happy.
    """
    ISN, JSN = 100000 + sport, 200000 + sport
    clen, slen = len(ch), len(sh)

    # 1) SYN
    syn = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="S", seq=ISN)
    # 2) SYN/ACK
    synack = IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="SA", seq=JSN, ack=ISN + 1)
    # 3) ACK
    ack1 = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="A", seq=ISN + 1, ack=JSN + 1)
    # 4) ClientHello (PA)
    chseg = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="PA",
                                       seq=ISN + 1, ack=JSN + 1) / ch
    # 5) ServerHello (PA), ack the CH payload
    shseg = IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="PA",
                                       seq=JSN + 1, ack=ISN + 1 + clen) / sh
    # 6) Final ACK from client (no payload)
    ack2 = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="A",
                                      seq=ISN + 1 + clen, ack=JSN + 1 + slen)

    syn.time = t0
    synack.time = t0 + 0.001
    ack1.time = t0 + 0.002
    chseg.time = t0 + 0.010
    shseg.time = t0 + 0.015
    ack2.time = t0 + 0.020

    pkts.extend([syn, synack, ack1, chseg, shseg, ack2])


# ------------------- Main -------------------

def main(out_path: Path):
    base = 1_700_001_200.0
    pkts = []

    # (ALPNs, count, client subnet, server IP, SNI)
    profiles = [
        ([b"h2"],          12, "192.0.2.",    "203.0.113.10", b"api.example.test"),
        ([b"http/1.1"],     8, "192.0.2.",    "203.0.113.20", b"www.example.test"),
        ([b"acme-tls/1"],   2, "198.51.100.", "203.0.113.30", b"acme.example.test"),
    ]

    t = base
    sport_seed = 43000
    # We'll select TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xC02F)
    sel_cipher = 0xC02F

    for alpns, count, subnet, dst, sni in profiles:
        ch = build_client_hello_bytes(sni, alpns)
        # server chooses the first client ALPN
        sh = build_server_hello_bytes(sel_cipher, alpns[0])
        for i in range(count):
            src = f"{subnet}{10 + i}"
            sport = sport_seed + i
            emit_flow(pkts, t, src, sport, dst, 443, ch, sh)
            t += 0.050
        sport_seed += 100

    out_path.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(out_path), pkts)
    print(f"Wrote {len(pkts)} packets to {out_path}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 scripts/make_tls13_pcap.py pcaps/input.pcap", file=sys.stderr)
        sys.exit(2)
    main(Path(sys.argv[1]))
