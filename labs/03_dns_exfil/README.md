# Lab 03 — DNS Exfiltration (Zeek)

**Learning outcomes**
- Parse Zeek `dns.log` (ASCII), compute label length & entropy.
- Spot TXT spikes and NXDOMAIN bursts; reason about query volume asymmetries.
- Flag suspicious FQDNs with justification (length/entropy/rate).

**Data source**
- `logs/zeek/dns.log` produced by the lite stack (`zeek -r pcaps/input.pcap local`).

**Student tasks**
1. Load `dns.log` and extract rows (fields like `query`, `qtype_name`, `rcode_name`).
2. For each `query` (FQDN), compute:
   - total length; label count; maximum label length
   - shannon entropy of `[a-z0-9]`-only version
   - TXT ratio and NXDOMAIN ratio
3. Flag suspicious FQDNs, justify with your metrics.
4. Put your final list into `answers.yml`:

```yaml
suspect_rrnames:
  - "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.exfil.lab.test."
  - "a1.a2.a3.a4.a5.a6.a7.a8.deep.lab.test."
  - "large-txt.data.test."
  - "k3j9qv7apd0zmxwq2y8n3b5.dga.lab.test."
