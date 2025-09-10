# Lab 02 — TLS 1.3 fingerprints

Goal: Summarize TLS metadata from Suricata `eve.json`: **top JA3** and **ALPN distribution**, and flag rare ALPN protocols.

## Learning outcomes
- Locate TLS events in `logs/suricata/eve.json`.
- Understand JA3 (client hello) at a high level.
- Compute ALPN frequency; reason about "rare" protocols as anomalies.

## Student tasks
1. List the **top JA3 hashes** and their counts (top 3 is fine in v1).
2. Identify **anomalous ALPN** tokens (rare protocols by share).

## Submitting
Provide an `answers.yml` like:

```yaml
top_ja3:
  - {hash: "…", count: 12}
  - {hash: "…", count: 8}
  - {hash: "…", count: 2}
anomalous_alpn:
  - "acme-tls/1"
