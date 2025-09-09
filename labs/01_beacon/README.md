# Lab 01 — Beacon Hunt

Goal: Use Zeek `conn.log` to find periodic "beacon"-like connections.

## Learning outcomes
- Read Zeek `conn.log` (TSV), understand key fields.
- Compute inter-arrival times and simple periodicity stats (mean, stddev, CV).
- Cross-check with DNS where relevant.

## Student tasks
1. Identify the **top 3 candidate beacon endpoints** as `IP:port`.
2. Provide a **period estimate (seconds)** and **count** for each.

## What counts as a beacon (v1 heuristic)
- Same destination endpoint repeated over time.
- At least 5 occurrences.
- Low inter-arrival variability (coefficient of variation ≤ 0.2 is a good sign).

## Submitting
Produce `answers.yml` like:
```yaml
beacons:
  - endpoint: "203.0.113.55:443"
    period_sec: 60
    count: 10
  - endpoint: "198.51.100.9:80"
    period_sec: 30
    count: 12
  - endpoint: "203.0.113.99:22"
    period_sec: 45
    count: 8
