# Lab 01 — Beacon Hunt

This lab teaches simple network-beacon detection using Zeek `conn.log`.

## Run (lite mode)
1. Generate the dataset:
   ```bash
   python3 -m pip install scapy
   python3 scripts/make_beacon_pcap.py pcaps/input.pcap

2. Process with Zeek + Suricate:
   ```bash
   docker compose -f compose/docker-compose.lite.yml up --build

3. open notebooks (optional):
   ```bash
   make demo MODE=lite
