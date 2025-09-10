# NetSec Lab‑in‑a‑Box (v1)

**One command to spin up Zeek + Suricata, load curated pcaps, and guide students through three foundational network‑security labs—complete with dashboards, notebooks, and an autograder.**

> v1 scope: offline pcaps only; no live capture; minimal dashboards; laptop‑friendly.

## Quickstart (scaffold only)
This is the initial scaffold. Containers and datasets arrive in the next steps.
- Install Git, Docker, and Python 3.11+.
- See docs/ once published for full usage.

## Project status
- ✅ Repo scaffold, CI sanity test
- ⏳ Zeek/Suricata containers
- ⏳ Labs & autograder
- ⏳ Full mode (OpenSearch + Dashboards)

## Lab 01 quickstart (lite)
```bash
python3 -m pip install scapy
python3 scripts/make_beacon_pcap.py pcaps/input.pcap
docker compose -f compose/docker-compose.lite.yml up --build
python3 -m pip install -e ./grader
labgrade labs/01_beacon labs/01_beacon/answers.sample.yml --logs ./logs

## Lab 02 quickstart (lite)
```bash
python3 -m pip install scapy
python3 scripts/make_tls13_pcap.py pcaps/input.pcap
docker compose -f compose/docker-compose.lite.yml up --build
python3 -m pip install -e ./grader
labgrade labs/02_tls13_fingerprints labs/02_tls13_fingerprints/answers.sample.yml --logs ./logs
