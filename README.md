# SDZTG-gateway

## Overview
The Software-Defined Zero-Trust Gateway (SDZTG) is a plug-and-play 
hardware-software appliance that enforces Zero-Trust security principles 
on behalf of commodity IoT devices that cannot protect themselves. It sits 
inline between IoT devices and the enterprise network, inspecting and 
controlling all traffic without requiring any modification to the protected 
devices.

Built on a Raspberry Pi / commodity Linux platform using Python, Scapy, 
SQLite, Flask, and a PPO-based reinforcement learning policy core.

## Current Status
✅ Phase 0 — Foundation complete (repo, environment, lab topology)
✅  Phase 1 — Writing first unit test (in progress)
✅ Phase 1.1 — Packet capture + SQLite persistence working
✅ Phase 2 — Baseline behavior profiling working (4 devices, real std dev)
✅ Phase 3 — Anomaly score engine working, tested with live traffic anomaly
✅ Phase 4 — DNS exfiltration detection working (LONG_LABEL + HIGH_ENTROPY + BURST)
✅ Phase 5 — Real-time WebSocket dashboard, <2s lag, WAL SQLite, inline anomaly scoring
✅ Phase 6 — Telegram + webhook alerts firing in real time

## Hardware
- Gateway: PC running Ubuntu 26.04 LTS (dual NIC)
- Test device: Raspberry Pi Zero 2 W
- See docs/lab.md for full topology and specs

## Setup
**Linux (gateway machine)**
```bash
git clone https://github.com/DeToKn/SDZTG-gateway.git
cd SDZTG-gateway
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

**Workflow**
1. Code on Windows (VS Code + Remote SSH)
2. Push to GitHub
3. Pull on Linux
4. Run and test

## Documentation
- [Lab Topology](docs/lab.md)