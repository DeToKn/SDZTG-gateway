#!/bin/bash
# ─── SDZTG STARTUP SCRIPT ─────────────────────────────────────────────
cd ~/sdztg-gateway
source .venv/bin/activate

echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║   SDZTG — Zero Trust Gateway                ║"
echo "║   Starting Traffic Anomaly Detector...       ║"
echo "╚══════════════════════════════════════════════╝"
echo ""

# Step 1: Enable WAL mode
sqlite3 /home/devinlinux/sdztg-gateway/data/packets.db "PRAGMA journal_mode=WAL;" > /dev/null 2>&1
echo "[✓] Database ready"

# Step 2: Start dashboard in background
.venv/bin/python src/dashboard.py &
DASHBOARD_PID=$!
echo "[✓] Dashboard running at http://192.168.1.218:5000"
sleep 2

# Step 3: Start alert monitor in background
.venv/bin/python src/alerts.py &
ALERTS_PID=$!
echo "[✓] Telegram alert monitor running"
sleep 1

# Step 4: Start DNS detector in background
sudo .venv/bin/python src/dns_detect.py &
DNS_PID=$!
echo "[✓] DNS exfiltration detector running"
sleep 1

echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║   All services started.                     ║"
echo "║   Dashboard: http://192.168.1.218:5000       ║"
echo "║   Ctrl+C to stop everything                 ║"
echo "╚══════════════════════════════════════════════╝"
echo ""

trap "echo 'Shutting down...'; kill $DASHBOARD_PID $ALERTS_PID $DNS_PID 2>/dev/null; exit 0" INT

sudo .venv/bin/python src/capture.py