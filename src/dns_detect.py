import sqlite3
import time
import math
from collections import defaultdict
from scapy.all import sniff, DNS, DNSQR, DNSRR, Ether, IP

DB_PATH = '/home/devinlinux/sdztg-gateway/data/packets.db'

# ─── DATABASE SETUP ───────────────────────────────────────────────────
def init_dns_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS dns_events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ts          REAL,
            mac_src     TEXT,
            query       TEXT,
            label_len   INTEGER,
            entropy     REAL,
            alert       TEXT
        )
    ''')
    conn.commit()
    conn.close()

# ─── ENTROPY CALCULATION ──────────────────────────────────────────────
def label_entropy(name):
    """Calculate Shannon entropy of a DNS label."""
    if not name:
        return 0.0
    freq = defaultdict(int)
    for c in name:
        freq[c] += 1
    length = len(name)
    entropy = -sum((count/length) * math.log2(count/length)
                   for count in freq.values())
    return round(entropy, 4)

# ─── PER-DEVICE TRACKING ──────────────────────────────────────────────
# Track DNS queries per device in a sliding window
device_dns = defaultdict(list)  # mac -> [(ts, query)]

def check_exfiltration(mac, query, ts):
    """
    Check for DNS exfiltration indicators:
    1. >10 distinct DNS destinations in 10 seconds
    2. Subdomain label length > 40 chars
    3. High entropy subdomain (> 3.5 bits)
    """
    alerts = []

    # Clean label — strip trailing dot and get subdomain
    clean = query.rstrip('.')
    parts = clean.split('.')
    subdomain = parts[0] if len(parts) > 2 else ''
    entropy = label_entropy(subdomain)

    # Rule 1: label length
    if len(subdomain) > 40:
        alerts.append(f"LONG_LABEL:{len(subdomain)}chars")

    # Rule 2: high entropy subdomain
    if entropy > 3.5 and len(subdomain) > 8:
        alerts.append(f"HIGH_ENTROPY:{entropy}")

    # Rule 3: distinct destinations in 10 sec window
    device_dns[mac].append((ts, clean))
    cutoff = ts - 10
    device_dns[mac] = [(t, q) for t, q in device_dns[mac] if t > cutoff]
    distinct = len(set(q for _, q in device_dns[mac]))
    if distinct > 10:
        alerts.append(f"BURST:{distinct}_destinations_in_10s")

    return alerts, entropy, len(subdomain)

# ─── PACKET HANDLER ───────────────────────────────────────────────────
def handle_dns(pkt):
    if not (pkt.haslayer(DNS) and pkt.haslayer(DNSQR)):
        return
    if not pkt.haslayer(Ether) or not pkt.haslayer(IP):
        return
    # Only process queries (qr=0), not responses
    if pkt[DNS].qr != 0:
        return

    mac = pkt[Ether].src
    query = pkt[DNSQR].qname.decode('utf-8', errors='replace')
    ts = time.time()

    alerts, entropy, label_len = check_exfiltration(mac, query, ts)

    if alerts:
        alert_str = ' | '.join(alerts)
        print(f"[🚨 ALERT] {mac} -> {query}")
        print(f"    Alerts: {alert_str}")
        print(f"    Entropy: {entropy}  Label len: {label_len}")
        # Save to DB
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('''
            INSERT INTO dns_events
            (ts, mac_src, query, label_len, entropy, alert)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (ts, mac, query, label_len, entropy, alert_str))
        conn.commit()
        conn.close()
    else:
        print(f"[DNS] {mac} -> {query} (entropy={entropy}, len={label_len})")

# ─── MAIN ─────────────────────────────────────────────────────────────
if __name__ == '__main__':
    INTERFACE = 'enp1s0'
    init_dns_db()
    print(f"[*] DNS exfiltration detector running on {INTERFACE}")
    print(f"[*] Rules: label>40chars | entropy>3.5 | >10 dst in 10s")
    print(f"[*] Ctrl+C to stop\n")
    sniff(iface=INTERFACE, prn=handle_dns,
          filter='udp port 53', store=False)