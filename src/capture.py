import sys
import os
sys.path.insert(0, os.path.dirname(__file__))
from anomaly import compute_anomaly_score, save_anomaly_event
from scapy.all import sniff, Ether, IP, TCP, UDP
import sqlite3
import time

# ─── DATABASE SETUP ───────────────────────────────────────────────────
DB_PATH = '/home/devinlinux/sdztg-gateway/data/packets.db'

def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS packets (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            ts        REAL,
            mac_src   TEXT,
            mac_dst   TEXT,
            ip_src    TEXT,
            ip_dst    TEXT,
            port_src  INTEGER,
            port_dst  INTEGER,
            protocol  TEXT,
            size      INTEGER
        )
    ''')
    c.execute('CREATE INDEX IF NOT EXISTS idx_mac_ts ON packets (mac_src, ts)')
    conn.commit()
    conn.close()
    print(f"[DB] Initialized at {DB_PATH}")

# ─── PACKET PARSER ────────────────────────────────────────────────────
def parse_packet(pkt):
    if not pkt.haslayer(Ether) or not pkt.haslayer(IP):
        return None
    eth = pkt[Ether]
    ip  = pkt[IP]
    proto = 'OTHER'
    port_src = port_dst = None
    if pkt.haslayer(TCP):
        proto    = 'TCP'
        port_src = pkt[TCP].sport
        port_dst = pkt[TCP].dport
    elif pkt.haslayer(UDP):
        proto    = 'UDP'
        port_src = pkt[UDP].sport
        port_dst = pkt[UDP].dport
    return {
        'ts':       time.time(),
        'mac_src':  eth.src,
        'mac_dst':  eth.dst,
        'ip_src':   ip.src,
        'ip_dst':   ip.dst,
        'port_src': port_src,
        'port_dst': port_dst,
        'protocol': proto,
        'size':     len(pkt),
    }

# ─── PACKET HANDLER ───────────────────────────────────────────────────
packet_counter = 0

def handle_packet(pkt):
    global packet_counter
    record = parse_packet(pkt)
    if record is None:
        return
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        INSERT INTO packets
        (ts, mac_src, mac_dst, ip_src, ip_dst, port_src, port_dst, protocol, size)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        record['ts'], record['mac_src'], record['mac_dst'],
        record['ip_src'], record['ip_dst'], record['port_src'],
        record['port_dst'], record['protocol'], record['size']
    ))
    conn.commit()
    conn.close()
    
    print(f"[PKT] {record['mac_src']} -> {record['ip_dst']}:{record['port_dst']} ({record['protocol']}) {record['size']}B")

    # Score every 20 packets
    packet_counter += 1
    if packet_counter % 20 == 0:
        score, breakdown = compute_anomaly_score(record['mac_src'])
        if score is not None and score >= 0.3:
            save_anomaly_event(record['mac_src'], score, breakdown)
            print(f"[SCORE] {record['mac_src']} -> {score}")

# ─── MAIN ─────────────────────────────────────────────────────────────
if __name__ == '__main__':
    INTERFACE = 'enp1s0'
    print("[*] Script started")
    init_db()
    print("[*] DB initialized")
    print(f"[*] Capturing on {INTERFACE} — Ctrl+C to stop")
    sniff(iface=INTERFACE, prn=handle_packet, store=False)