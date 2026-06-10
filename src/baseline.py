import sqlite3
import time
import os
from collections import defaultdict
import math

DB_PATH = '/home/devinlinux/sdztg-gateway/data/packets.db'

# ─── WINDOW AGGREGATION ───────────────────────────────────────────────
def get_windows(mac, window_seconds=60):
    """Pull packets for a device and bucket them into time windows."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        SELECT ts, ip_dst, port_dst, protocol, size
        FROM packets
        WHERE mac_src = ?
        ORDER BY ts ASC
    ''', (mac,))
    rows = c.fetchall()
    conn.close()

    if not rows:
        return []

    windows = []
    start_ts = rows[0][0]
    current_window = []

    for row in rows:
        ts, ip_dst, port_dst, protocol, size = row
        if ts - start_ts <= window_seconds:
            current_window.append(row)
        else:
            if current_window:
                windows.append(compute_features(current_window, start_ts))
            start_ts = ts
            current_window = [row]

    if current_window:
        windows.append(compute_features(current_window, start_ts))

    return windows

# ─── FEATURE COMPUTATION ──────────────────────────────────────────────
def compute_features(window, start_ts):
    """Compute per-window features for a device."""
    duration = max(window[-1][0] - start_ts, 1)
    pkt_count = len(window)
    byte_total = sum(r[4] for r in window)
    dst_ips = set(r[1] for r in window if r[1])
    dst_ports = set(r[2] for r in window if r[2])

    return {
        'start_ts':     start_ts,
        'pkt_rate':     pkt_count / duration,
        'byte_rate':    byte_total / duration,
        'dst_ip_count': len(dst_ips),
        'dst_port_count': len(dst_ports),
        'pkt_count':    pkt_count,
        'byte_total':   byte_total,
    }

# ─── BASELINE STATS ───────────────────────────────────────────────────
def compute_baseline(windows):
    """Compute mean and std dev for each feature across all windows."""
    if not windows:
        return {}

    features = ['pkt_rate', 'byte_rate', 'dst_ip_count', 'dst_port_count']
    baseline = {}

    for f in features:
        values = [w[f] for w in windows]
        mean = sum(values) / len(values)
        variance = sum((v - mean) ** 2 for v in values) / max(len(values) - 1, 1)
        std = math.sqrt(variance)
        baseline[f] = {'mean': mean, 'std': std, 'samples': len(values)}

    return baseline

# ─── SAVE BASELINE ────────────────────────────────────────────────────
def save_baseline(mac, baseline):
    """Store baseline in SQLite."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS baselines (
            mac         TEXT,
            feature     TEXT,
            mean        REAL,
            std         REAL,
            samples     INTEGER,
            updated_ts  REAL,
            PRIMARY KEY (mac, feature)
        )
    ''')
    for feature, stats in baseline.items():
        c.execute('''
            INSERT OR REPLACE INTO baselines
            (mac, feature, mean, std, samples, updated_ts)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (mac, feature, stats['mean'], stats['std'],
              stats['samples'], time.time()))
    conn.commit()
    conn.close()
    print(f"[BASELINE] Saved for {mac}")

# ─── GET ALL DEVICES ──────────────────────────────────────────────────
def get_all_devices():
    """Return all unique MAC addresses in the packets table."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT DISTINCT mac_src FROM packets')
    macs = [row[0] for row in c.fetchall()]
    conn.close()
    return macs

# ─── MAIN ─────────────────────────────────────────────────────────────
if __name__ == '__main__':
    devices = get_all_devices()
    print(f"[*] Found {len(devices)} device(s)")

    for mac in devices:
        windows = get_windows(mac)
        print(f"[*] {mac}: {len(windows)} window(s)")
        if windows:
            baseline = compute_baseline(windows)
            save_baseline(mac, baseline)
            for feature, stats in baseline.items():
                print(f"    {feature}: mean={stats['mean']:.2f} std={stats['std']:.2f}")