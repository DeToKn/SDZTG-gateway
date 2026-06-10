import sqlite3
import time
import math
import os
from baseline import get_windows, compute_features, get_all_devices

DB_PATH = '/home/devinlinux/sdztg-gateway/data/packets.db'

# ─── LOAD BASELINE ────────────────────────────────────────────────────
def load_baseline(mac):
    """Load stored baseline stats for a device."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        SELECT feature, mean, std FROM baselines WHERE mac = ?
    ''', (mac,))
    rows = c.fetchall()
    conn.close()
    if not rows:
        return None
    return {row[0]: {'mean': row[1], 'std': row[2]} for row in rows}

# ─── Z-SCORE ──────────────────────────────────────────────────────────
def z_score(value, mean, std):
    """Compute z-score. If std is 0, return 0 if value matches mean, else 3."""
    if std == 0:
        return 0.0 if value == mean else 3.0
    return abs(value - mean) / std

# ─── ANOMALY SCORE ────────────────────────────────────────────────────
def compute_anomaly_score(mac, window_seconds=60):
    """
    Compute anomaly score [0.0 - 1.0] for a device's most recent window.
    Score is the weighted average of z-scores across all features,
    clamped to [0, 1].
    """
    baseline = load_baseline(mac)
    if baseline is None:
        return None, {}

    windows = get_windows(mac, window_seconds)
    if not windows:
        return None, {}

    latest = windows[-1]

    feature_map = {
        'pkt_rate':       latest.get('pkt_rate', 0),
        'byte_rate':      latest.get('byte_rate', 0),
        'dst_ip_count':   latest.get('dst_ip_count', 0),
        'dst_port_count': latest.get('dst_port_count', 0),
    }

    scores = {}
    for feature, value in feature_map.items():
        if feature in baseline:
            z = z_score(value, baseline[feature]['mean'], baseline[feature]['std'])
            scores[feature] = round(min(z / 3.0, 1.0), 4)

    if not scores:
        return 0.0, {}

    final_score = round(sum(scores.values()) / len(scores), 4)
    return final_score, scores

# ─── SAVE ANOMALY EVENT ───────────────────────────────────────────────
def save_anomaly_event(mac, score, feature_scores):
    """Log anomaly event to SQLite."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS anomaly_events (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            ts            REAL,
            mac           TEXT,
            score         REAL,
            pkt_rate_z    REAL,
            byte_rate_z   REAL,
            dst_ip_z      REAL,
            dst_port_z    REAL
        )
    ''')
    c.execute('''
        INSERT INTO anomaly_events
        (ts, mac, score, pkt_rate_z, byte_rate_z, dst_ip_z, dst_port_z)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (
        time.time(), mac, score,
        feature_scores.get('pkt_rate', 0),
        feature_scores.get('byte_rate', 0),
        feature_scores.get('dst_ip_count', 0),
        feature_scores.get('dst_port_count', 0),
    ))
    conn.commit()
    conn.close()

# ─── MAIN ─────────────────────────────────────────────────────────────
if __name__ == '__main__':
    devices = get_all_devices()
    print(f"[*] Scoring {len(devices)} device(s)\n")

    for mac in devices:
        score, breakdown = compute_anomaly_score(mac)
        if score is None:
            print(f"[?] {mac}: no baseline yet")
            continue

        # Color coding
        if score >= 0.7:
            status = "🔴 HIGH"
        elif score >= 0.3:
            status = "🟡 MEDIUM"
        else:
            status = "🟢 LOW"

        print(f"[{status}] {mac}")
        print(f"    Score: {score}")
        for feature, z in breakdown.items():
            print(f"    {feature}: {z}")

        if score >= 0.5:
            save_anomaly_event(mac, score, breakdown)
            print(f"    ⚠️  Event logged to DB")
        print()