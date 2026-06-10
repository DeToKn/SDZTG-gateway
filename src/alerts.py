time.sleep(1)import os
import requests
import sqlite3
import time
from dotenv import load_dotenv

# Load .env from project root
load_dotenv('/home/devinlinux/sdztg-gateway/.env')

TELEGRAM_TOKEN   = os.getenv('TELEGRAM_TOKEN')
TELEGRAM_CHAT_ID = os.getenv('TELEGRAM_CHAT_ID')
WEBHOOK_URL      = os.getenv('WEBHOOK_URL', None)

DB_PATH = '/home/devinlinux/sdztg-gateway/data/packets.db'

# ─── TELEGRAM ─────────────────────────────────────────────────────────
def send_telegram(message):
    """Send a message to your Telegram bot."""
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        print("[ALERT] Telegram not configured — check .env")
        return False
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
        payload = {
            'chat_id': TELEGRAM_CHAT_ID,
            'text': message,
            'parse_mode': 'Markdown'
        }
        r = requests.post(url, json=payload, timeout=5)
        if r.status_code == 200:
            print(f"[TELEGRAM] Sent: {message[:60]}...")
            return True
        else:
            print(f"[TELEGRAM] Failed: {r.status_code} {r.text}")
            return False
    except Exception as e:
        print(f"[TELEGRAM] Error: {e}")
        return False

# ─── WEBHOOK ──────────────────────────────────────────────────────────
def send_webhook(payload):
    """POST alert payload to a webhook URL if configured."""
    if not WEBHOOK_URL:
        return
    try:
        requests.post(WEBHOOK_URL, json=payload, timeout=5)
        print(f"[WEBHOOK] Sent to {WEBHOOK_URL}")
    except Exception as e:
        print(f"[WEBHOOK] Error: {e}")

# ─── ALERT FORMATTERS ─────────────────────────────────────────────────
def format_anomaly_alert(mac, score, breakdown):
    top_feature = max(breakdown, key=breakdown.get) if breakdown else 'unknown'
    return (
        f"🚨 *ANOMALY DETECTED*\n"
        f"Device: `{mac}`\n"
        f"Score: `{score:.3f}`\n"
        f"Top feature: `{top_feature}`\n"
        f"Time: `{time.strftime('%H:%M:%S')}`"
    )

def format_dns_alert(mac, query, entropy, alert_type):
    return (
        f"🔴 *DNS EXFILTRATION ALERT*\n"
        f"Device: `{mac}`\n"
        f"Query: `{query[:50]}...`\n"
        f"Entropy: `{entropy:.3f}`\n"
        f"Alert: `{alert_type}`\n"
        f"Time: `{time.strftime('%H:%M:%S')}`"
    )

# ─── ALERT DISPATCHER ─────────────────────────────────────────────────
def dispatch_anomaly_alert(mac, score, breakdown):
    """Send anomaly alert via Telegram + webhook."""
    message = format_anomaly_alert(mac, score, breakdown)
    send_telegram(message)
    send_webhook({
        'type': 'anomaly',
        'mac': mac,
        'score': score,
        'breakdown': breakdown,
        'ts': time.time()
    })

def dispatch_dns_alert(mac, query, entropy, alert_type):
    """Send DNS exfiltration alert via Telegram + webhook."""
    message = format_dns_alert(mac, query, entropy, alert_type)
    send_telegram(message)
    send_webhook({
        'type': 'dns_exfiltration',
        'mac': mac,
        'query': query,
        'entropy': entropy,
        'alert': alert_type,
        'ts': time.time()
    })

# ─── MONITOR LOOP ─────────────────────────────────────────────────────
def monitor(interval=10, anomaly_threshold=0.5):
    """
    Continuously monitor the database for new anomaly and DNS events
    and fire alerts when thresholds are crossed.
    """
    print(f"[*] Alert monitor running (interval={interval}s, threshold={anomaly_threshold})")
    last_anomaly_id = 0
    last_dns_id = 0

    # Start from current latest
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT MAX(id) FROM anomaly_events')
        row = c.fetchone()
        last_anomaly_id = row[0] or 0
        c.execute('SELECT MAX(id) FROM dns_events')
        row = c.fetchone()
        last_dns_id = row[0] or 0
        conn.close()
    except:
        pass

    print(f"[*] Starting from anomaly_id={last_anomaly_id}, dns_id={last_dns_id}")

    while True:
        try:
            conn = sqlite3.connect(DB_PATH, timeout=5)
            c = conn.cursor()

            # Check new anomaly events
            c.execute('''
                SELECT id, mac, score, pkt_rate_z, byte_rate_z, dst_ip_z, dst_port_z
                FROM anomaly_events
                WHERE id > ? AND score >= ?
                ORDER BY id ASC
            ''', (last_anomaly_id, anomaly_threshold))
            anomalies = c.fetchall()
            for row in anomalies:
                last_anomaly_id = row[0]
                mac = row[1]
                score = row[2]
                breakdown = {
                    'pkt_rate': row[3],
                    'byte_rate': row[4],
                    'dst_ip': row[5],
                    'dst_port': row[6]
                }
                dispatch_anomaly_alert(mac, score, breakdown)

            # Check new DNS events
            c.execute('''
                SELECT id, mac_src, query, entropy, alert
                FROM dns_events WHERE id > ?
                ORDER BY id ASC
            ''', (last_dns_id,))
            dns_events = c.fetchall()
            for row in dns_events:
                last_dns_id = row[0]
                dispatch_dns_alert(row[1], row[2], row[3], row[4])

            conn.close()

        except Exception as e:
            print(f"[MONITOR ERROR] {e}")

        time.sleep(interval)

# ─── MAIN ─────────────────────────────────────────────────────────────
if __name__ == '__main__':
    print("[*] Testing Telegram connection...")
    send_telegram("🟢 *SDZTG Gateway Online*\nAlert monitor connected and watching.")
    monitor(interval=10, anomaly_threshold=0.5)