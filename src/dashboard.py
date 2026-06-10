from flask import Flask, render_template_string, jsonify
import sqlite3
import time

app = Flask(__name__)
DB_PATH = '/home/devinlinux/sdztg-gateway/data/packets.db'

# ─── DB HELPERS ───────────────────────────────────────────────────────
def query_db(sql, args=()):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute(sql, args)
    rows = c.fetchall()
    conn.close()
    return [dict(r) for r in rows]

# ─── ROUTES ───────────────────────────────────────────────────────────
@app.route('/')
def index():
    return render_template_string(HTML)

@app.route('/api/devices')
def devices():
    rows = query_db('''
        SELECT
            mac_src as mac,
            ip_dst as last_ip,
            MAX(ts) as last_seen,
            COUNT(*) as pkt_count
        FROM packets
        GROUP BY mac_src
        ORDER BY last_seen DESC
    ''')
    # Attach latest anomaly score
    for row in rows:
        scores = query_db('''
            SELECT score FROM anomaly_events
            WHERE mac = ?
            ORDER BY ts DESC LIMIT 1
        ''', (row['mac'],))
        row['score'] = scores[0]['score'] if scores else 0.0
        row['last_seen'] = time.strftime('%H:%M:%S',
                           time.localtime(row['last_seen']))
    return jsonify(rows)

@app.route('/api/alerts')
def alerts():
    rows = query_db('''
        SELECT ts, mac, score, pkt_rate_z, byte_rate_z,
               dst_ip_z, dst_port_z
        FROM anomaly_events
        ORDER BY ts DESC LIMIT 20
    ''')
    for row in rows:
        row['ts'] = time.strftime('%H:%M:%S', time.localtime(row['ts']))
        row['score'] = round(row['score'], 3)
    return jsonify(rows)

@app.route('/api/dns_alerts')
def dns_alerts():
    rows = query_db('''
        SELECT ts, mac_src, query, entropy, label_len, alert
        FROM dns_events
        ORDER BY ts DESC LIMIT 20
    ''')
    for row in rows:
        row['ts'] = time.strftime('%H:%M:%S', time.localtime(row['ts']))
    return jsonify(rows)

@app.route('/api/traffic')
def traffic():
    rows = query_db('''
        SELECT ts, mac_src, ip_dst, protocol, size
        FROM packets
        ORDER BY ts DESC LIMIT 50
    ''')
    for row in rows:
        row['ts'] = time.strftime('%H:%M:%S', time.localtime(row['ts']))
    return jsonify(rows)

# ─── HTML TEMPLATE ────────────────────────────────────────────────────
HTML = '''
<!DOCTYPE html>
<html>
<head>
    <title>SDZTG Dashboard</title>
    <meta http-equiv="refresh" content="5">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            background: #0a0c10;
            color: #c9d1d9;
            font-family: 'JetBrains Mono', monospace;
            padding: 24px;
        }
        h1 {
            font-size: 18px;
            color: #00FF9C;
            border-left: 3px solid #00FF9C;
            padding-left: 12px;
            margin-bottom: 6px;
        }
        .subtitle {
            font-size: 10px;
            color: #555;
            margin-bottom: 24px;
            padding-left: 15px;
        }
        .grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 16px;
            margin-bottom: 16px;
        }
        .card {
            background: #0d1117;
            border: 1px solid #1e2530;
            border-radius: 8px;
            padding: 16px;
        }
        .card h2 {
            font-size: 10px;
            letter-spacing: 2px;
            color: #555;
            margin-bottom: 12px;
            text-transform: uppercase;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 11px;
        }
        th {
            text-align: left;
            color: #555;
            font-size: 9px;
            padding: 4px 8px;
            border-bottom: 1px solid #1e2530;
        }
        td {
            padding: 6px 8px;
            border-bottom: 1px solid #0d1117;
        }
        .score-high { color: #ff5555; font-weight: bold; }
        .score-med  { color: #FFAB40; font-weight: bold; }
        .score-low  { color: #00FF9C; }
        .alert-row td { background: #ff555511; }
        .dns-row td   { background: #ff555522; }
        .tag {
            font-size: 8px;
            padding: 1px 6px;
            border-radius: 8px;
            background: #ff555522;
            color: #ff5555;
            border: 1px solid #ff555544;
        }
    </style>
</head>
<body>
    <h1>SDZTG — Zero Trust Gateway</h1>
    <div class="subtitle">Auto-refreshes every 5 seconds</div>

    <div class="grid">
        <div class="card">
            <h2>Connected Devices</h2>
            <table id="devices">
                <tr>
                    <th>MAC</th><th>LAST IP</th>
                    <th>PACKETS</th><th>SCORE</th>
                </tr>
            </table>
        </div>
        <div class="card">
            <h2>Anomaly Alerts</h2>
            <table id="alerts">
                <tr>
                    <th>TIME</th><th>MAC</th>
                    <th>SCORE</th><th>TOP FEATURE</th>
                </tr>
            </table>
        </div>
    </div>

    <div class="card" style="margin-bottom:16px">
        <h2>DNS Exfiltration Alerts</h2>
        <table id="dns">
            <tr>
                <th>TIME</th><th>MAC</th>
                <th>QUERY</th><th>ALERT</th>
            </tr>
        </table>
    </div>

    <div class="card">
        <h2>Live Traffic Feed</h2>
        <table id="traffic">
            <tr>
                <th>TIME</th><th>MAC</th>
                <th>DESTINATION</th><th>PROTO</th><th>SIZE</th>
            </tr>
        </table>
    </div>

<script>
function scoreClass(s) {
    if (s >= 0.7) return 'score-high';
    if (s >= 0.3) return 'score-med';
    return 'score-low';
}

function topFeature(row) {
    const f = ['pkt_rate_z','byte_rate_z','dst_ip_z','dst_port_z'];
    const labels = ['pkt_rate','byte_rate','dst_ip','dst_port'];
    let max = 0, label = '-';
    f.forEach((k,i) => { if (row[k] > max) { max = row[k]; label = labels[i]; }});
    return label;
}

async function loadDevices() {
    const data = await fetch('/api/devices').then(r => r.json());
    const t = document.getElementById('devices');
    while (t.rows.length > 1) t.deleteRow(1);
    data.forEach(d => {
        const sc = parseFloat(d.score);
        const tr = t.insertRow();
        tr.innerHTML = `
            <td>${d.mac}</td>
            <td>${d.last_ip}</td>
            <td>${d.pkt_count}</td>
            <td class="${scoreClass(sc)}">${sc.toFixed(3)}</td>`;
    });
}

async function loadAlerts() {
    const data = await fetch('/api/alerts').then(r => r.json());
    const t = document.getElementById('alerts');
    while (t.rows.length > 1) t.deleteRow(1);
    data.forEach(a => {
        const tr = t.insertRow();
        tr.className = 'alert-row';
        tr.innerHTML = `
            <td>${a.ts}</td>
            <td>${a.mac}</td>
            <td class="score-high">${a.score}</td>
            <td>${topFeature(a)}</td>`;
    });
}

async function loadDNS() {
    const data = await fetch('/api/dns_alerts').then(r => r.json());
    const t = document.getElementById('dns');
    while (t.rows.length > 1) t.deleteRow(1);
    data.forEach(d => {
        const tr = t.insertRow();
        tr.className = 'dns-row';
        tr.innerHTML = `
            <td>${d.ts}</td>
            <td>${d.mac_src}</td>
            <td style="font-size:9px">${d.query.substring(0,50)}...</td>
            <td><span class="tag">${d.alert.split('|')[0]}</span></td>`;
    });
}

async function loadTraffic() {
    const data = await fetch('/api/traffic').then(r => r.json());
    const t = document.getElementById('traffic');
    while (t.rows.length > 1) t.deleteRow(1);
    data.forEach(p => {
        const tr = t.insertRow();
        tr.innerHTML = `
            <td>${p.ts}</td>
            <td>${p.mac_src}</td>
            <td>${p.ip_dst}</td>
            <td>${p.protocol}</td>
            <td>${p.size}B</td>`;
    });
}

function refresh() {
    loadDevices();
    loadAlerts();
    loadDNS();
    loadTraffic();
}

refresh();
setInterval(refresh, 5000);
</script>
</body>
</html>
'''

# ─── MAIN ─────────────────────────────────────────────────────────────
if __name__ == '__main__':
    print("[*] SDZTG Dashboard running at http://0.0.0.0:5000")
    app.run(host='0.0.0.0', port=5000, debug=False)