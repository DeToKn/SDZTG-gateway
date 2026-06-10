from flask import Flask, render_template_string
from flask_socketio import SocketIO
import sqlite3
import time
import threading

app = Flask(__name__)
app.config['SECRET_KEY'] = 'sdztg-secret'
socketio = SocketIO(app, async_mode='eventlet', cors_allowed_origins='*')

DB_PATH = '/home/devinlinux/sdztg-gateway/data/packets.db'

# ─── DB HELPER ────────────────────────────────────────────────────────
def query_db(sql, args=()):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute(sql, args)
    rows = c.fetchall()
    conn.close()
    return [dict(r) for r in rows]

# ─── BACKGROUND PUSHER ────────────────────────────────────────────────
last_packet_id = 0
last_anomaly_id = 0
last_dns_id = 0

def push_updates():
    global last_packet_id, last_anomaly_id, last_dns_id

    while True:
        try:
            # New packets
            new_packets = query_db('''
                SELECT id, ts, mac_src, ip_dst, protocol, size
                FROM packets WHERE id > ?
                ORDER BY id ASC LIMIT 20
            ''', (last_packet_id,))
            if new_packets:
                last_packet_id = new_packets[-1]['id']
                for p in new_packets:
                    p['ts'] = time.strftime('%H:%M:%S', time.localtime(p['ts']))
                socketio.emit('new_packets', new_packets)

            # New anomaly events
            new_anomalies = query_db('''
                SELECT id, ts, mac, score,
                       pkt_rate_z, byte_rate_z, dst_ip_z, dst_port_z
                FROM anomaly_events WHERE id > ?
                ORDER BY id ASC
            ''', (last_anomaly_id,))
            if new_anomalies:
                last_anomaly_id = new_anomalies[-1]['id']
                for a in new_anomalies:
                    a['ts'] = time.strftime('%H:%M:%S', time.localtime(a['ts']))
                    a['score'] = round(a['score'], 3)
                socketio.emit('new_anomalies', new_anomalies)

            # New DNS alerts
            new_dns = query_db('''
                SELECT id, ts, mac_src, query, entropy, label_len, alert
                FROM dns_events WHERE id > ?
                ORDER BY id ASC
            ''', (last_dns_id,))
            if new_dns:
                last_dns_id = new_dns[-1]['id']
                for d in new_dns:
                    d['ts'] = time.strftime('%H:%M:%S', time.localtime(d['ts']))
                socketio.emit('new_dns', new_dns)

            # Device summary — push every 2 seconds
            devices = query_db('''
                SELECT mac_src as mac, ip_dst as last_ip,
                       MAX(ts) as last_seen, COUNT(*) as pkt_count
                FROM packets GROUP BY mac_src
                ORDER BY last_seen DESC
            ''')
            for d in devices:
                scores = query_db('''
                    SELECT score FROM anomaly_events
                    WHERE mac = ? ORDER BY ts DESC LIMIT 1
                ''', (d['mac'],))
                d['score'] = round(scores[0]['score'], 3) if scores else 0.0
                d['last_seen'] = time.strftime('%H:%M:%S',
                                 time.localtime(d['last_seen']))
            socketio.emit('devices', devices)

        except Exception as e:
            print(f'[PUSH ERROR] {e}')

        time.sleep(1)

# ─── ROUTES ───────────────────────────────────────────────────────────
@app.route('/')
def index():
    return render_template_string(HTML)

@socketio.on('connect')
def on_connect():
    print('[WS] Client connected')
    # Send initial data on connect
    packets = query_db('''
        SELECT id, ts, mac_src, ip_dst, protocol, size
        FROM packets ORDER BY id DESC LIMIT 30
    ''')
    for p in packets:
        p['ts'] = time.strftime('%H:%M:%S', time.localtime(p['ts']))
    socketio.emit('new_packets', list(reversed(packets)))

    anomalies = query_db('''
        SELECT id, ts, mac, score,
               pkt_rate_z, byte_rate_z, dst_ip_z, dst_port_z
        FROM anomaly_events ORDER BY ts DESC LIMIT 20
    ''')
    for a in anomalies:
        a['ts'] = time.strftime('%H:%M:%S', time.localtime(a['ts']))
        a['score'] = round(a['score'], 3)
    socketio.emit('new_anomalies', list(reversed(anomalies)))

    dns = query_db('''
        SELECT id, ts, mac_src, query, entropy, label_len, alert
        FROM dns_events ORDER BY ts DESC LIMIT 20
    ''')
    for d in dns:
        d['ts'] = time.strftime('%H:%M:%S', time.localtime(d['ts']))
    socketio.emit('new_dns', list(reversed(dns)))

# ─── HTML ─────────────────────────────────────────────────────────────
HTML = '''
<!DOCTYPE html>
<html>
<head>
    <title>SDZTG — Zero Trust Gateway</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.7.2/socket.io.min.js"></script>
    <style>
        * { margin:0; padding:0; box-sizing:border-box; }
        body {
            background:#0a0c10;
            color:#c9d1d9;
            font-family:'JetBrains Mono',monospace;
            padding:20px;
            font-size:12px;
        }
        header {
            border-left:3px solid #00FF9C;
            padding-left:12px;
            margin-bottom:20px;
        }
        header h1 { font-size:18px; color:#00FF9C; }
        header p  { font-size:10px; color:#555; margin-top:3px; }
        .live-dot {
            display:inline-block;
            width:7px; height:7px;
            background:#00FF9C;
            border-radius:50%;
            margin-right:6px;
            animation: pulse 1s infinite;
        }
        @keyframes pulse {
            0%,100% { opacity:1; }
            50%      { opacity:0.3; }
        }
        .grid {
            display:grid;
            grid-template-columns:1fr 1fr;
            gap:14px;
            margin-bottom:14px;
        }
        .card {
            background:#0d1117;
            border:1px solid #1e2530;
            border-radius:8px;
            overflow:hidden;
        }
        .card.full { grid-column: span 2; }
        .card-header {
            padding:10px 14px;
            border-bottom:1px solid #1e2530;
            font-size:9px;
            letter-spacing:2px;
            color:#555;
            text-transform:uppercase;
            display:flex;
            align-items:center;
            justify-content:space-between;
        }
        .card-header .count {
            font-size:9px;
            padding:1px 7px;
            border-radius:8px;
            background:#ffffff11;
            color:#8b949e;
        }
        .scroll-table {
            max-height:220px;
            overflow-y:auto;
        }
        table { width:100%; border-collapse:collapse; }
        th {
            text-align:left;
            padding:6px 14px;
            font-size:9px;
            color:#3d5a7a;
            border-bottom:1px solid #1e2530;
            position:sticky;
            top:0;
            background:#0d1117;
        }
        td { padding:5px 14px; border-bottom:1px solid #0a0c10; font-size:11px; }
        tr:hover td { background:#ffffff06; }
        .new-row td { animation: flash 0.6s ease; }
        @keyframes flash {
            0%   { background:#00FF9C22; }
            100% { background:transparent; }
        }
        .score-high { color:#ff5555; font-weight:700; }
        .score-med  { color:#FFAB40; font-weight:700; }
        .score-low  { color:#00FF9C; }
        .tag {
            font-size:8px;
            padding:1px 6px;
            border-radius:8px;
        }
        .tag-dns  { background:#ff555522; color:#ff5555; border:1px solid #ff555444; }
        .tag-tcp  { background:#4FC3F722; color:#4FC3F7; border:1px solid #4FC3F744; }
        .tag-udp  { background:#CE93D822; color:#CE93D8; border:1px solid #CE93D844; }
        .tag-other{ background:#ffffff11; color:#8b949e; border:1px solid #333; }
        #status {
            font-size:9px;
            color:#555;
            margin-bottom:14px;
            display:flex;
            gap:16px;
        }
        #status span { color:#00FF9C; }
    </style>
</head>
<body>

<header>
    <h1><span class="live-dot"></span>SDZTG — Zero Trust Gateway</h1>
    <p>Software-Defined Zero-Trust Gateway · Real-time monitoring</p>
</header>

<div id="status">
    <div>Packets: <span id="pkt-count">0</span></div>
    <div>Devices: <span id="dev-count">0</span></div>
    <div>Anomaly Alerts: <span id="alert-count">0</span></div>
    <div>DNS Alerts: <span id="dns-count">0</span></div>
    <div>Connection: <span id="conn-status">connecting...</span></div>
</div>

<div class="grid">
    <!-- Devices -->
    <div class="card">
        <div class="card-header">
            Connected Devices
            <span class="count" id="d-count">0</span>
        </div>
        <div class="scroll-table">
            <table>
                <thead><tr>
                    <th>MAC</th><th>LAST IP</th>
                    <th>PACKETS</th><th>SCORE</th>
                </tr></thead>
                <tbody id="devices-body"></tbody>
            </table>
        </div>
    </div>

    <!-- Anomaly Alerts -->
    <div class="card">
        <div class="card-header">
            Anomaly Alerts
            <span class="count" id="a-count">0</span>
        </div>
        <div class="scroll-table">
            <table>
                <thead><tr>
                    <th>TIME</th><th>MAC</th>
                    <th>SCORE</th><th>TOP FEATURE</th>
                </tr></thead>
                <tbody id="anomaly-body"></tbody>
            </table>
        </div>
    </div>

    <!-- DNS Alerts -->
    <div class="card full">
        <div class="card-header">
            DNS Exfiltration Alerts
            <span class="count" id="dns-c">0</span>
        </div>
        <div class="scroll-table">
            <table>
                <thead><tr>
                    <th>TIME</th><th>MAC</th>
                    <th>QUERY</th><th>ENTROPY</th><th>ALERT</th>
                </tr></thead>
                <tbody id="dns-body"></tbody>
            </table>
        </div>
    </div>

    <!-- Live Traffic -->
    <div class="card full">
        <div class="card-header">
            Live Traffic Feed
            <span class="count" id="t-count">0</span>
        </div>
        <div class="scroll-table">
            <table>
                <thead><tr>
                    <th>TIME</th><th>MAC</th>
                    <th>DESTINATION</th><th>PROTO</th><th>SIZE</th>
                </tr></thead>
                <tbody id="traffic-body"></tbody>
            </table>
        </div>
    </div>
</div>

<script>
const socket = io();
let pktCount = 0, alertCount = 0, dnsCount = 0;
const MAX_ROWS = 100;

function scoreClass(s) {
    if (s >= 0.7) return 'score-high';
    if (s >= 0.3) return 'score-med';
    return 'score-low';
}

function topFeature(a) {
    const f = ['pkt_rate_z','byte_rate_z','dst_ip_z','dst_port_z'];
    const l = ['pkt_rate','byte_rate','dst_ip','dst_port'];
    let max = 0, label = '-';
    f.forEach((k,i) => { if ((a[k]||0) > max) { max = a[k]; label = l[i]; }});
    return label;
}

function protoTag(p) {
    const cls = p === 'TCP' ? 'tag-tcp' : p === 'UDP' ? 'tag-udp' : 'tag-other';
    return `<span class="tag ${cls}">${p}</span>`;
}

function addRow(tbodyId, html, prepend=true) {
    const tb = document.getElementById(tbodyId);
    const tr = document.createElement('tr');
    tr.className = 'new-row';
    tr.innerHTML = html;
    if (prepend) tb.insertBefore(tr, tb.firstChild);
    else tb.appendChild(tr);
    // Trim old rows
    while (tb.rows.length > MAX_ROWS) tb.deleteRow(tb.rows.length - 1);
}

socket.on('connect', () => {
    document.getElementById('conn-status').textContent = 'live';
    document.getElementById('conn-status').style.color = '#00FF9C';
});

socket.on('disconnect', () => {
    document.getElementById('conn-status').textContent = 'disconnected';
    document.getElementById('conn-status').style.color = '#ff5555';
});

socket.on('new_packets', (packets) => {
    packets.forEach(p => {
        pktCount++;
        addRow('traffic-body', `
            <td>${p.ts}</td>
            <td>${p.mac_src}</td>
            <td>${p.ip_dst}</td>
            <td>${protoTag(p.protocol)}</td>
            <td>${p.size}B</td>
        `);
    });
    document.getElementById('pkt-count').textContent = pktCount;
    document.getElementById('t-count').textContent =
        document.getElementById('traffic-body').rows.length;
});

socket.on('new_anomalies', (alerts) => {
    alerts.forEach(a => {
        alertCount++;
        const sc = parseFloat(a.score);
        addRow('anomaly-body', `
            <td>${a.ts}</td>
            <td>${a.mac}</td>
            <td class="${scoreClass(sc)}">${a.score}</td>
            <td>${topFeature(a)}</td>
        `);
    });
    document.getElementById('alert-count').textContent = alertCount;
    document.getElementById('a-count').textContent =
        document.getElementById('anomaly-body').rows.length;
});

socket.on('new_dns', (events) => {
    events.forEach(d => {
        dnsCount++;
        addRow('dns-body', `
            <td>${d.ts}</td>
            <td>${d.mac_src}</td>
            <td style="font-size:10px;max-width:300px;overflow:hidden;
                text-overflow:ellipsis;white-space:nowrap">
                ${d.query.substring(0,60)}...</td>
            <td>${parseFloat(d.entropy).toFixed(3)}</td>
            <td><span class="tag tag-dns">${d.alert.split('|')[0].trim()}</span></td>
        `);
    });
    document.getElementById('dns-count').textContent = dnsCount;
    document.getElementById('dns-c').textContent =
        document.getElementById('dns-body').rows.length;
});

socket.on('devices', (devs) => {
    const tb = document.getElementById('devices-body');
    tb.innerHTML = '';
    devs.forEach(d => {
        const sc = parseFloat(d.score);
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>${d.mac}</td>
            <td>${d.last_ip}</td>
            <td>${d.pkt_count}</td>
            <td class="${scoreClass(sc)}">${sc.toFixed(3)}</td>
        `;
        tb.appendChild(tr);
    });
    document.getElementById('dev-count').textContent = devs.length;
    document.getElementById('d-count').textContent = devs.length;
});
</script>
</body>
</html>
'''

# ─── MAIN ─────────────────────────────────────────────────────────────
if __name__ == '__main__':
    t = threading.Thread(target=push_updates, daemon=True)
    t.start()
    print('[*] SDZTG Dashboard running at http://0.0.0.0:5000')
    socketio.run(app, host='0.0.0.0', port=5000)