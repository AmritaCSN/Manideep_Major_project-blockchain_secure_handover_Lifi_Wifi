"""
dashboard.py
============
Live web dashboard for LiFi-WiFi Blockchain Handover Prototype.
Runs as Flask app on port 5000.

Access from any device on the same network:
  http://<raspberry-pi-ip>:5000

Shows:
  - Live handover log (auto-refreshes every 3s)
  - Blockchain statistics (TX, blocks, energy saving)
  - AP trust registry
  - Attack controls (trigger any of 9 attacks from browser)
"""

import requests
from flask import Flask, request, jsonify, render_template_string

app  = Flask(__name__)
HOST = "0.0.0.0"   # accessible from any device on network
PORT = 5000

BC_URL   = "http://127.0.0.1:5001"
LIFI_URL = "http://127.0.0.1:5002"
WIFI_URL = "http://127.0.0.1:5003"
UE_URL   = "http://127.0.0.1:5004"

# In-memory event log (last 100 events)
events = []


HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>LiFi-WiFi Blockchain Handover — Dashboard</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', Arial, sans-serif; background: #0f1117; color: #e0e0e0; }
  .header { background: #1a1f2e; padding: 18px 24px; border-bottom: 2px solid #1D9E75; }
  .header h1 { font-size: 1.3rem; color: #1D9E75; }
  .header p  { font-size: 0.8rem; color: #888; margin-top: 4px; }
  .container { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; padding: 16px; }
  .card { background: #1a1f2e; border-radius: 10px; padding: 16px; border: 1px solid #2a2f3e; }
  .card h2 { font-size: 0.9rem; color: #888; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 12px; }
  .stats-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; }
  .stat { background: #0f1117; border-radius: 8px; padding: 12px; text-align: center; }
  .stat .val { font-size: 1.8rem; font-weight: 700; color: #1D9E75; }
  .stat .lbl { font-size: 0.75rem; color: #888; margin-top: 4px; }
  .stat.warn .val { color: #EF9F27; }
  .stat.danger .val { color: #E24B4A; }
  .log-table { width: 100%; border-collapse: collapse; font-size: 0.78rem; }
  .log-table th { background: #0f1117; color: #888; padding: 6px 8px; text-align: left; }
  .log-table td { padding: 5px 8px; border-bottom: 1px solid #2a2f3e; }
  .log-table tr:hover td { background: #252a3a; }
  .badge { padding: 2px 8px; border-radius: 4px; font-size: 0.7rem; font-weight: 600; }
  .badge.approved { background: #0d3322; color: #1D9E75; }
  .badge.denied   { background: #3a1515; color: #E24B4A; }
  .badge.mitm     { background: #3a2a00; color: #EF9F27; }
  .attack-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 8px; }
  .atk-btn { padding: 8px 6px; border: 1px solid #2a2f3e; border-radius: 6px;
             background: #0f1117; color: #e0e0e0; cursor: pointer; font-size: 0.75rem;
             text-align: center; transition: all 0.2s; }
  .atk-btn:hover { border-color: #EF9F27; color: #EF9F27; }
  .atk-btn.running { border-color: #1D9E75; color: #1D9E75; }
  .registry-table { width: 100%; border-collapse: collapse; font-size: 0.78rem; }
  .registry-table th { background: #0f1117; color: #888; padding: 6px 8px; text-align: left; }
  .registry-table td { padding: 5px 8px; border-bottom: 1px solid #2a2f3e; }
  .trust-bar { height: 6px; border-radius: 3px; background: #2a2f3e; width: 100px; display: inline-block; }
  .trust-fill { height: 6px; border-radius: 3px; }
  .signal-card { grid-column: 1 / -1; }
  .signal-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
  .signal-box { background: #0f1117; border-radius: 8px; padding: 14px; }
  .signal-box h3 { font-size: 0.8rem; color: #888; margin-bottom: 8px; }
  .signal-val { font-size: 1.4rem; font-weight: 700; }
  .lifi-color { color: #EF9F27; }
  .wifi-color { color: #378ADD; }
  .full-row { grid-column: 1 / -1; }
  #status-bar { background: #1D9E75; color: white; padding: 6px 24px; font-size: 0.75rem; }
</style>
</head>
<body>

<div class="header">
  <h1>LiFi-WiFi Blockchain Handover — Live Dashboard</h1>
  <p>Raspberry Pi 4 · Stage 1 Prototype · Garrepelly Manideep · Amrita Vishwa Vidyapeetham</p>
</div>
<div id="status-bar">System initialising...</div>

<div class="container">

  <!-- Stats -->
  <div class="card full-row">
    <h2>Blockchain statistics</h2>
    <div class="stats-grid" id="stats-grid">
      <div class="stat"><div class="val" id="s-tx">—</div><div class="lbl">Total TX</div></div>
      <div class="stat"><div class="val" id="s-approved">—</div><div class="lbl">Approved</div></div>
      <div class="stat danger"><div class="val" id="s-denied">—</div><div class="lbl">Denied</div></div>
      <div class="stat"><div class="val" id="s-blocks">—</div><div class="lbl">Block height</div></div>
      <div class="stat warn"><div class="val" id="s-latency">—</div><div class="lbl">Avg latency (ms)</div></div>
      <div class="stat"><div class="val" id="s-saving">—</div><div class="lbl">Energy saved (%)</div></div>
    </div>
  </div>

  <!-- Signal status -->
  <div class="card signal-card">
    <h2>Radio signal status</h2>
    <div class="signal-grid">
      <div class="signal-box">
        <h3>LiFi AP</h3>
        <div class="signal-val lifi-color" id="lifi-rssi">— dBm</div>
        <div style="font-size:0.75rem; color:#888; margin-top:6px">
          Error rate: <span id="lifi-error">—</span> &nbsp;|&nbsp;
          Stage: <span id="lifi-stage">—</span> &nbsp;|&nbsp;
          <span id="lifi-blocked" style="color:#E24B4A"></span>
        </div>
      </div>
      <div class="signal-box">
        <h3>WiFi AP</h3>
        <div class="signal-val wifi-color" id="wifi-rssi">— dBm</div>
        <div style="font-size:0.75rem; color:#888; margin-top:6px">
          Status: <span id="wifi-status">—</span>
        </div>
      </div>
    </div>
  </div>

  <!-- AP Registry -->
  <div class="card">
    <h2>AP trust registry</h2>
    <table class="registry-table">
      <thead><tr><th>AP ID</th><th>Org</th><th>Trust</th><th>Status</th><th>Approved</th><th>Rejected</th></tr></thead>
      <tbody id="registry-body"></tbody>
    </table>
  </div>

  <!-- Attack controls -->
  <div class="card">
    <h2>Attack simulation controls</h2>
    <div class="attack-grid">
      <button class="atk-btn" onclick="triggerAttack(1)">A1: LiFi Blockage</button>
      <button class="atk-btn" onclick="triggerAttack(2)">A2: Rogue AP</button>
      <button class="atk-btn" onclick="triggerAttack(3)">A3: MITM</button>
      <button class="atk-btn" onclick="triggerAttack(4)">A4: Downgrade</button>
      <button class="atk-btn" onclick="triggerAttack(5)">A5: Replay</button>
      <button class="atk-btn" onclick="triggerAttack(6)">A6: Sybil</button>
      <button class="atk-btn" onclick="triggerAttack(7)">A7: DoS-BC</button>
      <button class="atk-btn" onclick="triggerAttack(8)">A8: Byzantine</button>
      <button class="atk-btn" onclick="triggerAttack(9)">A9: Session Hijack</button>
    </div>
    <button class="atk-btn" style="width:100%;margin-top:10px;border-color:#E24B4A;color:#E24B4A"
            onclick="triggerDemo()">▶ Run Full Demo (all 9 attacks)</button>
  </div>

  <!-- Handover log -->
  <div class="card full-row">
    <h2>Live handover log <span style="font-size:0.7rem; color:#555">(auto-refresh 3s)</span></h2>
    <div style="overflow-x:auto">
    <table class="log-table">
      <thead>
        <tr>
          <th>Time</th><th>Source AP</th><th>Target AP</th>
          <th>Decision</th><th>Score</th><th>Latency (ms)</th><th>Attack</th>
        </tr>
      </thead>
      <tbody id="log-body"></tbody>
    </table>
    </div>
  </div>

</div>

<script>
function fmt(v, dec=2) { return v != null ? parseFloat(v).toFixed(dec) : '—'; }

async function refreshStats() {
  try {
    const r = await fetch('/api/stats');
    const d = await r.json();
    document.getElementById('s-tx').textContent       = d.total_tx       || 0;
    document.getElementById('s-approved').textContent = d.approved        || 0;
    document.getElementById('s-denied').textContent   = d.denied          || 0;
    document.getElementById('s-blocks').textContent   = d.block_height    || 1;
    document.getElementById('s-latency').textContent  = fmt(d.avg_latency_ms, 1);
    document.getElementById('s-saving').textContent   = fmt(d.energy_saving_pct, 1) + '%';
    document.getElementById('status-bar').textContent =
      `Blockchain running · ${d.total_tx} TX processed · Block height ${d.block_height} · Energy saved: ${fmt(d.energy_saving_pct,1)}%`;
  } catch(e) {
    document.getElementById('status-bar').textContent = 'Blockchain node unreachable — is blockchain_node.py running?';
  }
}

async function refreshSignal() {
  try {
    const r = await fetch('/api/signal/lifi');
    const d = await r.json();
    document.getElementById('lifi-rssi').textContent  = fmt(d.rssi_dbm, 1) + ' dBm';
    document.getElementById('lifi-error').textContent = fmt(d.error_rate*100, 1) + '%';
    document.getElementById('lifi-stage').textContent = d.stage || 0;
    document.getElementById('lifi-blocked').textContent = d.blocked ? 'BLOCKED' : '';
  } catch(e) {}

  try {
    const r2 = await fetch('/api/signal/wifi');
    const d2 = await r2.json();
    const ap = d2[0] || {};
    document.getElementById('wifi-rssi').textContent  = fmt(ap.rssi_dbm, 1) + ' dBm';
    document.getElementById('wifi-status').textContent = ap.active ? 'Active' : 'Inactive';
  } catch(e) {}
}

async function refreshRegistry() {
  try {
    const r = await fetch('/api/registry');
    const aps = await r.json();
    const tbody = document.getElementById('registry-body');
    tbody.innerHTML = aps.map(ap => {
      const trust = (ap.trust * 100).toFixed(1);
      const fillColor = ap.trust > 0.8 ? '#1D9E75' : ap.trust > 0.4 ? '#EF9F27' : '#E24B4A';
      return `<tr>
        <td>${ap.ap_id}</td>
        <td>${ap.org}</td>
        <td>
          <span class="trust-bar"><span class="trust-fill" style="width:${trust}%;background:${fillColor};display:block"></span></span>
          ${trust}%
        </td>
        <td>${ap.registered ? '<span style="color:#1D9E75">Registered</span>' : '<span style="color:#E24B4A">Revoked</span>'}</td>
        <td style="color:#1D9E75">${ap.approved}</td>
        <td style="color:#E24B4A">${ap.rejected}</td>
      </tr>`;
    }).join('');
  } catch(e) {}
}

async function refreshLog() {
  try {
    const r = await fetch('/api/log');
    const txs = await r.json();
    const tbody = document.getElementById('log-body');
    tbody.innerHTML = txs.map(tx => {
      const dec = tx.decision;
      const badgeClass = dec === 'APPROVED' ? 'approved' : dec === 'MITM_ACTIVE' ? 'mitm' : 'denied';
      const t = tx.timestamp ? tx.timestamp.substring(11,19) : '—';
      return `<tr>
        <td>${t}</td>
        <td>${tx.source_ap || '—'}</td>
        <td>${tx.target_ap || '—'}</td>
        <td><span class="badge ${badgeClass}">${dec}</span></td>
        <td>${tx.score != null ? parseFloat(tx.score).toFixed(4) : '—'}</td>
        <td>${tx.latency_ms != null ? parseFloat(tx.latency_ms).toFixed(1) : '—'}</td>
        <td style="color:#EF9F27;font-size:0.7rem">${tx.attack_type !== 'none' ? tx.attack_type : ''}</td>
      </tr>`;
    }).join('');
  } catch(e) {}
}

async function triggerAttack(n) {
  const btns = document.querySelectorAll('.atk-btn');
  btns[n-1].classList.add('running');
  btns[n-1].textContent = `Running A${n}...`;
  try {
    await fetch(`/api/attack/${n}`, { method: 'POST' });
  } catch(e) {}
  setTimeout(() => {
    btns[n-1].classList.remove('running');
    btns[n-1].textContent = ['A1: LiFi Blockage','A2: Rogue AP','A3: MITM',
      'A4: Downgrade','A5: Replay','A6: Sybil','A7: DoS-BC',
      'A8: Byzantine','A9: Session Hijack'][n-1];
  }, 5000);
}

async function triggerDemo() {
  await fetch('/api/demo', { method: 'POST' });
}

function refresh() {
  refreshStats();
  refreshSignal();
  refreshRegistry();
  refreshLog();
}
refresh();
setInterval(refresh, 3000);
</script>
</body>
</html>
"""


# ══════════════════════════════════════════════════════════════════════════════
# Dashboard API endpoints (proxy to services)
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/")
def index():
    return render_template_string(HTML)


@app.route("/event", methods=["POST"])
def receive_event():
    """Receive events from UE simulator."""
    events.insert(0, request.get_json())
    if len(events) > 100:
        events.pop()
    return jsonify({"ok": True})


@app.route("/api/stats")
def api_stats():
    try:
        r = requests.get(f"{BC_URL}/stats", timeout=3)
        return jsonify(r.json())
    except Exception as e:
        return jsonify({"error": str(e)}), 503


@app.route("/api/registry")
def api_registry():
    try:
        r = requests.get(f"{BC_URL}/registry", timeout=3)
        return jsonify(r.json())
    except Exception as e:
        return jsonify([])


@app.route("/api/log")
def api_log():
    try:
        r = requests.get(f"{BC_URL}/ledger?limit=30", timeout=3)
        bc_txs = r.json()
    except Exception:
        bc_txs = []
    # Merge with in-memory events (MITM etc. not in ledger)
    merged = events[:10] + bc_txs
    merged.sort(key=lambda x: x.get("timestamp",""), reverse=True)
    return jsonify(merged[:30])


@app.route("/api/signal/lifi")
def api_lifi():
    try:
        r = requests.get(f"{LIFI_URL}/signal", timeout=2)
        return jsonify(r.json())
    except Exception:
        return jsonify({"rssi_dbm": -40, "error_rate": 0, "stage": 0, "blocked": False})


@app.route("/api/signal/wifi")
def api_wifi():
    try:
        r = requests.get(f"{WIFI_URL}/all", timeout=2)
        return jsonify(r.json())
    except Exception:
        return jsonify([])


@app.route("/api/attack/<int:n>", methods=["POST"])
def api_attack(n):
    """Trigger attack via UE simulator."""
    import subprocess
    subprocess.Popen(
        ["python3", "ue_simulator.py", "--attack", str(n)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    return jsonify({"status": f"attack_{n}_started"})


@app.route("/api/demo", methods=["POST"])
def api_demo():
    import subprocess
    subprocess.Popen(
        ["python3", "ue_simulator.py", "--demo"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    return jsonify({"status": "demo_started"})


if __name__ == "__main__":
    print(f"\n[DASH] Dashboard running on http://{HOST}:{PORT}")
    print(f"[DASH] Open from any device: http://<your-pi-ip>:{PORT}\n")
    app.run(host=HOST, port=PORT, debug=False, threaded=True)
