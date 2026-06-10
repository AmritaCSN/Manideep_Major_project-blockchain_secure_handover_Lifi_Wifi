"""
wifi_ap.py
==========
WiFi Access Point emulator for Raspberry Pi prototype.
Runs as Flask REST API on port 5003.

Simulates:
  - WiFi signal quality reporting
  - Connection state management
  - Rogue AP injection (for attack simulation)
"""

import time
import random
import threading
from flask import Flask, request, jsonify

app  = Flask(__name__)
HOST = "127.0.0.1"
PORT = 5003

# ── AP registry for this emulator ─────────────────────────────────────────────
lock = threading.Lock()
aps  = {
    "LegitWiFiAP": {
        "ap_id":     "LegitWiFiAP",
        "org":       "Org2",
        "rssi_dbm":  -62.0,
        "active":    True,
        "rogue":     False,
        "connected_ues": []
    }
}

# Currently connected UE
connected_ap = None


# ── Background: signal variation ──────────────────────────────────────────────
def signal_variation():
    while True:
        time.sleep(3)
        with lock:
            for ap_id, ap in aps.items():
                if ap["active"] and not ap["rogue"]:
                    noise = random.uniform(-1.5, 1.5)
                    ap["rssi_dbm"] = max(-80.0, min(-50.0,
                        ap["rssi_dbm"] + noise))

threading.Thread(target=signal_variation, daemon=True).start()


# ══════════════════════════════════════════════════════════════════════════════
# REST API
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "port": PORT})


@app.route("/signal", methods=["GET"])
def get_signal():
    """Return signal info for a specific AP."""
    ap_id = request.args.get("ap_id", "LegitWiFiAP")
    with lock:
        ap = aps.get(ap_id)
    if not ap:
        return jsonify({"error": "AP not found"}), 404
    return jsonify({
        "ap_id":    ap_id,
        "rssi_dbm": ap["rssi_dbm"],
        "active":   ap["active"],
        "rogue":    ap["rogue"]
    })


@app.route("/connect", methods=["POST"])
def connect():
    """UE connects to this WiFi AP after blockchain approval."""
    global connected_ap
    data   = request.get_json()
    ue_id  = data.get("ue_id", "UE-1")
    ap_id  = data.get("ap_id", "LegitWiFiAP")

    with lock:
        ap = aps.get(ap_id)
        if not ap:
            return jsonify({"success": False, "reason": "AP not found"}), 404
        ap["connected_ues"].append(ue_id)
        connected_ap = ap_id

    print(f"[WiFi] {ue_id} connected to {ap_id}")
    return jsonify({
        "success":  True,
        "ue_id":    ue_id,
        "ap_id":    ap_id,
        "rssi_dbm": ap["rssi_dbm"]
    })


@app.route("/disconnect", methods=["POST"])
def disconnect():
    """UE disconnects from WiFi AP."""
    global connected_ap
    data  = request.get_json()
    ue_id = data.get("ue_id", "UE-1")
    ap_id = data.get("ap_id", "LegitWiFiAP")

    with lock:
        ap = aps.get(ap_id)
        if ap and ue_id in ap["connected_ues"]:
            ap["connected_ues"].remove(ue_id)
        connected_ap = None

    print(f"[WiFi] {ue_id} disconnected from {ap_id}")
    return jsonify({"success": True})


@app.route("/rogue/inject", methods=["POST"])
def inject_rogue():
    """
    Inject a rogue AP (Attack 2 simulation).
    Rogue AP has strong spoofed RSSI to lure UE.
    """
    data     = request.get_json()
    rogue_id = data.get("ap_id", "RogueAP")
    rssi     = float(data.get("rssi_dbm", -40.0))

    with lock:
        aps[rogue_id] = {
            "ap_id":         rogue_id,
            "org":           "AttackerOrg",
            "rssi_dbm":      rssi,
            "active":        True,
            "rogue":         True,
            "connected_ues": []
        }

    print(f"[WiFi] ROGUE AP injected: {rogue_id}  spoofed_rssi={rssi}dBm")
    return jsonify({"status": "injected", "ap_id": rogue_id, "rssi_dbm": rssi})


@app.route("/rogue/remove", methods=["POST"])
def remove_rogue():
    """Remove a rogue AP."""
    data     = request.get_json()
    rogue_id = data.get("ap_id", "RogueAP")

    with lock:
        aps.pop(rogue_id, None)

    print(f"[WiFi] Rogue AP removed: {rogue_id}")
    return jsonify({"status": "removed", "ap_id": rogue_id})


@app.route("/all", methods=["GET"])
def get_all():
    """Return all APs visible in this WiFi environment."""
    with lock:
        return jsonify(list(aps.values()))


@app.route("/status", methods=["GET"])
def status():
    with lock:
        return jsonify({
            "aps":          list(aps.values()),
            "connected_ap": connected_ap
        })


if __name__ == "__main__":
    print(f"\n[WiFi] WiFi AP emulator running on http://{HOST}:{PORT}")
    print(f"[WiFi] LegitWiFiAP active  rssi=-62dBm\n")
    app.run(host=HOST, port=PORT, debug=False, threaded=True)
