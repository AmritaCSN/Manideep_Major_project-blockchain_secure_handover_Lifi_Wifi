"""
lifi_ap.py
==========
LiFi Access Point emulator for Raspberry Pi prototype.
Runs as Flask REST API on port 5002.

Simulates:
  - Light signal quality (intensity, error rate)
  - 4-stage blockage attack
  - Signal reporting to UE on request
"""

import time
import random
import threading
from flask import Flask, request, jsonify

app  = Flask(__name__)
HOST = "127.0.0.1"
PORT = 5002

# ── AP identity ───────────────────────────────────────────────────────────────
AP_ID   = "LiFiAP"
ORG     = "Org1"

# ── Signal state (shared, thread-safe via lock) ───────────────────────────────
lock        = threading.Lock()
signal_state = {
    "intensity":    1.0,    # 0.0 (blocked) to 1.0 (perfect)
    "error_rate":   0.0,    # 0.0 to 1.0
    "rssi_dbm":    -40.0,   # dBm — LiFi represented as optical power
    "stage":        0,      # 0=clear, 1-4=blockage stages
    "blocked":      False,
    "active":       True
}

# Blockage stages — matches your ns-3 simulation
BLOCKAGE_STAGES = [
    {"stage": 1, "error": 0.05,  "rssi": -55.0, "intensity": 0.90},
    {"stage": 2, "error": 0.15,  "rssi": -65.0, "intensity": 0.70},
    {"stage": 3, "error": 0.35,  "rssi": -75.0, "intensity": 0.45},
    {"stage": 4, "error": 0.80,  "rssi": -85.0, "intensity": 0.10},
]

HANDOVER_TRIGGER_ERROR = 0.15  # Trigger handover when error >= 15%


# ── Background: natural signal variation ──────────────────────────────────────
def natural_variation():
    """Add slight random variation to signal when not blocked."""
    while True:
        time.sleep(2)
        with lock:
            if not signal_state["blocked"] and signal_state["active"]:
                # Small noise on a clean signal
                noise = random.uniform(-0.02, 0.02)
                signal_state["rssi_dbm"] = max(-50.0, min(-38.0,
                    signal_state["rssi_dbm"] + noise))
                signal_state["error_rate"] = max(0.0, min(0.02,
                    signal_state["error_rate"] + random.uniform(-0.002, 0.002)))

threading.Thread(target=natural_variation, daemon=True).start()


# ══════════════════════════════════════════════════════════════════════════════
# REST API
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "ap_id": AP_ID, "port": PORT})


@app.route("/signal", methods=["GET"])
def get_signal():
    """Return current signal quality — called by UE simulator."""
    with lock:
        state = signal_state.copy()
    state["ap_id"] = AP_ID
    state["needs_handover"] = state["error_rate"] >= HANDOVER_TRIGGER_ERROR
    return jsonify(state)


@app.route("/blockage/start", methods=["POST"])
def start_blockage():
    """
    Simulate physical LiFi blockage (someone walks between LED and detector).
    Runs all 4 stages with 1-second intervals.
    """
    def run_stages():
        for s in BLOCKAGE_STAGES:
            time.sleep(1.0)
            with lock:
                signal_state["stage"]      = s["stage"]
                signal_state["error_rate"] = s["error"]
                signal_state["rssi_dbm"]   = s["rssi"]
                signal_state["intensity"]  = s["intensity"]
                signal_state["blocked"]    = s["stage"] >= 2
            print(f"[LiFi] Stage {s['stage']}  error={s['error']}  rssi={s['rssi']}dBm")
            if s["error"] >= HANDOVER_TRIGGER_ERROR:
                print(f"[LiFi] Signal degraded — handover trigger threshold reached")

    threading.Thread(target=run_stages, daemon=True).start()
    print(f"[LiFi] Blockage sequence started")
    return jsonify({"status": "blockage_started", "stages": 4})


@app.route("/blockage/clear", methods=["POST"])
def clear_blockage():
    """Restore full LiFi signal."""
    with lock:
        signal_state["intensity"]  = 1.0
        signal_state["error_rate"] = 0.0
        signal_state["rssi_dbm"]  = -40.0
        signal_state["stage"]      = 0
        signal_state["blocked"]    = False
    print(f"[LiFi] Signal restored — blockage cleared")
    return jsonify({"status": "signal_restored"})


@app.route("/status", methods=["GET"])
def status():
    with lock:
        return jsonify({
            "ap_id":        AP_ID,
            "org":          ORG,
            "signal":       signal_state.copy(),
            "handover_threshold": HANDOVER_TRIGGER_ERROR
        })


if __name__ == "__main__":
    print(f"\n[LiFi] LiFi AP emulator  ({AP_ID}) running on http://{HOST}:{PORT}")
    print(f"[LiFi] Handover trigger at error_rate >= {HANDOVER_TRIGGER_ERROR}\n")
    app.run(host=HOST, port=PORT, debug=False, threaded=True)
