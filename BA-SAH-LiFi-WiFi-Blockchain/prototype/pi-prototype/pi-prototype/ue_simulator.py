"""
ue_simulator.py
===============
User Equipment (UE) simulator for Raspberry Pi prototype.

Runs as an autonomous agent that:
  1. Monitors LiFi signal quality every 2 seconds
  2. When signal degrades → sends handover request to blockchain
  3. On approval → connects to WiFi AP
  4. Simulates all 9 attacks from your ns-3 simulation
  5. Reports all events to the dashboard

Run modes:
  python3 ue_simulator.py              # continuous monitoring
  python3 ue_simulator.py --attack N   # trigger specific attack (1-9)
  python3 ue_simulator.py --demo       # run full 9-attack demo sequence
"""

import sys
import time
import uuid
import json
import random
import argparse
import requests
from datetime import datetime

# ── Service endpoints ─────────────────────────────────────────────────────────
BC_URL    = "http://127.0.0.1:5001"
LIFI_URL  = "http://127.0.0.1:5002"
WIFI_URL  = "http://127.0.0.1:5003"
DASH_URL  = "http://127.0.0.1:5000"

UE_ID     = "UE-1"
POLL_SEC  = 2       # check signal every 2 seconds

# Current radio medium
current_medium = "LiFi"


# ── Logging helper ────────────────────────────────────────────────────────────
def log(msg: str, level: str = "INFO"):
    ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    print(f"[{ts}] [{level}] {msg}")


def post_event(event: dict):
    """Send event to dashboard log."""
    try:
        requests.post(f"{DASH_URL}/event", json=event, timeout=1)
    except Exception:
        pass


# ── Handover request to blockchain ────────────────────────────────────────────
def request_handover(target_ap: str, rssi_dbm: float,
                     energy_mj: float = 500.0,
                     nonce: str = None,
                     attack_type: str = "none") -> dict:
    global current_medium

    if nonce is None:
        nonce = f"nonce-{uuid.uuid4().hex[:12]}"

    source_ap = "LiFiAP" if current_medium == "LiFi" else "LegitWiFiAP"
    log(f"HANDOVER REQUEST  {source_ap} → {target_ap}  rssi={rssi_dbm}dBm")

    try:
        resp = requests.post(f"{BC_URL}/handover", json={
            "source_ap":   source_ap,
            "target_ap":   target_ap,
            "rssi_dbm":    rssi_dbm,
            "energy_mj":   energy_mj,
            "nonce":       nonce,
            "attack_type": attack_type
        }, timeout=10)
        result = resp.json()
    except Exception as e:
        log(f"Blockchain unreachable: {e}", "ERROR")
        return {"approved": False, "decision": "ERROR", "reason": str(e)}

    if result.get("approved"):
        log(f"APPROVED  score={result.get('score')}  latency={result.get('latency_ms')}ms  block={result.get('block_num')}")
    else:
        log(f"DENIED  reason={result.get('reason')}  latency={result.get('latency_ms')}ms")

    # Post event to dashboard
    post_event({
        "timestamp":   datetime.now().isoformat(),
        "ue_id":       UE_ID,
        "source_ap":   source_ap,
        "target_ap":   target_ap,
        "decision":    result.get("decision"),
        "score":       result.get("score"),
        "latency_ms":  result.get("latency_ms"),
        "attack_type": attack_type
    })

    return result


# ── Switch radio medium ────────────────────────────────────────────────────────
def switch_to_wifi(ap_id: str = "LegitWiFiAP"):
    global current_medium
    try:
        requests.post(f"{WIFI_URL}/connect", json={"ue_id": UE_ID, "ap_id": ap_id}, timeout=3)
    except Exception:
        pass
    current_medium = "WiFi"
    log(f"SWITCHED to WiFi  ap={ap_id}")


def switch_to_lifi():
    global current_medium
    try:
        requests.post(f"{WIFI_URL}/disconnect", json={"ue_id": UE_ID, "ap_id": "LegitWiFiAP"}, timeout=3)
    except Exception:
        pass
    current_medium = "LiFi"
    log(f"SWITCHED to LiFi")


# ══════════════════════════════════════════════════════════════════════════════
# ATTACK SIMULATIONS — matching your ns-3 implementation
# ══════════════════════════════════════════════════════════════════════════════

def attack_1_lifi_blockage():
    log("=== ATTACK 1: LiFi Blockage ===")
    try:
        requests.post(f"{LIFI_URL}/blockage/start", timeout=3)
    except Exception:
        pass
    time.sleep(2)
    # At stage 2, signal degraded — request handover
    result = request_handover("LegitWiFiAP", rssi_dbm=-65.0,
                              attack_type="lifi_blockage")
    if result.get("approved"):
        switch_to_wifi()
    time.sleep(4)
    try:
        requests.post(f"{LIFI_URL}/blockage/clear", timeout=3)
    except Exception:
        pass
    if current_medium == "WiFi":
        result2 = request_handover("LiFiAP", rssi_dbm=-40.0,
                                   attack_type="return_to_lifi")
        if result2.get("approved"):
            switch_to_lifi()
    log("=== ATTACK 1 COMPLETE ===")


def attack_2_rogue_ap():
    log("=== ATTACK 2: Rogue AP ===")
    # Inject rogue AP with spoofed strong signal
    try:
        requests.post(f"{WIFI_URL}/rogue/inject", json={
            "ap_id":    "RogueAP",
            "rssi_dbm": -40.0
        }, timeout=3)
    except Exception:
        pass

    # Try connecting to rogue AP 3 times (blockchain should block)
    for i in range(3):
        log(f"Rogue beacon #{i+1} — attempting connection to RogueAP")
        result = request_handover("RogueAP", rssi_dbm=-40.0,
                                  attack_type="rogue_ap")
        if result.get("approved"):
            log("WARNING: Rogue AP handover APPROVED (should not happen)", "WARN")
            switch_to_wifi("RogueAP")
        else:
            log(f"Rogue AP BLOCKED — {result.get('reason')}")
        time.sleep(1.0)

    try:
        requests.post(f"{WIFI_URL}/rogue/remove", json={"ap_id": "RogueAP"}, timeout=3)
    except Exception:
        pass
    log("=== ATTACK 2 COMPLETE ===")


def attack_3_mitm():
    log("=== ATTACK 3: MITM — 40% packet drop simulation ===")
    log("MITM is data-plane — blockchain records in audit trail only")
    # In software prototype: log the MITM event, measure impact
    post_event({
        "timestamp":   datetime.now().isoformat(),
        "ue_id":       UE_ID,
        "source_ap":   current_medium,
        "target_ap":   "Attacker",
        "decision":    "MITM_ACTIVE",
        "score":       None,
        "latency_ms":  None,
        "attack_type": "mitm_40pct_drop"
    })
    time.sleep(3)
    log("=== ATTACK 3 COMPLETE (partial — data-plane) ===")


def attack_4_downgrade():
    log("=== ATTACK 4: Downgrade Attack ===")
    # Revoke LegitWiFiAP from registry
    try:
        requests.post(f"{BC_URL}/revoke", json={"ap_id": "LegitWiFiAP"}, timeout=3)
    except Exception:
        pass
    log("LegitWiFiAP revoked — attempting downgrade handover")

    result = request_handover("LegitWiFiAP", rssi_dbm=-62.0,
                              attack_type="downgrade")
    if not result.get("approved"):
        log(f"Downgrade BLOCKED — {result.get('reason')}")
    else:
        log("WARNING: Downgrade SUCCEEDED", "WARN")

    # Restore
    time.sleep(2)
    try:
        requests.post(f"{BC_URL}/reregister", json={"ap_id": "LegitWiFiAP"}, timeout=3)
    except Exception:
        pass
    log("LegitWiFiAP re-registered — security restored")
    log("=== ATTACK 4 COMPLETE ===")


def attack_5_replay():
    log("=== ATTACK 5: Replay Attack ===")
    # First legitimate request — capture nonce
    captured_nonce = f"nonce-{uuid.uuid4().hex[:12]}"
    log(f"Legitimate TX captured — nonce={captured_nonce}")

    # Immediately replay same nonce
    time.sleep(0.5)
    log(f"Replaying captured nonce after 0.5s")
    result = request_handover("LegitWiFiAP", rssi_dbm=-62.0,
                              nonce=captured_nonce,
                              attack_type="replay")
    if not result.get("approved"):
        log(f"Replay BLOCKED — {result.get('reason')}")
    else:
        log("WARNING: Replay SUCCEEDED (nonce not tracked)", "WARN")
    log("=== ATTACK 5 COMPLETE ===")


def attack_6_sybil():
    log("=== ATTACK 6: Sybil Attack — 15 fake APs ===")
    for i in range(1, 16):
        sybil_id = f"SybilAP_{i}"
        # Register with low trust (attacker org)
        try:
            requests.post(f"{BC_URL}/register", json={
                "ap_id": sybil_id,
                "org":   "AttackerOrg",
                "trust": 0.05
            }, timeout=3)
        except Exception:
            pass
        # Try handover to sybil AP
        result = request_handover(sybil_id, rssi_dbm=-45.0,
                                  attack_type="sybil")
        status = "BLOCKED" if not result.get("approved") else "CONNECTED"
        log(f"SybilAP_{i}: {status}")
        time.sleep(0.2)
    log("=== ATTACK 6 COMPLETE ===")


def attack_7_dos():
    log("=== ATTACK 7: DoS on Blockchain — 50 TX flood ===")
    # Flood blockchain with TX and measure latency impact
    latencies = []
    for i in range(50):
        nonce = f"dos-{uuid.uuid4().hex[:8]}"
        result = request_handover("LegitWiFiAP", rssi_dbm=-62.0,
                                  nonce=nonce,
                                  attack_type="dos_bc")
        if result.get("latency_ms"):
            latencies.append(result["latency_ms"])
    if latencies:
        avg = sum(latencies) / len(latencies)
        log(f"DoS flood complete — avg latency under load: {avg:.1f}ms")
    log("=== ATTACK 7 COMPLETE ===")


def attack_8_byzantine():
    log("=== ATTACK 8: Byzantine Peer ===")
    log("Byzantine peer (Peer-0) sends false endorsement")
    log("2-of-3 honest majority overrides — requesting handover")
    # With BYZANTINE_PROB set in blockchain_node.py,
    # consensus may override one bad vote
    result = request_handover("LegitWiFiAP", rssi_dbm=-62.0,
                              attack_type="byzantine")
    if result.get("approved"):
        log("Handover APPROVED — honest consensus overrode Byzantine peer")
    else:
        log(f"Handover DENIED — {result.get('reason')}")
    log("=== ATTACK 8 COMPLETE ===")


def attack_9_session_hijack():
    log("=== ATTACK 9: Session Hijack ===")
    # Step 1: legitimate handover
    result = request_handover("LegitWiFiAP", rssi_dbm=-62.0,
                              attack_type="session_hijack_init")
    if result.get("approved"):
        switch_to_wifi()
        log(f"Session established — session-{int(time.time())}")
        time.sleep(1)
        # Step 2: ARP spoof simulation — attacker masquerades as UE
        log("Attacker begins ARP spoofing — masquerading as UE")
        # Blockchain audit trail detects traffic fingerprint mismatch
        anomaly_detected = random.random() < 0.85
        if anomaly_detected:
            log("ANOMALY DETECTED via blockchain audit trail")
            log("Traffic fingerprint mismatch — forcing re-authentication")
            # Force re-auth
            reauth = request_handover("LegitWiFiAP", rssi_dbm=-62.0,
                                     attack_type="session_reauth")
            if reauth.get("approved"):
                log("Re-auth APPROVED — session re-established securely")
        else:
            log("Anomaly NOT detected (P_miss=0.15) — hijack succeeds this run", "WARN")
    log("=== ATTACK 9 COMPLETE ===")


# ══════════════════════════════════════════════════════════════════════════════
# Main operating modes
# ══════════════════════════════════════════════════════════════════════════════

ATTACKS = {
    1: attack_1_lifi_blockage,
    2: attack_2_rogue_ap,
    3: attack_3_mitm,
    4: attack_4_downgrade,
    5: attack_5_replay,
    6: attack_6_sybil,
    7: attack_7_dos,
    8: attack_8_byzantine,
    9: attack_9_session_hijack
}


def run_demo():
    """Run all 9 attacks with 3-second gaps — full demo sequence."""
    log("Starting full 9-attack demo sequence")
    for i in range(1, 10):
        log(f"\n{'='*50}")
        ATTACKS[i]()
        time.sleep(3)
    log("\nDemo complete — check dashboard at http://localhost:5000")


def run_continuous():
    """Continuously monitor LiFi signal and trigger handover when needed."""
    log(f"UE monitoring started — polling every {POLL_SEC}s")
    log(f"Current medium: {current_medium}")

    while True:
        try:
            resp = requests.get(f"{LIFI_URL}/signal", timeout=3)
            signal = resp.json()

            if signal.get("needs_handover") and current_medium == "LiFi":
                log(f"LiFi degraded (error={signal['error_rate']:.2f}) — requesting handover")
                result = request_handover(
                    "LegitWiFiAP",
                    rssi_dbm=-62.0,
                    attack_type="auto_lifi_blockage"
                )
                if result.get("approved"):
                    switch_to_wifi()

            elif not signal.get("needs_handover") and current_medium == "WiFi":
                log("LiFi restored — returning to LiFi")
                result = request_handover(
                    "LiFiAP",
                    rssi_dbm=signal.get("rssi_dbm", -40.0),
                    attack_type="return_to_lifi"
                )
                if result.get("approved"):
                    switch_to_lifi()

        except Exception as e:
            log(f"Signal check failed: {e}", "WARN")

        time.sleep(POLL_SEC)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="UE Simulator")
    parser.add_argument("--attack", type=int, choices=range(1, 10),
                        help="Run specific attack (1-9)")
    parser.add_argument("--demo",   action="store_true",
                        help="Run full 9-attack demo")
    args = parser.parse_args()

    # Wait for services to start
    log("Waiting 2s for services to initialise...")
    time.sleep(2)

    if args.demo:
        run_demo()
    elif args.attack:
        log(f"Running attack {args.attack}")
        ATTACKS[args.attack]()
    else:
        run_continuous()
