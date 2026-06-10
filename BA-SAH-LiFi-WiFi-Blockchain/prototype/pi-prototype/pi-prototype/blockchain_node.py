"""
blockchain_node.py
==================
Core blockchain node for LiFi-WiFi Handover Prototype
Raspberry Pi 4 — Stage 1 (Software only)

Runs as a Flask REST API on port 5001.
Implements:
  - AP registry (register / revoke / lookup)
  - Handover policy (trust · RSSI · energy scoring)
  - Immutable ledger stored in SQLite
  - Raft-inspired consensus simulation (3 peers via majority vote)

Author : Garrepelly Manideep
Guide  : Dr. Sriram Sankaran
"""

import sqlite3
import hashlib
import json
import time
import random
import threading
from datetime import datetime
from flask import Flask, request, jsonify

app = Flask(__name__)

# ── Configuration ────────────────────────────────────────────────────────────
DB_PATH         = "ledger.db"
HOST            = "127.0.0.1"
PORT            = 5001

# Handover policy weights
W_TRUST         = 0.50
W_RSSI          = 0.30
W_ENERGY        = 0.20
THRESHOLD       = 0.55

# Consensus: simulate 3 Raft peers — majority (2/3) needed
N_PEERS         = 3
BYZANTINE_PROB  = 0.0   # set > 0 to simulate Byzantine peer

# Consensus latency range (ms) — realistic Raft LAN range
CONSENSUS_MIN_MS = 93
CONSENSUS_MAX_MS = 282

# Replay attack window (seconds)
REPLAY_WINDOW_S  = 30

# Rate limiting: max registrations per minute per org
RATE_LIMIT_PER_MIN = 5

# ── Database setup ────────────────────────────────────────────────────────────
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # AP registry — world state
    c.execute("""
        CREATE TABLE IF NOT EXISTS ap_registry (
            ap_id       TEXT PRIMARY KEY,
            org         TEXT NOT NULL,
            trust       REAL NOT NULL DEFAULT 1.0,
            registered  INTEGER NOT NULL DEFAULT 1,
            approved    INTEGER NOT NULL DEFAULT 0,
            rejected    INTEGER NOT NULL DEFAULT 0,
            registered_at TEXT NOT NULL
        )
    """)

    # Immutable ledger — all transactions
    c.execute("""
        CREATE TABLE IF NOT EXISTS ledger (
            tx_id       TEXT PRIMARY KEY,
            block_num   INTEGER NOT NULL,
            timestamp   TEXT NOT NULL,
            source_ap   TEXT NOT NULL,
            target_ap   TEXT NOT NULL,
            decision    TEXT NOT NULL,
            score       REAL,
            trust       REAL,
            rssi_norm   REAL,
            energy_norm REAL,
            latency_ms  REAL,
            energy_mj   REAL,
            attack_type TEXT,
            prev_hash   TEXT NOT NULL
        )
    """)

    # Block headers — chain integrity
    c.execute("""
        CREATE TABLE IF NOT EXISTS blocks (
            block_num   INTEGER PRIMARY KEY,
            block_hash  TEXT NOT NULL,
            prev_hash   TEXT NOT NULL,
            tx_count    INTEGER NOT NULL,
            created_at  TEXT NOT NULL
        )
    """)

    # Rate limiting tracking
    c.execute("""
        CREATE TABLE IF NOT EXISTS rate_log (
            org         TEXT NOT NULL,
            timestamp   TEXT NOT NULL
        )
    """)

    # Seen TX nonces — for replay protection
    c.execute("""
        CREATE TABLE IF NOT EXISTS seen_nonces (
            nonce       TEXT PRIMARY KEY,
            timestamp   TEXT NOT NULL
        )
    """)

    # Genesis block
    c.execute("SELECT COUNT(*) FROM blocks")
    if c.fetchone()[0] == 0:
        genesis_hash = hashlib.sha256(b"genesis").hexdigest()
        c.execute("""
            INSERT INTO blocks (block_num, block_hash, prev_hash, tx_count, created_at)
            VALUES (0, ?, '0000000000000000', 0, ?)
        """, (genesis_hash, datetime.now().isoformat()))

    # Seed legitimate APs
    c.execute("SELECT COUNT(*) FROM ap_registry")
    if c.fetchone()[0] == 0:
        now = datetime.now().isoformat()
        c.execute("""
            INSERT INTO ap_registry (ap_id, org, trust, registered, registered_at)
            VALUES ('LiFiAP', 'Org1', 1.0, 1, ?)
        """, (now,))
        c.execute("""
            INSERT INTO ap_registry (ap_id, org, trust, registered, registered_at)
            VALUES ('LegitWiFiAP', 'Org2', 0.965, 1, ?)
        """, (now,))

    conn.commit()
    conn.close()
    print(f"[BC] Ledger initialised at {DB_PATH}")
    print(f"[BC] Genesis block created")
    print(f"[BC] LiFiAP and LegitWiFiAP seeded")


# ── Helper: last block hash ───────────────────────────────────────────────────
def get_last_block(conn):
    c = conn.cursor()
    c.execute("SELECT block_num, block_hash FROM blocks ORDER BY block_num DESC LIMIT 1")
    row = c.fetchone()
    return row if row else (0, "0000000000000000")


# ── Helper: commit TX to ledger ───────────────────────────────────────────────
def commit_tx(conn, tx_data: dict):
    c = conn.cursor()
    last_num, last_hash = get_last_block(conn)
    new_block_num = last_num + 1

    # Build TX ID from content hash
    tx_content = json.dumps(tx_data, sort_keys=True).encode()
    tx_id = hashlib.sha256(tx_content).hexdigest()[:16]

    # Block hash
    block_content = f"{new_block_num}{last_hash}{tx_id}".encode()
    block_hash = hashlib.sha256(block_content).hexdigest()

    # Insert TX
    c.execute("""
        INSERT OR REPLACE INTO ledger
        (tx_id, block_num, timestamp, source_ap, target_ap, decision,
         score, trust, rssi_norm, energy_norm, latency_ms, energy_mj,
         attack_type, prev_hash)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        tx_id,
        new_block_num,
        tx_data.get("timestamp", datetime.now().isoformat()),
        tx_data.get("source_ap", ""),
        tx_data.get("target_ap", ""),
        tx_data.get("decision", "UNKNOWN"),
        tx_data.get("score"),
        tx_data.get("trust"),
        tx_data.get("rssi_norm"),
        tx_data.get("energy_norm"),
        tx_data.get("latency_ms"),
        tx_data.get("energy_mj"),
        tx_data.get("attack_type", "none"),
        last_hash
    ))

    # Insert block header
    c.execute("""
        INSERT INTO blocks (block_num, block_hash, prev_hash, tx_count, created_at)
        VALUES (?,?,?,1,?)
    """, (new_block_num, block_hash, last_hash, datetime.now().isoformat()))

    # Update AP trust
    if tx_data.get("decision") == "APPROVED":
        c.execute("""
            UPDATE ap_registry SET approved = approved + 1 WHERE ap_id = ?
        """, (tx_data.get("target_ap"),))
    elif tx_data.get("decision") == "DENIED":
        c.execute("""
            UPDATE ap_registry
            SET rejected = rejected + 1,
                trust = MAX(0.0, trust - 0.005)
            WHERE ap_id = ?
        """, (tx_data.get("target_ap"),))

    conn.commit()
    return tx_id, new_block_num, block_hash


# ── Consensus simulation ──────────────────────────────────────────────────────
def run_consensus(verdict: str) -> tuple[str, float]:
    """
    Simulate Raft consensus across N_PEERS.
    Returns (final_verdict, latency_ms).
    Byzantine peer randomly sends wrong vote.
    """
    votes = []
    for peer_id in range(N_PEERS):
        is_byzantine = (peer_id == 0 and random.random() < BYZANTINE_PROB)
        if is_byzantine:
            # Byzantine peer sends opposite vote
            votes.append("APPROVED" if verdict == "DENIED" else "DENIED")
        else:
            votes.append(verdict)

    approve_count = votes.count("APPROVED")
    final = "APPROVED" if approve_count > N_PEERS / 2 else "DENIED"

    # Realistic Raft latency
    latency_ms = random.uniform(CONSENSUS_MIN_MS, CONSENSUS_MAX_MS)
    time.sleep(latency_ms / 1000.0)

    return final, latency_ms


# ── Scoring function ──────────────────────────────────────────────────────────
def compute_score(trust: float, rssi_dbm: float, energy_mj: float) -> dict:
    """
    S = W_TRUST * trust + W_RSSI * rssi_norm + W_ENERGY * energy_norm
    RSSI normalised from [-100, -30] dBm to [0, 1]
    Energy normalised from [0, 5000] mJ to [1, 0] (lower energy = better)
    """
    rssi_norm   = max(0.0, min(1.0, (rssi_dbm + 100) / 70.0))
    energy_norm = max(0.0, min(1.0, 1.0 - energy_mj / 5000.0))
    score       = W_TRUST * trust + W_RSSI * rssi_norm + W_ENERGY * energy_norm

    return {
        "score":       round(score, 4),
        "trust":       round(trust, 4),
        "rssi_norm":   round(rssi_norm, 4),
        "energy_norm": round(energy_norm, 4)
    }


# ── Rate limit check ──────────────────────────────────────────────────────────
def check_rate_limit(conn, org: str) -> bool:
    c = conn.cursor()
    one_min_ago = datetime.fromtimestamp(time.time() - 60).isoformat()
    c.execute("""
        SELECT COUNT(*) FROM rate_log
        WHERE org = ? AND timestamp > ?
    """, (org, one_min_ago))
    count = c.fetchone()[0]
    if count >= RATE_LIMIT_PER_MIN:
        return False
    c.execute("INSERT INTO rate_log (org, timestamp) VALUES (?,?)",
              (org, datetime.now().isoformat()))
    conn.commit()
    return True


# ── Replay check ──────────────────────────────────────────────────────────────
def check_replay(conn, nonce: str) -> bool:
    """Returns True if nonce is fresh (not a replay)."""
    c = conn.cursor()
    cutoff = datetime.fromtimestamp(time.time() - REPLAY_WINDOW_S).isoformat()
    # Purge old nonces
    c.execute("DELETE FROM seen_nonces WHERE timestamp < ?", (cutoff,))
    # Check if nonce already seen
    c.execute("SELECT 1 FROM seen_nonces WHERE nonce = ?", (nonce,))
    if c.fetchone():
        conn.commit()
        return False  # replay detected
    # Record nonce
    c.execute("INSERT INTO seen_nonces (nonce, timestamp) VALUES (?,?)",
              (nonce, datetime.now().isoformat()))
    conn.commit()
    return True


# ══════════════════════════════════════════════════════════════════════════════
# REST API endpoints
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "node": "blockchain_node", "port": PORT})


# ── Register AP ───────────────────────────────────────────────────────────────
@app.route("/register", methods=["POST"])
def register_ap():
    """
    Register a new AP into the blockchain registry.
    Body: { "ap_id": str, "org": str, "trust": float }
    """
    data   = request.get_json()
    ap_id  = data.get("ap_id", "")
    org    = data.get("org", "Unknown")
    trust  = float(data.get("trust", 0.5))

    conn = sqlite3.connect(DB_PATH)
    c    = conn.cursor()

    # Rate limit per org
    if not check_rate_limit(conn, org):
        conn.close()
        print(f"[BC] RATE_LIMIT blocked {ap_id} from {org}")
        return jsonify({
            "success": False,
            "reason":  "Rate limit exceeded — max 5 registrations/min per org"
        }), 429

    # Register
    c.execute("""
        INSERT OR REPLACE INTO ap_registry
        (ap_id, org, trust, registered, approved, rejected, registered_at)
        VALUES (?,?,?,1,0,0,?)
    """, (ap_id, org, trust, datetime.now().isoformat()))
    conn.commit()
    conn.close()

    print(f"[BC] REGISTERED  ap={ap_id}  org={org}  trust={trust}")
    return jsonify({"success": True, "ap_id": ap_id, "trust": trust})


# ── Revoke AP ─────────────────────────────────────────────────────────────────
@app.route("/revoke", methods=["POST"])
def revoke_ap():
    """Revoke (deregister) an AP from the registry."""
    data  = request.get_json()
    ap_id = data.get("ap_id", "")

    conn = sqlite3.connect(DB_PATH)
    c    = conn.cursor()
    c.execute("UPDATE ap_registry SET registered = 0 WHERE ap_id = ?", (ap_id,))
    conn.commit()
    conn.close()

    print(f"[BC] REVOKED  ap={ap_id}")
    return jsonify({"success": True, "ap_id": ap_id})


# ── Re-register AP ────────────────────────────────────────────────────────────
@app.route("/reregister", methods=["POST"])
def reregister_ap():
    data  = request.get_json()
    ap_id = data.get("ap_id", "")

    conn = sqlite3.connect(DB_PATH)
    c    = conn.cursor()
    c.execute("UPDATE ap_registry SET registered = 1 WHERE ap_id = ?", (ap_id,))
    conn.commit()
    conn.close()

    print(f"[BC] RE-REGISTERED  ap={ap_id}")
    return jsonify({"success": True, "ap_id": ap_id})


# ── Handover request ──────────────────────────────────────────────────────────
@app.route("/handover", methods=["POST"])
def handover():
    """
    Main handover decision endpoint.
    Body: {
        "source_ap":  str,
        "target_ap":  str,
        "rssi_dbm":   float,
        "energy_mj":  float,
        "nonce":      str,      (optional — for replay protection)
        "attack_type":str       (optional — for simulation labelling)
    }
    Returns: {
        "approved":    bool,
        "decision":    str,
        "score":       float,
        "latency_ms":  float,
        "block_num":   int,
        "tx_id":       str,
        "reason":      str
    }
    """
    data        = request.get_json()
    source_ap   = data.get("source_ap",  "Unknown")
    target_ap   = data.get("target_ap",  "Unknown")
    rssi_dbm    = float(data.get("rssi_dbm",   -70.0))
    energy_mj   = float(data.get("energy_mj",  500.0))
    nonce       = data.get("nonce",       f"nonce-{time.time()}")
    attack_type = data.get("attack_type", "none")

    conn   = sqlite3.connect(DB_PATH)
    c      = conn.cursor()
    reason = ""

    print(f"\n[BC] HANDOVER REQUEST  {source_ap} → {target_ap}")

    # ── Step 1: Replay check ──────────────────────────────────────────────────
    if not check_replay(conn, nonce):
        reason = f"Replay detected — nonce already used: {nonce}"
        print(f"[BC] BLOCKED (replay)  {reason}")
        tx_id, block_num, _ = commit_tx(conn, {
            "timestamp":   datetime.now().isoformat(),
            "source_ap":   source_ap,
            "target_ap":   target_ap,
            "decision":    "DENIED",
            "score":       None,
            "latency_ms":  5.0,
            "energy_mj":   energy_mj,
            "attack_type": "replay"
        })
        conn.close()
        return jsonify({
            "approved":   False,
            "decision":   "DENIED",
            "reason":     reason,
            "latency_ms": 5.0,
            "block_num":  block_num,
            "tx_id":      tx_id
        })

    # ── Step 2: Registry lookup ───────────────────────────────────────────────
    c.execute("""
        SELECT trust, registered, org FROM ap_registry WHERE ap_id = ?
    """, (target_ap,))
    row = c.fetchone()

    if not row or row[1] == 0:
        reason = f"Target AP not registered: {target_ap}"
        print(f"[BC] BLOCKED (registry)  {reason}")
        final, latency_ms = run_consensus("DENIED")
        tx_id, block_num, _ = commit_tx(conn, {
            "timestamp":   datetime.now().isoformat(),
            "source_ap":   source_ap,
            "target_ap":   target_ap,
            "decision":    "DENIED",
            "score":       None,
            "latency_ms":  latency_ms,
            "energy_mj":   energy_mj,
            "attack_type": attack_type
        })
        conn.close()
        return jsonify({
            "approved":   False,
            "decision":   "DENIED",
            "reason":     reason,
            "latency_ms": latency_ms,
            "block_num":  block_num,
            "tx_id":      tx_id
        })

    trust = row[0]

    # ── Step 3: Score computation ─────────────────────────────────────────────
    scored  = compute_score(trust, rssi_dbm, energy_mj)
    score   = scored["score"]
    verdict = "APPROVED" if score >= THRESHOLD else "DENIED"

    if verdict == "DENIED":
        reason = f"Score {score:.4f} below threshold {THRESHOLD}"

    # ── Step 4: Consensus ─────────────────────────────────────────────────────
    final, latency_ms = run_consensus(verdict)

    if final != verdict:
        reason = "Consensus overrode local verdict (Byzantine peer detected)"
    if not reason and final == "APPROVED":
        reason = "Score above threshold — legitimate AP"

    # ── Step 5: Energy cost ───────────────────────────────────────────────────
    energy_cost_mj = 4.257 if final == "APPROVED" else 0.1

    # ── Step 6: Commit to ledger ──────────────────────────────────────────────
    tx_data = {
        "timestamp":   datetime.now().isoformat(),
        "source_ap":   source_ap,
        "target_ap":   target_ap,
        "decision":    final,
        "score":       score,
        "trust":       scored["trust"],
        "rssi_norm":   scored["rssi_norm"],
        "energy_norm": scored["energy_norm"],
        "latency_ms":  latency_ms,
        "energy_mj":   energy_cost_mj,
        "attack_type": attack_type
    }
    tx_id, block_num, block_hash = commit_tx(conn, tx_data)
    conn.close()

    print(f"[BC] {final}  score={score:.4f}  latency={latency_ms:.1f}ms  block={block_num}")

    return jsonify({
        "approved":    final == "APPROVED",
        "decision":    final,
        "score":       score,
        "trust":       scored["trust"],
        "rssi_norm":   scored["rssi_norm"],
        "energy_norm": scored["energy_norm"],
        "reason":      reason,
        "latency_ms":  round(latency_ms, 2),
        "energy_mj":   energy_cost_mj,
        "block_num":   block_num,
        "tx_id":       tx_id,
        "block_hash":  block_hash
    })


# ── Ledger query ──────────────────────────────────────────────────────────────
@app.route("/ledger", methods=["GET"])
def get_ledger():
    """Return last N transactions from the ledger."""
    limit = int(request.args.get("limit", 20))
    conn  = sqlite3.connect(DB_PATH)
    c     = conn.cursor()
    c.execute("""
        SELECT tx_id, block_num, timestamp, source_ap, target_ap,
               decision, score, latency_ms, energy_mj, attack_type
        FROM ledger ORDER BY block_num DESC LIMIT ?
    """, (limit,))
    rows = c.fetchall()
    conn.close()
    keys = ["tx_id","block_num","timestamp","source_ap","target_ap",
            "decision","score","latency_ms","energy_mj","attack_type"]
    return jsonify([dict(zip(keys, r)) for r in rows])


# ── World state ───────────────────────────────────────────────────────────────
@app.route("/registry", methods=["GET"])
def get_registry():
    """Return all APs in the registry."""
    conn = sqlite3.connect(DB_PATH)
    c    = conn.cursor()
    c.execute("""
        SELECT ap_id, org, trust, registered, approved, rejected, registered_at
        FROM ap_registry ORDER BY trust DESC
    """)
    rows = conn.cursor().fetchall() if False else c.fetchall()
    conn.close()
    keys = ["ap_id","org","trust","registered","approved","rejected","registered_at"]
    return jsonify([dict(zip(keys, r)) for r in rows])


# ── Statistics ────────────────────────────────────────────────────────────────
@app.route("/stats", methods=["GET"])
def get_stats():
    """Return summary statistics for the dashboard."""
    conn = sqlite3.connect(DB_PATH)
    c    = conn.cursor()

    c.execute("SELECT COUNT(*) FROM ledger")
    total_tx = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM ledger WHERE decision='APPROVED'")
    approved = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM ledger WHERE decision='DENIED'")
    denied = c.fetchone()[0]

    c.execute("SELECT AVG(latency_ms) FROM ledger WHERE latency_ms IS NOT NULL")
    avg_lat = c.fetchone()[0] or 0

    c.execute("SELECT SUM(energy_mj) FROM ledger WHERE decision='APPROVED'")
    energy_with_bc = c.fetchone()[0] or 0

    c.execute("SELECT COUNT(*) FROM blocks")
    block_height = c.fetchone()[0]

    conn.close()

    # Energy without BC: assume all TX approved at 4.257 mJ each
    energy_without_bc = total_tx * 4.257
    energy_saving_pct = (
        (1 - energy_with_bc / energy_without_bc) * 100
        if energy_without_bc > 0 else 0
    )

    return jsonify({
        "total_tx":          total_tx,
        "approved":          approved,
        "denied":            denied,
        "block_height":      block_height,
        "avg_latency_ms":    round(avg_lat, 2),
        "energy_with_bc_mj": round(energy_with_bc, 2),
        "energy_without_bc_mj": round(energy_without_bc, 2),
        "energy_saving_pct": round(energy_saving_pct, 2)
    })


# ── Startup ───────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    init_db()
    print(f"\n[BC] Blockchain node running on http://{HOST}:{PORT}")
    print(f"[BC] Policy: S = {W_TRUST}*trust + {W_RSSI}*RSSI + {W_ENERGY}*energy >= {THRESHOLD}")
    print(f"[BC] Consensus: {N_PEERS} Raft peers | Replay window: {REPLAY_WINDOW_S}s\n")
    app.run(host=HOST, port=PORT, debug=False, threaded=True)
