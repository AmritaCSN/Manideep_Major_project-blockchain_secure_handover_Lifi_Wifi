# BA-SAH: Blockchain-Assisted Security-Aware Handover for Energy Optimization in Hybrid LiFi–WiFi Access Networks

[![ns-3](https://img.shields.io/badge/Simulator-ns--3%20(3--dev)-blue)](https://www.nsnam.org/)
[![Python](https://img.shields.io/badge/Python-3.11-green)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Hardware-Raspberry%20Pi%204-red)](https://www.raspberrypi.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)
[![Institution](https://img.shields.io/badge/Institution-Amrita%20Vishwa%20Vidyapeetham-purple)](https://www.amrita.edu/)


---

## Table of Contents

1. [Overview](#overview)
2. [Key Contributions](#key-contributions)
3. [Framework Overview](#framework-overview)
4. [Repository Structure](#repository-structure)
5. [Methodology](#methodology)
6. [Installation](#installation)
7. [Usage](#usage)
8. [Experimental Setup](#experimental-setup)
9. [Results](#results)
10. [Reproducibility Guide](#reproducibility-guide)
11. [Output Artifacts](#output-artifacts)
12. [Limitations and Future Work](#limitations-and-future-work)
13. [Citation](#citation)
14. [License and Acknowledgments](#license-and-acknowledgments)

---

## Overview

Hybrid Light Fidelity–Wireless Fidelity (LiFi–WiFi) networks combine multi-gigabit optical throughput with ubiquitous RF coverage to deliver high-capacity indoor wireless access. However, the vertical handover process — which switches a user device between the LiFi optical medium and the WiFi radio medium — introduces a critical and largely unexplored attack surface. When a LiFi link degrades (through natural occlusion or deliberate physical blockage), the forced fallback to WiFi occurs within a narrow time window during which existing performance-oriented handover algorithms apply no authentication or trust validation. An adversary who monitors the optical channel can exploit this window to inject rogue access points, replay captured handover tokens, flood the AP registry with Sybil identities, or compromise endorsing peers — all without triggering existing wireless intrusion detection systems.

This repository implements and validates **BA-SAH** (Blockchain-Assisted Security-Aware Handover), The permissioned-blockchain framework specifically designed to secure vertical handover decisions in hybrid LiFi–WiFi networks while jointly optimizing energy consumption. BA-SAH embeds a Hyperledger Fabric-inspired permissioned blockchain into the handover decision plane. Before any radio medium switch is executed, the framework submits the handover request to a three-peer Raft consensus cluster, which evaluates the candidate access point against a multi-factor composite trust score and an immutable AP registry. Only requests that exceed the approval threshold proceed to radio switching, while rejected requests are permanently recorded in the tamper-proof audit ledger. The central finding is that this security gate, by blocking 312 of 316 malicious handover requests, incidentally reduces total handover energy consumption by **72.527 ± 0.028%** — establishing that security enforcement and energy optimization are complementary objectives in adversarial handover environments.

---

## Key Contributions

1. **BA-SAH Framework Design.** To the best of our knowledge, the first permissioned-blockchain framework targeting security-aware vertical handover in hybrid LiFi–WiFi networks. BA-SAH integrates three smart contracts — AP Registry, Handover Policy, and Energy Accounting — with a Raft-based ordering service modelled on Hyperledger Fabric.

2. **Multi-Factor Handover Decision Policy.** A formally derived composite scoring function:
   ```
   S_composite = 0.50 × S_trust + 0.30 × S_RSSI + 0.20 × S_energy
   ```
   with approval threshold `θ = 0.55`. The weights satisfy two jointly derived constraints: Sybil resistance (any AP with `S_trust = 0.05` scores at most `0.525 < θ` regardless of channel quality) and legitimate-AP admissibility (LegitWiFiAP with `S_trust = 0.965` scores `0.8254 >> θ`).

3. **Nine-Attack STRIDE Threat Model.** Nine mechanistically distinct attack classes spanning all six STRIDE categories, each implemented as a separate simulation object with precise timing, measurable data-plane and control-plane impact, and a `blockchainEnabled` flag that produces a genuine insecure-baseline run. Six reproducibility fixes were applied over successive review cycles (documented in `fabric-attacks-v2.h`).

4. **Three-Scenario Comparative Evaluation.** Three rigorously defined ns-3 evaluation scenarios — clean baseline, attack without defense, attack with BA-SAH — producing directly comparable FlowMonitor network-layer evidence across 10 statistically independent runs (95% CI reported for all metrics).

5. **Energy–Security Co-Optimisation Finding.** Demonstration that blocking malicious handovers reduces total network energy by `72.527 ± 0.028%`, establishing a novel design principle: in adversarial environments, access control overhead is outweighed by the energy savings from eliminating unnecessary radio-switching events.

6. **Raspberry Pi 4 Hardware Prototype.** A five-process Python prototype running the identical protocol on embedded hardware, confirming that simulation-predicted latency (93–282 ms) matches hardware-measured latency (110–228 ms) and validating the ns-3 model as an accurate predictor of deployment behaviour.

---

## Framework Overview

BA-SAH operates as a control-plane security overlay. The data plane (UDP traffic between UE and server) is unaffected by blockchain consensus; the UE continues transmitting on its current medium while the blockchain processes the handover request asynchronously.

```
Handover Request Flow:

  UE detects LiFi degradation
       │
       ▼
  FabricClient.RequestHandover(source, target, RSSI, energy_budget)
       │
       ├─► Step 1: Replay check (nonce window = 30 s)
       │         → if expired or reused: DENIED in 5 ms (fast-path)
       │
       ├─► Step 2: AP Registry lookup
       │         → if not registered: DENIED after consensus (~110–282 ms)
       │
       ├─► Step 3: Composite score computation
       │         S = 0.50·trust + 0.30·RSSI_norm + 0.20·energy_norm
       │         → if S < 0.55: DENIED
       │
       ├─► Step 4: Raft 3-peer consensus (2-of-3 majority)
       │         latency: U[93, 282] ms (steady-state)
       │
       ├─► Step 5: Energy cost assignment
       │         APPROVED → 4.257 mJ (consensus overhead, no radio switch)
       │         DENIED   → 0.1 mJ
       │
       └─► Step 6: Commit to hash-linked block store
                 tx_id | block_hash | prev_hash | decision | score | latency
```

**Why energy decreases under BA-SAH:** In the undefended scenario, all 316 malicious requests are approved, each triggering a radio switch at ~15.5 mJ. Under BA-SAH, 312 are denied at only 4.257 mJ (consensus only, no switch). Net saving per blocked handover: `15.5 − 4.257 = 11.243 mJ`; total saving: `312 × 11.243 ≈ 3,508 mJ` (72.527% of 4,896 mJ).

---

## Repository Structure

```
BA-SAH-LiFi-WiFi-Blockchain/
│
├── README.md                         # This file
├── .gitignore                        # Excludes runtime/build artifacts
├── LICENSE                           # MIT License
|
├── simulation/                       # ── ns-3 C++ Simulation Layer ──────────
│   ├── CMakeLists.txt                # ns-3 build configuration (v5)
│   ├── hybrid_full_v5.cc             # Main simulation driver
│   │                                 #   3 scenarios · 9 attacks · FlowMonitor
│   │                                 #   7-node topology · --runId seeds
│   ├── fabric-ledger.h               # FabricLedger: data structures (header)
│   ├── fabric-ledger.cc              # FabricLedger: world state + block store
│   ├── fabric-chaincode.h            # Three smart-contract headers
│   ├── fabric-chaincode.cc           # ApRegistry · HandoverPolicy · Energy
│   ├── fabric-orderer.h              # FabricOrderer: Raft consensus (header+impl)
│   ├── fabric-client.h               # FabricClient SDK (header+impl)
│   ├── fabric-attacks-v2.h           # Nine attack classes + AttackOrchestrator
│   ├── fabric-metrics.h              # FabricMetricsCollector + CSV/XML export
│   └── run_experiments.sh            # Automated full experiment runner
│
├── prototype/                        # ── Raspberry Pi 4 Prototype ────────────
│   ├── blockchain_node.py            # Core blockchain REST API (port 5001)
│   │                                 #   SQLite ledger · 6-step protocol
│   ├── lifi_ap.py                    # LiFi AP emulator (port 5002)
│   │                                 #   4-stage blockage · signal quality API
│   ├── wifi_ap.py                    # WiFi AP emulator (port 5003)
│   │                                 #   connection manager · rogue AP inject
│   ├── ue_simulator.py               # UE simulator
│   │                                 #   continuous monitoring · 9 attacks
│   ├── dashboard.py                  # Flask live web dashboard (port 5000)
│   ├── run_all.sh                    # Start all 5 processes simultaneously
│   ├── setup.sh                      # First-time dependency installation
│   └── requirements.txt             # flask==3.0.3, requests==2.31.0
│
├── analysis/
│   └── analyze_stats.py              # Mean ± std dev · 95% CI · journal tables
│
└── results/
    └── sample/                       # Sample output CSVs (reference values)
        ├── attack_summary.csv
        ├── baseline_measured.csv
        ├── latency_comparison.csv
        └── energy_comparison.csv
```

**Key design note on `CMakeLists.txt`:** The active build target is `hybrid_full_v5`. A commented-out v4 entry is retained for reference and must not be uncommented during builds.

---

## Methodology

### 1. Network Topology and Channel Models

The simulation instantiates a seven-node hybrid LiFi–WiFi topology in ns-3:

| Node | Role | Position (m) |
|------|------|-------------|
| UE | Dual-interface device (LiFi + WiFi 802.11ac) | (0, 0, 0) |
| LiFi-AP | 200 Mbps P2P link, 1 ms delay | (0, 3, 3) |
| LegitWiFi-AP | 802.11ac, Org2, trust=0.95 | (5, 0, 0) |
| Rogue-AP | Isolated channel, unregistered, RSSI=−40 dBm | (3, 1, 0) |
| Router | 1 Gbps backhaul, 2 ms | (10, 0, 0) |
| Attacker | Permanent MITM node (passive by default) | (15, 2, 0) |
| Server | UDP sink, FlowMonitor target | (20, 0, 0) |

**Critical topology decision:** Traffic always routes through the Attacker node in all three scenarios. This ensures that FlowMonitor XML differences across scenarios are caused solely by attack effects rather than topology changes. The Rogue-AP operates on a physically isolated `YansWifiPhy` channel to prevent IP subnet conflicts with the legitimate WiFi infrastructure.

**LiFi blockage model:** Error rate evolves in four deterministic stages post-blockage onset:

```
ε(t) = { 0.05,  t ∈ [0,1) s  (partial occlusion)
        { 0.15,  t ∈ [1,2) s  ← handover trigger threshold
        { 0.35,  t ∈ [2,3) s
        { 0.80,  t ≥ 3 s      (link failure)
```

### 2. Three-Scenario Experimental Design

| Scenario | Command Flag | Description |
|----------|-------------|-------------|
| **S0: Baseline** | `--scenario=0` | No attacks, blockchain disabled. Measures clean network performance; exports `baseline_measured.csv`. Two handovers (LiFi→WiFi at t=5 s; WiFi→LiFi at t=10 s) at 5 ms insecure latency. |
| **S1: Attack, No Defense** | `--scenario=1` | All 9 attacks active; blockchain disabled. All handovers unconditionally approved via `InsecureHandover()` at 5 ms. Measures maximum attack damage. |
| **S2: Attack + BA-SAH** | `--scenario=2` | All 9 attacks active; blockchain enabled. All requests processed through the full 6-step BA-SAH protocol. Measures defense effectiveness. |

### 3. Blockchain Modules

#### FabricLedger (`fabric-ledger.h / fabric-ledger.cc`)

Implements two storage layers:

- **World State:** `std::map<string, ApTrustRecord>` keyed by AP ID. Each record stores trust score [0.0–1.0], registration flag, handover/rejection counts, organisation ID, and timestamp. Trust updates are applied at block commit: +0.005 per APPROVED, −0.010 per DENIED.
- **Block Store:** Append-only `std::vector<FabricBlock>`. Each block carries a deterministic XOR-fold hash of its transactions linked to the previous block hash. A genesis block (`blockHash = "GENESIS_BLOCK_HASH"`, `prevHash = "0000000000000000"`) anchors the chain at initialisation.

#### FabricChaincode (`fabric-chaincode.h / fabric-chaincode.cc`)

Three smart contracts:

**ApRegistryChaincode:** `RegisterAP()` / `RevokeAP()` / `IsRegistered()` — manages the trusted AP list with soft-delete semantics (revocation sets `registered=false`; re-registration restores).

**HandoverPolicyChaincode:** Core decision engine.
```cpp
// RSSI normalisation: [-90, -40] dBm → [0.0, 1.0]
double sRssi = (rssiDbm + 90.0) / 50.0;  // clamped

// Energy normalisation: higher cost → lower score
double sEnergy = 1.0 - costMj / budgetMj; // clamped [0,1]

// Composite score
double S = 0.50 * S_trust + 0.30 * sRssi + 0.20 * sEnergy;

// Decision
verdict = (S >= 0.55) ? "APPROVED" : "DENIED";
```
Blockchain latency is modelled as a sum of five independent uniform random variables (endorsement RTT, chaincode execution, orderer submit, Raft ordering, block delivery), producing a total range of ~80–295 ms per call.

**EnergyChaincode:** Per-handover energy accounting.
- LiFi: `P_total = 50 + 150 × scaleFactor` mW (scaleFactor derived from optical SNR)
- WiFi: `P_total = 100 + P_out / 0.35` mW (PA efficiency 35%)
- BC overhead: `3 × 1.0 + 0.2 + 1.0 = 4.2 mJ` per transaction (3 endorsers + network + orderer)

#### FabricOrderer (`fabric-orderer.h`)

Raft consensus batching:
- **Batch size:** 10 transactions (MaxMessageCount, matching Hyperledger Fabric default)
- **Batch timeout:** 2000 ms (BatchTimeout)
- **Raft latency model:** `U[60, 180]` ms steady-state (leader already elected)
- Batch fills quickly → minimum latency (~93 ms); timeout-triggered batch → maximum latency (~282 ms)

#### FabricClient (`fabric-client.h`)

Single SDK entry point. `RequestHandover(src, tgt, RSSI, energy)` internally:
1. Calls `HandoverPolicyChaincode::EvaluateHandover()`
2. Builds a `TxRecord` with simulated endorsements from Peer0-Org1, Peer1-Org2, Peer2-Org3
3. Submits to `FabricOrderer::SubmitTransaction()`
4. Updates min/max latency statistics
5. Returns `HandoverVerdict` to caller

### 4. Nine-Attack Implementation

All attacks are implemented in `fabric-attacks-v2.h`. Each class has `Start()`, `Stop()`, and `GetStats()` methods and accepts a `blockchainEnabled` flag. Six correctness fixes were applied during the development cycle (see file header for details).

| ID | Class | Mechanism | BC Defense | 
|----|-------|-----------|------------|
| A1 | `LifiBlockageAttack` | 4-stage error decay; HO trigger at ε=0.15 | Registry-validated fallback |
| A2 | `RogueApAttack` | Beacon every 1.024 s; spoofed RSSI=−40 dBm | Registry lookup fails (not registered) |
| A3 | `MitmAttack` | 40% `RateErrorModel` on server-receive interface | Audit trail only (data-plane) | 
| A4 | `DowngradeAttack` | Temporarily revokes LegitWiFiAP | Registry revocation → DENIED |
| A5 | `ReplayAttack` | Captured nonce at t≈0; replayed at t=31 s (age=31 s > 30 s window) | Timestamp expiry + nonce registry |
| A6 | `SybilAttack` | 15 fake APs from AttackerOrg; rate limit=5/min | Rate limit + trust score=0.05 → S=0.525 < 0.55 |
| A7 | `DoSBlockchainAttack` | 300 real TX injected at 50/s via `RequestHandover()` | 35.9% latency increase; no service failure |
| A8 | `ByzantinePeerAttack` | Peer-0 votes opposite to honest peers | 2-of-3 majority overrides dishonest vote |
| A9 | `SessionHijackAttack` | ARP spoofing post-handover; P_detect=0.85 | Audit trail fingerprint mismatch → re-auth |

**Attack timing schedule (60 s simulation window):**

| Attack | Start (s) | Stop (s) |
|--------|-----------|----------|
| A1 LiFi Blockage | 5 | 10 |
| A2 Rogue AP | 12 | 17 |
| A3 MITM | 19 | 24 |
| A4 Downgrade | 26 | 29 |
| A5 Replay | 31 | 34 |
| A6 Sybil | 36 | 39 |
| A7 DoS-BC | 41 | 47 |
| A8 Byzantine | 49 | 52 |
| A9 Session Hijack | 54 | 58 |

### 5. Raspberry Pi Prototype

The prototype mirrors the simulation protocol in Python, running as five REST-communicating processes:

**`blockchain_node.py`** (port 5001) — six-step decision engine backed by SQLite:

| SQLite Table | Role |
|-------------|------|
| `ap_registry` | World state: trust, registered flag, approved/rejected counts |
| `ledger` | All transactions with score, latency, energy, block reference |
| `blocks` | Block headers with SHA-256 hash chain |
| `seen_nonces` | 30-second rolling window replay protection |
| `rate_log` | Per-org registration rate limiting (max 5/min) |

Configuration (extracted from source):
```python
W_TRUST          = 0.50
W_RSSI           = 0.30
W_ENERGY         = 0.20
THRESHOLD        = 0.55
N_PEERS          = 3          # Raft simulation
BYZANTINE_PROB   = 0.0        # set > 0 for Byzantine simulation
CONSENSUS_MIN_MS = 93
CONSENSUS_MAX_MS = 282
REPLAY_WINDOW_S  = 30
RATE_LIMIT_PER_MIN = 5
```

**`lifi_ap.py`** (port 5002) — LiFi AP emulator with 4-stage blockage model matching ns-3 simulation. Natural signal variation ±0.02 dBm added via background thread. Handover trigger at `error_rate ≥ 0.15`.

**`wifi_ap.py`** (port 5003) — WiFi AP emulator. Manages real-time connection state and rogue AP injection (`POST /rogue/inject`) with configurable spoofed RSSI.

**`ue_simulator.py`** — Autonomous UE agent polling LiFi signal every 2 seconds. Supports three run modes: continuous monitoring, single attack (`--attack N`), full demo (`--demo`).

**`dashboard.py`** (port 5000) — Flask web dashboard with live auto-refresh (3 s interval). Displays blockchain statistics, AP trust registry with visual trust bars, radio signal status, attack simulation buttons (A1–A9 + full demo), and a scrollable live handover log.

### 6. Statistical Methodology

All results are reported over `N=10` independent simulation runs. Per-scenario RNG seeds are set as `seed = runId × 7 + 3` to ensure reproducibility. Confidence intervals use the Student's t-distribution with ν=9 degrees of freedom:

```
CI = x̄ ± (t_{0.025,9} × s) / √10 = x̄ ± 2.262 × s / √10
```

Statistical computation is handled by `analysis/analyze_stats.py`, which reads per-run CSV output and produces mean, standard deviation, and 95% CI for all reported metrics.

---

## Installation

### Layer 1 — ns-3 Simulation

**System requirements:**
- Ubuntu 20.04 / 22.04 / Kali Linux (tested)
- ns-3 version 3-dev (C++23 build)
- CMake ≥ 3.16
- GCC/G++ ≥ 10
- Python ≥ 3.8 (for `analyze_stats.py`)

```bash
# Step 1: Clone into ns-3 scratch directory
cd ~/ns-3-dev/scratch
git clone https://github.com/AmritaCSN/BA-SAH-LiFi-WiFi-Blockchain.git hybrid-project

# Step 2: Create required output directories
mkdir -p ~/ns-3-dev/results/logs
mkdir -p ~/ns-3-dev/results/xml
mkdir -p ~/ns-3-dev/results/pcap

# Step 3: Build
cd ~/ns-3-dev
./ns3 configure
./ns3 build

# Step 4: Verify build
./ns3 run "scratch/hybrid-project/hybrid_full_v5 --scenario=0 --simTime=10"
```

> **Important:** `Fabric-metrics-v2.h` must be present as `fabric-metrics.h` (lowercase) in the simulation directory. If cloned with the capital-F filename, rename it:
> ```bash
> mv Fabric-metrics-v2.h fabric-metrics.h
> ```

### Layer 2 — Raspberry Pi Prototype

**Hardware requirements:**
- Raspberry Pi 4 Model B, 4 GB RAM
- Raspberry Pi OS 64-bit (Debian Bookworm)
- Python 3.11

```bash
# Step 1: Clone repository
git clone https://github.com/AmritaCSN/BA-SAH-LiFi-WiFi-Blockchain.git
cd BA-SAH-LiFi-WiFi-Blockchain/prototype

# Step 2: Install dependencies
pip3 install flask requests --break-system-packages
# or use setup.sh for a full environment setup:
bash setup.sh

# Step 3: Prepare runtime directories
mkdir -p logs
chmod +x run_all.sh setup.sh

# Step 4: Verify health
python3 blockchain_node.py &
sleep 2
curl http://127.0.0.1:5001/health
# Expected: {"node":"blockchain_node","port":5001,"status":"ok"}
pkill -f blockchain_node.py
```

---

## Usage

### Running the Three-Scenario Evaluation (ns-3)

```bash
cd ~/ns-3-dev

# Scenario 0: Clean baseline — no attacks, no blockchain
./ns3 run "scratch/hybrid-project/hybrid_full_v5 --scenario=0 --simTime=60"

# Scenario 1: All 9 attacks, blockchain DISABLED (insecure baseline)
./ns3 run "scratch/hybrid-project/hybrid_full_v5 --scenario=1 --simTime=60"

# Scenario 2: All 9 attacks, blockchain ENABLED (BA-SAH defense)
./ns3 run "scratch/hybrid-project/hybrid_full_v5 --scenario=2 --simTime=60"
```

### Configurable Parameters

| Parameter | Flag | Default | Description |
|-----------|------|---------|-------------|
| Scenario | `--scenario` | `0` | 0=baseline, 1=attack no BC, 2=attack+BC |
| Simulation duration | `--simTime` | `60` | Seconds |
| Statistical run ID | `--runId` | `1` | RNG seed = `runId × 7 + 3` |
| Verbose ns-3 logging | `--verbose` | `false` | Enables `NS_LOG` component output |

### Statistical Validation (10 Independent Runs)

```bash
cd ~/ns-3-dev

for i in $(seq 1 10); do
  echo "=== Run ${i}/10 ==="
  ./ns3 run "scratch/hybrid-project/hybrid_full_v5 --scenario=0 --runId=${i} --simTime=60"
  ./ns3 run "scratch/hybrid-project/hybrid_full_v5 --scenario=1 --runId=${i} --simTime=60"
  ./ns3 run "scratch/hybrid-project/hybrid_full_v5 --scenario=2 --runId=${i} --simTime=60"
done

# Compute statistics
cd results
python3 ../scratch/hybrid-project/analysis/analyze_stats.py
```

### Automated Full Experiment Suite

```bash
bash simulation/run_experiments.sh          # 30 runs (10 per scenario)
bash simulation/run_experiments.sh --quick  # 3 runs (1 per scenario, fast check)
```

### Raspberry Pi Prototype

```bash
# Start all 5 processes
cd prototype/
./run_all.sh

# Open dashboard from any browser on the same network:
# http://<pi-ip-address>:5000

# Check Pi IP:
hostname -I | awk '{print $1}'
```

### Hardware Protocol Verification (4 curl Tests)

Run these on the Pi terminal after `./run_all.sh` with a fresh ledger (`rm -f ledger.db` first):

```bash
# Test 1: Legitimate handover → APPROVED (~100–280 ms latency)
curl -X POST http://127.0.0.1:5001/handover \
  -H "Content-Type: application/json" \
  -d '{"source_ap":"LiFiAP","target_ap":"LegitWiFiAP","rssi_dbm":-62,"energy_mj":500,"nonce":"verify-001"}'

# Test 2: Rogue AP → DENIED (not registered)
curl -X POST http://127.0.0.1:5001/handover \
  -H "Content-Type: application/json" \
  -d '{"source_ap":"LiFiAP","target_ap":"RogueAP","rssi_dbm":-40,"energy_mj":500,"nonce":"verify-002","attack_type":"rogue_ap"}'

# Test 3: Replay (fresh nonce) → APPROVED
curl -X POST http://127.0.0.1:5001/handover \
  -H "Content-Type: application/json" \
  -d '{"source_ap":"LiFiAP","target_ap":"LegitWiFiAP","rssi_dbm":-62,"energy_mj":500,"nonce":"replay-001"}'

# Test 4: Replay (same nonce) → DENIED in 5 ms (fast-path)
curl -X POST http://127.0.0.1:5001/handover \
  -H "Content-Type: application/json" \
  -d '{"source_ap":"LiFiAP","target_ap":"LegitWiFiAP","rssi_dbm":-62,"energy_mj":500,"nonce":"replay-001"}'
```

**Expected responses:**
- Test 1: `"decision":"APPROVED"`, `"score":~0.825`, latency 100–280 ms
- Test 2: `"decision":"DENIED"`, `"reason":"Target AP not registered: RogueAP"`
- Test 3: `"decision":"APPROVED"`, nonce recorded in `seen_nonces`
- Test 4: `"decision":"DENIED"`, `"latency_ms":5.0`, `"reason":"Replay detected — nonce already used"`

### Individual Attack Triggers (Prototype)

```bash
cd prototype/

python3 ue_simulator.py --attack 1   # A1: LiFi Blockage
python3 ue_simulator.py --attack 2   # A2: Rogue AP
python3 ue_simulator.py --attack 3   # A3: MITM
python3 ue_simulator.py --attack 4   # A4: Downgrade
python3 ue_simulator.py --attack 5   # A5: Replay
python3 ue_simulator.py --attack 6   # A6: Sybil (15 fake APs)
python3 ue_simulator.py --attack 7   # A7: DoS-BC (50 TX flood)
python3 ue_simulator.py --attack 8   # A8: Byzantine peer
python3 ue_simulator.py --attack 9   # A9: Session Hijack
python3 ue_simulator.py --demo       # Full 9-attack sequence (3 s gaps)
```

---

## Experimental Setup

### Simulation Parameters

| Parameter | Value |
|-----------|-------|
| Simulator | ns-3 version 3-dev (C++23) |
| Simulation duration | 60 s |
| UDP packet size | 1024 bytes |
| UDP send interval | 10 ms (nominal 0.842 Mbps) |
| LiFi data rate | 200 Mbps |
| LiFi propagation delay | 1 ms |
| WiFi standard | 802.11ac (5 GHz) |
| Backhaul data rate | 1 Gbps |
| Backhaul delay | 2 ms |
| BC batch size | 10 TX (MaxMessageCount) |
| BC batch timeout | 2000 ms (BatchTimeout) |
| Approval threshold θ | 0.55 |
| Weight vector (w_t, w_r, w_e) | (0.50, 0.30, 0.20) |
| Replay window | 30 s |
| Rate limit | 5 registrations/min/org |
| Statistical runs N | 10 |
| RNG seed formula | seed = runId × 7 + 3 |
| t-distribution (95% CI) | t_{0.025,9} = 2.262 |

### Evaluation Metrics

| Category | Metrics |
|----------|---------|
| Network (FlowMonitor) | Throughput (Mbps), E2E delay (ms), packet loss (%) |
| Blockchain | Total TX, approved/denied counts, block height, avg/min/max latency (ms) |
| Energy | Total handover energy (mJ), avg per-handover energy (mJ), energy saving (%) |
| Security | Per-attack: attempts, blocked count, handover succeeded, defense result |
| Scalability | Latency under DoS load, graceful degradation |

### Hardware Configuration (Prototype)

| Component | Specification |
|-----------|--------------|
| Platform | Raspberry Pi 4 Model B |
| RAM | 4 GB LPDDR4 |
| CPU | ARM Cortex-A72, 1.8 GHz quad-core |
| Storage | MicroSD (SQLite ledger) |
| OS | Raspberry Pi OS 64-bit (Debian Bookworm) |
| Runtime | Python 3.11, Flask 3.0.3 |
| Network | wlan0 (IEEE 802.11) |
| Dashboard access | `http://172.20.10.9:5000` (lab network) |

---

## Results

### Three-Scenario Network Performance (N=10 runs, mean ± std dev)

| Metric | S0: Baseline | S1: Attack, No BC | S2: Attack + BA-SAH |
|--------|-------------|-------------------|---------------------|
| Throughput (Mbps) | 0.842 ± 0.000 | 0.795 ± 0.000 | 0.796 ± 0.002 |
| E2E delay (ms) | 6.091 ± 0.001 | 6.091 ± 0.001 | 6.091 ± 0.001 |
| Packet loss (%) | 0.000 ± 0.000 | 5.573 ± 0.068 [CI ±0.049] | 5.391 ± 0.263 [CI ±0.188] |
| HO latency (ms) | 5.00 | 5.00 | 187.92 ± 1.93 [CI ±1.38] |
| BC latency min (ms) | — | — | 97.39 ± 3.39 |
| BC latency max (ms) | — | — | 276.67 ± 4.37 |
| DoS-load latency (ms) | — | 5.00 | 176.66 ± 49.96 [CI ±35.74] |
| Total energy (mJ) | 1.00 | 4896.45 ± 4.90 | 1345.20 ± 0.00 |
| **Energy saving (%)** | — | — | **72.527 ± 0.028 [CI ±0.020]** |

> **Key observation on E2E delay:** The 6.091 ms delay is identical across all three scenarios, confirming that blockchain consensus operates exclusively at the control plane without affecting data-plane latency.

### Blockchain Performance (Scenario 2, N=10)

| Metric | Value |
|--------|-------|
| Total TX submitted | 315.9 ± 0.32 (316 in 9 runs; 315 in Run 3†) |
| TX approved | 3.9 ± 0.32 |
| TX denied | **312.0 ± 0.00 (perfectly deterministic)** |
| Block height | 36.9 ± 0.32 |
| Avg BC latency (ms) | 187.92 ± 1.93 [CI ±1.38] |
| Min BC latency (ms) | 97.39 ± 3.39 |
| Max BC latency (ms) | 276.67 ± 4.37 |
| DoS latency overhead | +35.9% (vs 130 ms nominal) |
| LiFiAP trust (final) | 1.000 (no rejections) |
| LegitWiFiAP trust (final) | 0.965 (temporary A4 revocation) |
| SybilAP\_1–5 trust | 0.040 (well below 0.55 threshold) |

> †Run 3: Session Hijack P_miss = 0.15 occurred (1–2 misses expected over 10 runs, confirming genuine probabilistic behaviour).

### Attack Mitigation Results (Scenario 2, cumulative over 10 runs)

| ID | Attack | Attempts | Blocked | Block Rate | Result |
|----|--------|----------|---------|------------|--------|
| A1 | LiFi Blockage | 10 | 0 | — | FULLY_MITIGATED (legit fallback approved) |
| A2 | Rogue AP | 50 | 50 | 100% | FULLY_MITIGATED |
| A3 | MITM | 10 | 0 | — | **PARTIAL** (data-plane; correct) |
| A4 | Downgrade | 10 | 10 | 100% | FULLY_MITIGATED |
| A5 | Replay | 20 | 10 | 50%† | FULLY_MITIGATED |
| A6 | Sybil | 150 | 150 | 100% | FULLY_MITIGATED |
| A7 | DoS-BC | 3000 | 0 | — | **PARTIAL** (35.9% latency increase) |
| A8 | Byzantine | 10 | 10 | 100% | FULLY_MITIGATED |
| A9 | Session Hijack | 10 | 9 | 90% | FULLY_MITIGATED |

> †Replay: 10 attempts blocked by timestamp expiry (age > 30 s); 10 in-window but nonce consumed. Both defenses activated per design.

**7 of 9 attacks FULLY_MITIGATED.** MITM and DoS-BC are correctly PARTIAL: MITM drops packets at the data plane (beyond blockchain's control-plane scope); DoS-BC increases latency by 35.9% without service failure (graceful degradation).

### Composite Score Validation

```
LegitWiFiAP (rssi=−62 dBm, trust=0.965):
  S = 0.50×0.965 + 0.30×0.5429 + 0.20×0.900
    = 0.4825 + 0.1629 + 0.1800 = 0.8254 → APPROVED ✓

SybilAP (trust=0.05, best-case RSSI=1.0, energy=1.0):
  S = 0.50×0.05 + 0.30×1.0 + 0.20×1.0
    = 0.025 + 0.300 + 0.200 = 0.525 < 0.55 → DENIED ✓ (always)
```

### Simulation–Hardware Validation

| Metric | ns-3 Simulation (N=10) | Raspberry Pi 4 | Verdict |
|--------|----------------------|----------------|---------|
| Minimum latency | 97.39 ms | 110.58 ms | Within range ✓ |
| Average latency | 187.92 ± 1.93 ms | ~165 ms (3 test cases) | Within range ✓ |
| Maximum latency | 276.67 ms | 228.14 ms | Within range ✓ |
| Pre-consensus denial | 5.00 ms | 5.00 ms | **Exact match** ✓ |
| Composite score | 0.8254 (formula) | 0.8254 (API response) | **Exact match** ✓ |
| Decision correctness | 7/9 attacks mitigated | 7/9 protocols verified | Consistent ✓ |

---

## Reproducibility Guide

The following workflow reproduces all reported results from scratch.

### Step 1: Environment Setup

```bash
# ns-3 simulation environment
cd ~/ns-3-dev/scratch
git clone https://github.com/AmritaCSN/BA-SAH-LiFi-WiFi-Blockchain.git hybrid-project
mkdir -p ~/ns-3-dev/results/{logs,xml,pcap}
cd ~/ns-3-dev && ./ns3 configure && ./ns3 build
```

### Step 2: Quick Functional Verification (3 runs, ~6 min)

```bash
cd ~/ns-3-dev
./ns3 run "scratch/hybrid-project/hybrid_full_v5 --scenario=0 --simTime=60"
./ns3 run "scratch/hybrid-project/hybrid_full_v5 --scenario=1 --simTime=60"
./ns3 run "scratch/hybrid-project/hybrid_full_v5 --scenario=2 --simTime=60"
```

Verify outputs:
```bash
cat ~/ns-3-dev/results/attack_summary.csv     # Expect 7 FULLY_MITIGATED
cat ~/ns-3-dev/results/energy_comparison.csv  # Expect ~4896 vs ~1345 mJ
cat ~/ns-3-dev/results/latency_comparison.csv # Expect 5.00 vs ~187 ms
```

### Step 3: Full Statistical Validation (30 runs, ~10–20 min)

```bash
cd ~/ns-3-dev
for i in $(seq 1 10); do
  ./ns3 run "scratch/hybrid-project/hybrid_full_v5 --scenario=0 --runId=${i} --simTime=60"
  ./ns3 run "scratch/hybrid-project/hybrid_full_v5 --scenario=1 --runId=${i} --simTime=60"
  ./ns3 run "scratch/hybrid-project/hybrid_full_v5 --scenario=2 --runId=${i} --simTime=60"
done

cd results
python3 ../scratch/hybrid-project/analysis/analyze_stats.py
```

Expected statistical outputs in `results/stats_output/`:
- `table2_network.csv` — Three-scenario network performance (mean ± std dev ± CI)
- `table3_attacks.csv` — Attack mitigation summary
- `summary_report.txt` — Full statistical report

**Expected energy saving:** 72.527 ± 0.028% (should be consistent to third decimal place across runs — this is a structural property of the framework, not a statistical artefact).

### Step 4: Hardware Prototype Verification (Raspberry Pi)

```bash
cd prototype/
rm -f ledger.db       # Reset to genesis block
./run_all.sh
sleep 3

# Run 4 verification curl commands (see Usage section)
# Expected: Test 1 APPROVED ~100-280ms, Test 2 DENIED, Test 3 APPROVED, Test 4 DENIED 5ms
```

### Step 5: Validate Simulation–Hardware Consistency

Confirm that all hardware latency measurements fall within the simulation-predicted range of **93.80–282.62 ms**. The 5.00 ms pre-consensus fast-path denial must match exactly.



## Limitations and Future Work

### Current Limitations

1. **Single-user, small-topology evaluation.** The simulation models one UE and one cell. Multi-user scenarios introduce world-state write contention on shared AP trust keys. Empirical characterisation at 10, 50, and 100 concurrent UEs is required before production claims can be made.

2. **Nonce Bloom filter absent.** The within-window nonce reuse attack (A5, second attempt) is caught by explicit set membership check. Production deployments should replace this with a Bloom filter for O(1) amortised lookup at scale.

3. **Emulated LiFi channel.** The blockage model uses a staged error-rate function rather than a full Lambertian radiation channel model (Pathak et al., 2015). More accurate optical channel simulation would improve physical-layer fidelity.

4. **Stage-1 software prototype only.** The Raspberry Pi prototype implements the decision plane in software. Physical LiFi hardware (LED driver + photodetector on GPIO pins) is absent; the LiFi interface is emulated by `lifi_ap.py`.

5. **Static weight vector.** The policy weights `(w_t, w_r, w_e) = (0.50, 0.30, 0.20)` are fixed. No mechanism exists for adaptive weight updating in response to changing adversarial conditions.

6. **No PKI/certificate layer.** AP identity is asserted at registration time by organisation membership only. A production system requires ECDSA-signed AP certificates and a root CA.

### Future Directions

1. **Multi-user scalability study.** Empirical evaluation with 10–100 concurrent UEs to characterise consensus throughput, world-state contention latency, and blockchain TPS limits.

2. **Adaptive federated trust learning.** Replace the static weight vector with a federated learning model updated across distributed AP nodes, or a Bayesian posterior over trust scores.

3. **Stage-3 physical LiFi integration.** GPIO-connected LED transmitter and photodetector on Raspberry Pi for end-to-end optical-RF handover validation. <!-- TODO: cite specific hardware modules when identified -->

4. **Real Hyperledger Fabric deployment.** Replace the ns-3 simulation model with a live Fabric network using Go chaincode, gRPC peers, and a full ordering cluster.

5. **Spent-nonce Bloom filter.** Replace the in-memory `set<string>` nonce registry with a probabilistic data structure to support large-scale deployments.

6. **Mobility model integration.** Incorporate Random Waypoint and Gauss-Markov mobility in ns-3 to evaluate BA-SAH under realistic multi-cell user movement patterns.

7. **Threshold and weight sensitivity sweep.** Systematic parameter sweep over `w_t ∈ [0.40, 0.70]` and `θ ∈ [0.50, 0.65]` to characterise the Sybil resistance boundary and false-rejection rate under degraded channel conditions.

---

## Citation

```bibtex
@article{manideep2026basah,
  title     = {{BA-SAH}: Blockchain-Assisted Security-Aware Handover
               for Energy Optimization in Hybrid {LiFi}--{WiFi} Access Networks},
  author    = {Manideep, Garrepelly and Sankaran, Sriram},
  journal   = {TODO: target journal (e.g., IEEE Transactions on Wireless Communications)},
  volume    = {TODO},
  number    = {TODO},
  pages     = {TODO},
  year      = {2026},
  publisher = {IEEE},
  doi       = {TODO},
  note      = {Center for Cybersecurity Systems and Networks,
               Amrita Vishwa Vidyapeetham, India}
}
```

---

## License and Acknowledgments

### License

This project is released under the **MIT License**. See [`LICENSE`](LICENSE) for details.

### Acknowledgments

- **Institution:** Center for Cybersecurity Systems and Networks, Amrita Vishwa Vidyapeetham, Amritapuri, Kerala, India
- **Guide:** Dr. Sriram Sankaran (`srirams@am.amrita.edu`)
- **Simulation platform:** [ns-3 Network Simulator](https://www.nsnam.org/) (open source, GPLv2)
- **Blockchain architecture reference:** Androulaki et al., *Hyperledger Fabric: A Distributed Operating System for Permissioned Blockchains*, ACM EuroSys 2018
- **Consensus algorithm:** Ongaro and Ousterhout, *In Search of an Understandable Consensus Algorithm (Raft)*, USENIX ATC 2014
- **LiFi channel reference:** Pathak et al., *Visible Light Communication, Networking, and Sensing: A Survey*, IEEE COMST 2015
- **Energy model reference:** Chen et al., *Downlink Performance of Optical Attocell Networks*, IEEE/OSA JLT 2016
- **Prototype hardware:** Raspberry Pi Foundation — Raspberry Pi 4 Model B
- **Web framework:** Flask (BSD License), Requests (Apache 2.0)

---

*This README was generated from source code and validated results. All quantitative claims are reproducible using the instructions in this document.*
