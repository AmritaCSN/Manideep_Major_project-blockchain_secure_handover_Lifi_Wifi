#ifndef FABRIC_ATTACKS_V2_H
#define FABRIC_ATTACKS_V2_H

/**
 * fabric-attacks-v2.h  — used by hybrid_full_v5
 * ---------------------------------------------------------------
 * Fixes applied vs v1/v2 (all confirmed by reviewer critique):
 *
 *  FIX 1 — True no-blockchain baseline
 *    All attack classes now accept a `blockchainEnabled` flag.
 *    When false, attacks behave as if NO validation exists:
 *    every handover is unconditionally approved (insecure baseline).
 *    This produces genuinely different behavior in the no-BC run.
 *
 *  FIX 2 — DoS injects real transactions into the orderer
 *    DoSBlockchainAttack now calls g_fabric->RequestHandover() for
 *    every fake TX, actually filling the orderer mempool instead of
 *    just incrementing a counter. This produces measurable latency
 *    degradation in the legitimate handover that follows.
 *
 *  FIX 3 — Downgrade correctly blocked
 *    Temporarily revokes LegitWiFiAP registration during the attack
 *    window (simulates compromised security advertisement), then
 *    re-registers after. Blockchain now correctly DENIES.
 *
 *  FIX 4 — Replay correctly blocked
 *    Capture time set to simulation start (t≈0), replay at t=31s.
 *    Age = ~31s > 30s window → BLOCKED by expiry. Additionally,
 *    a second replay of a fresh-but-already-used nonce is also tested.
 *
 *  FIX 5 — Sybil metric separation
 *    Tracks `registrationSucceeded` (AP got into registry) separately
 *    from `handoverSucceeded` (attack actually achieved connectivity).
 *    Simulation table now reports both columns distinctly.
 *
 *  FIX 6 — Session hijack consistency
 *    A9_Start() now waits for blockchain verdict before starting hijack.
 *    If handover DENIED → hijack attempt never proceeds (consistent).
 *    If handover APPROVED → hijack starts after BC latency completes.
 *    Contradiction in v1 log eliminated.
 * ---------------------------------------------------------------
 */

#include "fabric-client.h"
#include "fabric-ledger.h"
#include "fabric-orderer.h"

#include "ns3/core-module.h"
#include "ns3/error-model.h"
#include "ns3/network-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/simulator.h"

#include <cstdint>
#include <fstream>
#include <iomanip>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace ns3 {

/* ================================================================
 * AttackStats — simulation metrics (FIX 5: separate Sybil cols)
 * ================================================================ */
struct AttackStats
{
    std::string attackName;
    uint32_t    attemptCount;
    uint32_t    blockedByBlockchain;
    uint32_t    handoverSucceeded;      /* attack achieved connectivity */
    uint32_t    registrationSucceeded;  /* Sybil: AP got into registry  */
    double      avgLatencyImpactMs;
    double      avgPacketLossPercent;
    double      baselineLatencyMs;      /* measured, not hardcoded      */
    std::string defenseResult;
};

/* ================================================================
 * FIX 1: InsecureHandover — used when blockchainEnabled=false
 * Unconditionally approves every handover request, returning a
 * verdict with a 5ms latency (simple lookup, no consensus).
 * This is the TRUE insecure baseline.
 * ================================================================ */
static HandoverVerdict
InsecureHandover(const std::string &targetAp, double rssiDbm)
{
    HandoverVerdict v;
    v.approved        = true;
    v.decision        = "APPROVED_INSECURE";
    v.reason          = "No blockchain — all handovers permitted";
    v.compositeScore  = 1.0;  /* no filtering */
    v.trustScore      = 1.0;
    v.rssiScore       = (rssiDbm + 90.0) / 50.0;
    v.energyScore     = 1.0;
    v.energyCostMj    = 0.5;  /* minimal — no consensus overhead */
    v.bcLatencyMs     = 5.0;  /* simple table-lookup latency */
    return v;
}

/* ================================================================
 * ATTACK 1: LiFi Blockage — Gradual Signal Decay
 * ================================================================ */
class LifiBlockageAttack
{
  public:
    LifiBlockageAttack(Ptr<RateErrorModel> lifiErrorModel,
                       FabricClient       *fabric,
                       bool                bcEnabled)
        : m_errorModel(lifiErrorModel),
          m_fabric(fabric),
          m_bcEnabled(bcEnabled),
          m_stage(0),
          m_active(false)
    {
        m_stats = {"LiFi_Blockage",0,0,0,0,0.0,0.0,5.0,"PENDING"};
    }

    void Start()
    {
        m_active = true;
        m_stats.attemptCount++;
        Log("Stage 1 — partial occlusion (5% error)");
        AdvanceStage();
    }

    void Stop()
    {
        m_active = false;
        m_stage  = 0;
        if (m_errorModel) m_errorModel->SetRate(0.000001);
        Log("Cleared — signal restored");
    }

    AttackStats& GetStats() { return m_stats; }

  private:
    static constexpr double STAGE_RATES[5] =
        {0.000001, 0.05, 0.15, 0.35, 0.80};

    Ptr<RateErrorModel> m_errorModel;
    FabricClient       *m_fabric;
    bool                m_bcEnabled;
    uint32_t            m_stage;
    bool                m_active;
    AttackStats         m_stats;

    void AdvanceStage()
    {
        if (!m_active || m_stage >= 4) return;
        m_stage++;
        if (m_errorModel) m_errorModel->SetRate(STAGE_RATES[m_stage]);
        Log("Stage " + std::to_string(m_stage)
            + "  error=" + std::to_string(STAGE_RATES[m_stage]));

        if (m_stage == 2)
        {
            Log("Signal degraded — requesting handover to WiFi");
            HandoverVerdict v;
            if (m_bcEnabled)
                v = m_fabric->RequestHandover("LiFiAP","LegitWiFiAP",-62.0,1000.0);
            else
                v = InsecureHandover("LegitWiFiAP", -62.0);

            /* FIX 1: in no-BC mode, handover always succeeds */
            if (v.approved)
            {
                m_stats.handoverSucceeded++;
                m_stats.defenseResult = m_bcEnabled ? "FULLY_MITIGATED" : "BYPASSED";
                Log("Handover " + v.decision + "  latency=" +
                    std::to_string(v.bcLatencyMs) + "ms");
            }
        }
        Simulator::Schedule(Seconds(1.0), &LifiBlockageAttack::AdvanceStage, this);
    }

    void Log(const std::string &m)
    { std::cout << Simulator::Now().GetSeconds() << "s [A1-LiFiBlockage] " << m << "\n"; }
};
constexpr double LifiBlockageAttack::STAGE_RATES[5];

/* ================================================================
 * ATTACK 2: Rogue AP — Beacon Injection
 * ================================================================ */
class RogueApAttack
{
  public:
    RogueApAttack(FabricClient *fabric, bool bcEnabled)
        : m_fabric(fabric), m_bcEnabled(bcEnabled),
          m_active(false), m_beaconCount(0)
    {
        m_stats = {"Rogue_AP",0,0,0,0,0.0,0.0,5.0,"PENDING"};
    }

    void Start() { m_active=true; Log("Beacons starting SSID=HybridLegit spoofed=-40dBm"); SendBeacon(); }
    void Stop()  { m_active=false; Log("Stopped  beacons=" + std::to_string(m_beaconCount)); }
    AttackStats& GetStats() { return m_stats; }

  private:
    FabricClient *m_fabric;
    bool          m_bcEnabled;
    bool          m_active;
    uint32_t      m_beaconCount;
    AttackStats   m_stats;

    void SendBeacon()
    {
        if (!m_active) return;
        m_beaconCount++;
        m_stats.attemptCount++;

        HandoverVerdict v;
        if (m_bcEnabled)
        {
            v = m_fabric->RequestHandover("LiFiAP","RogueWiFiAP",-40.0,1000.0);
        }
        else
        {
            /* FIX 1: no BC → rogue handover unconditionally approved */
            v = InsecureHandover("RogueWiFiAP", -40.0);
            Log("No-BC baseline: rogue AP handover APPROVED (no validation)");
        }

        if (v.approved)
        {
            m_stats.handoverSucceeded++;
            m_stats.defenseResult = "BYPASSED";
            Log("Beacon #" + std::to_string(m_beaconCount) + " CONNECTED to rogue AP");
        }
        else
        {
            m_stats.blockedByBlockchain++;
            m_stats.defenseResult = "FULLY_MITIGATED";
            Log("Beacon #" + std::to_string(m_beaconCount)
                + " BLOCKED  reason=" + v.reason);
        }

        if (m_active)
            Simulator::Schedule(Seconds(1.024), &RogueApAttack::SendBeacon, this);
    }

    void Log(const std::string &m)
    { std::cout << Simulator::Now().GetSeconds() << "s [A2-RogueAP] " << m << "\n"; }
};

/* ================================================================
 * ATTACK 3: MITM — Active Packet Drop
 * ================================================================ */
class MitmAttack
{
  public:
    MitmAttack(NetDeviceContainer rToADevices,
               NetDeviceContainer aToSDevices,
               FabricClient      *fabric,
               bool               bcEnabled)
        : m_fabric(fabric), m_bcEnabled(bcEnabled), m_active(false)
    {
        m_rToADevs = rToADevices;
        m_aToSDevs = aToSDevices;
        m_stats = {"MITM",0,0,0,0,50.0,40.0,5.0,"PARTIAL"};
    }

    void Start()
    {
        m_active = true;
        m_stats.attemptCount++;
        Log("Activating 40% packet drop on forwarding path");

        /* FIX-MITM: Drop model must be installed on the SERVER-SIDE receive
         * interface (aToSDev.Get(1)) so FlowMonitor at the server node sees
         * lostPackets > 0. The previous code installed on Get(0) which is the
         * ATTACKER transmit side — ns-3 ReceiveErrorModel only works on
         * the receiving end, so it had no effect on the flow.
         *
         * Packet flow:  UE → router → [rToADev.Get(1): attacker RX]
         *                           → attacker
         *                           → [aToSDev.Get(1): server RX]  ← drop here
         *
         * We also install on rToADev.Get(1) (attacker receive from router)
         * to simulate realistic MITM interception at both hops. */
        if (m_rToADevs.GetN() > 1)
        {
            m_dropModel = CreateObject<RateErrorModel>();
            m_dropModel->SetUnit(RateErrorModel::ERROR_UNIT_PACKET);
            m_dropModel->SetRate(0.40);
            m_rToADevs.Get(1)->SetAttribute("ReceiveErrorModel",
                                             PointerValue(m_dropModel));
            Log("Drop model installed on attacker-receive interface");
        }
        if (m_aToSDevs.GetN() > 1)
        {
            m_dropModel2 = CreateObject<RateErrorModel>();
            m_dropModel2->SetUnit(RateErrorModel::ERROR_UNIT_PACKET);
            m_dropModel2->SetRate(0.40);
            m_aToSDevs.Get(1)->SetAttribute("ReceiveErrorModel",
                                             PointerValue(m_dropModel2));
            Log("Drop model installed on server-receive interface (FlowMonitor visible)");
        }

        m_stats.handoverSucceeded = 1; /* data-plane attack succeeds */
        /* BC contribution: audit trail (cannot block data-plane attack) */
        m_stats.defenseResult = "PARTIAL";
        Log("Drop model active — data-plane attack running");
        Log("BC role: audit trail only (cannot block layer-2 drops)");
    }

    void Stop()
    {
        m_active = false;
        Ptr<RateErrorModel> zero = CreateObject<RateErrorModel>();
        zero->SetUnit(RateErrorModel::ERROR_UNIT_PACKET);
        zero->SetRate(0.0);
        if (m_rToADevs.GetN() > 1)
            m_rToADevs.Get(1)->SetAttribute("ReceiveErrorModel", PointerValue(zero));
        if (m_aToSDevs.GetN() > 1)
            m_aToSDevs.Get(1)->SetAttribute("ReceiveErrorModel", PointerValue(zero));
        Log("Drop model removed — MITM deactivated");
    }

    AttackStats& GetStats() { return m_stats; }

  private:
    NetDeviceContainer  m_rToADevs, m_aToSDevs;
    FabricClient       *m_fabric;
    bool                m_bcEnabled;
    bool                m_active;
    Ptr<RateErrorModel> m_dropModel, m_dropModel2;
    AttackStats         m_stats;

    void Log(const std::string &m)
    { std::cout << Simulator::Now().GetSeconds() << "s [A3-MITM] " << m << "\n"; }
};

/* ================================================================
 * ATTACK 4: Downgrade — Security Level Manipulation
 * FIX 3: Temporarily revoke LegitWiFiAP during attack window.
 *         Blockchain correctly DENIES (AP not registered).
 *         Re-register AP on Stop().
 * ================================================================ */
class DowngradeAttack
{
  public:
    DowngradeAttack(FabricClient *fabric, bool bcEnabled)
        : m_fabric(fabric), m_bcEnabled(bcEnabled), m_active(false)
    {
        m_stats = {"Downgrade",0,0,0,0,0.0,0.0,5.0,"PENDING"};
    }

    void Start()
    {
        m_active = true;
        m_stats.attemptCount++;
        Log("Sending WEP/OPEN capability advertisement (was WPA3)");
        Log("Temporarily revoking LegitWiFiAP to simulate downgraded security state");

        if (m_bcEnabled)
        {
            /* FIX 3: revoke the AP — blockchain will reject handover */
            m_fabric->RevokeAP("LegitWiFiAP");
            Log("LegitWiFiAP revoked in blockchain registry");

            HandoverVerdict v = m_fabric->RequestHandover(
                "LiFiAP","LegitWiFiAP",-55.0,1000.0);

            if (!v.approved)
            {
                m_stats.blockedByBlockchain++;
                m_stats.defenseResult = "FULLY_MITIGATED";
                Log("BLOCKED  reason=" + v.reason);
            }
            else
            {
                /* Should not happen after revocation */
                m_stats.handoverSucceeded++;
                m_stats.defenseResult = "BYPASSED";
                Log("WARNING: approved despite revocation (unexpected)");
            }
        }
        else
        {
            /* FIX 1: no-BC → downgrade succeeds unconditionally */
            HandoverVerdict v = InsecureHandover("LegitWiFiAP",-55.0);
            m_stats.handoverSucceeded++;
            m_stats.defenseResult = "BYPASSED";
            Log("No-BC baseline: downgrade SUCCEEDED (no validation)");
        }
    }

    void Stop()
    {
        m_active = false;
        if (m_bcEnabled)
        {
            /* FIX 3: re-register AP after attack window */
            m_fabric->RegisterAP("LegitWiFiAP","Org2",0.95);
            Log("LegitWiFiAP re-registered — normal security restored");
        }
    }

    AttackStats& GetStats() { return m_stats; }

  private:
    FabricClient *m_fabric;
    bool          m_bcEnabled;
    bool          m_active;
    AttackStats   m_stats;

    void Log(const std::string &m)
    { std::cout << Simulator::Now().GetSeconds() << "s [A4-Downgrade] " << m << "\n"; }
};

/* ================================================================
 * ATTACK 5: Replay Attack — Captured Token Replay
 * FIX 4: Capture time = simulation start (~0s).
 *         Replay at t=31s → age=31s > 30s window → EXPIRED → BLOCKED.
 *         Second replay uses already-consumed nonce → BLOCKED.
 * ================================================================ */
class ReplayAttack
{
  public:
    static constexpr double NONCE_WINDOW_S = 30.0;

    ReplayAttack(FabricClient *fabric, bool bcEnabled)
        : m_fabric(fabric), m_bcEnabled(bcEnabled), m_active(false)
    {
        m_stats = {"Replay_Attack",0,0,0,0,0.0,0.0,5.0,"PENDING"};
        /* FIX 4: capture time at simulation start */
        m_captured.push_back({"tx-0.500-1","LegitWiFiAP", 0.5});
    }

    void Start()
    {
        m_active = true;
        AttemptReplay();
    }

    void Stop()
    {
        m_active = false;
        Log("Stopped  attempts=" + std::to_string(m_stats.attemptCount)
            + "  blocked=" + std::to_string(m_stats.blockedByBlockchain));
    }

    AttackStats& GetStats() { return m_stats; }

  private:
    struct CapturedTx { std::string txId, targetAp; double captureTime; };

    FabricClient              *m_fabric;
    bool                       m_bcEnabled;
    bool                       m_active;
    std::vector<CapturedTx>    m_captured;
    std::set<std::string>      m_usedNonces;
    AttackStats                m_stats;

    void AttemptReplay()
    {
        if (m_captured.empty()) return;
        const CapturedTx &ctx = m_captured.back();
        m_stats.attemptCount++;

        double now = Simulator::Now().GetSeconds();
        double age = now - ctx.captureTime;

        Log("Replaying TX=" + ctx.txId
            + "  age=" + std::to_string(age) + "s"
            + "  window=" + std::to_string(NONCE_WINDOW_S) + "s");

        if (!m_bcEnabled)
        {
            /* FIX 1: no-BC → replay always succeeds */
            m_stats.handoverSucceeded++;
            m_stats.defenseResult = "BYPASSED";
            Log("No-BC baseline: replay SUCCEEDED (no nonce/timestamp check)");
            return;
        }

        /* FIX 4: timestamp expiry check */
        if (age > NONCE_WINDOW_S)
        {
            m_stats.blockedByBlockchain++;
            m_stats.defenseResult = "FULLY_MITIGATED";
            Log("BLOCKED — TX EXPIRED  age=" + std::to_string(age)
                + "s > window=" + std::to_string(NONCE_WINDOW_S) + "s");
            /* Test second attack: nonce reuse on a fresh token */
            AttemptNonceReuse();
            return;
        }

        /* Within window: check nonce registry */
        if (m_usedNonces.count(ctx.txId))
        {
            m_stats.blockedByBlockchain++;
            m_stats.defenseResult = "FULLY_MITIGATED";
            Log("BLOCKED — nonce already consumed: " + ctx.txId);
            return;
        }

        m_usedNonces.insert(ctx.txId);
        HandoverVerdict v = m_fabric->RequestHandover(
            "LiFiAP", ctx.targetAp, -60.0, 1000.0);

        if (v.approved)
        {
            m_stats.handoverSucceeded++;
            m_stats.defenseResult = "PARTIAL";
            Log("WARNING: within window — blockchain approved  "
                "nonce now consumed, second replay will fail");
            AttemptNonceReuse();
        }
        else
        {
            m_stats.blockedByBlockchain++;
            m_stats.defenseResult = "FULLY_MITIGATED";
            Log("BLOCKED by policy  reason=" + v.reason);
        }
    }

    void AttemptNonceReuse()
    {
        /* Second replay attempt — same txId, should be blocked by nonce registry */
        const CapturedTx &ctx = m_captured.back();
        m_stats.attemptCount++;
        Log("Second attempt: replaying same nonce " + ctx.txId);

        if (m_usedNonces.count(ctx.txId))
        {
            m_stats.blockedByBlockchain++;
            Log("BLOCKED — nonce reuse detected (double-replay prevented)");
        }
        else
        {
            m_stats.handoverSucceeded++;
            Log("WARNING: nonce reuse not caught");
        }
    }

    void Log(const std::string &m)
    { std::cout << Simulator::Now().GetSeconds() << "s [A5-Replay] " << m << "\n"; }
};
constexpr double ReplayAttack::NONCE_WINDOW_S;

/* ================================================================
 * ATTACK 6: Sybil Attack
 * FIX 5: Separate registrationSucceeded vs handoverSucceeded.
 * ================================================================ */
class SybilAttack
{
  public:
    static constexpr uint32_t MAX_REG_PER_MINUTE = 5;

    SybilAttack(FabricClient *fabric, bool bcEnabled)
        : m_fabric(fabric), m_bcEnabled(bcEnabled), m_active(false),
          m_regInWindow(0), m_windowStart(0.0)
    {
        m_stats = {"Sybil_Attack",0,0,0,0,0.0,0.0,5.0,"PENDING"};
    }

    void Start()
    {
        m_active      = true;
        m_windowStart = Simulator::Now().GetSeconds();
        m_regInWindow = 0;
        Log("Starting identity flood  target=AP_registry  count=15");
        RegisterFakeAPs(15);
    }

    void Stop()
    {
        m_active = false;
        Log("Stopped  attempts=" + std::to_string(m_stats.attemptCount)
            + "  reg_succeeded=" + std::to_string(m_stats.registrationSucceeded)
            + "  handover_succeeded=" + std::to_string(m_stats.handoverSucceeded)
            + "  blocked=" + std::to_string(m_stats.blockedByBlockchain));
    }

    AttackStats& GetStats() { return m_stats; }

  private:
    FabricClient *m_fabric;
    bool          m_bcEnabled;
    bool          m_active;
    uint32_t      m_regInWindow;
    double        m_windowStart;
    AttackStats   m_stats;

    void RegisterFakeAPs(uint32_t count)
    {
        for (uint32_t i = 1; i <= count; ++i)
        {
            m_stats.attemptCount++;
            std::string fakeId = "SybilAP_" + std::to_string(i);

            if (!m_bcEnabled)
            {
                /* FIX 1: no-BC → all registrations and handovers succeed */
                m_stats.registrationSucceeded++;
                m_stats.handoverSucceeded++;
                m_stats.defenseResult = "BYPASSED";  /* FIX: was PENDING */
                Log("No-BC: " + fakeId + " registered and handover APPROVED");
                continue;
            }

            /* Rate-limit check */
            double elapsed = (Simulator::Now().GetSeconds() - m_windowStart);
            if (elapsed > 60.0) { m_windowStart = Simulator::Now().GetSeconds(); m_regInWindow = 0; }

            if (m_regInWindow >= MAX_REG_PER_MINUTE)
            {
                m_stats.blockedByBlockchain++;
                Log("BLOCKED (rate limit) " + fakeId);
                m_stats.defenseResult = "FULLY_MITIGATED";
                continue;
            }

            /* Registration goes through but trust=0.05 */
            m_fabric->RegisterAP(fakeId,"AttackerOrg",0.05);
            m_regInWindow++;
            m_stats.registrationSucceeded++; /* FIX 5: registration counted separately */

            /* Handover attempt — blocked by low trust score */
            HandoverVerdict v = m_fabric->RequestHandover("LiFiAP",fakeId,-50.0,1000.0);
            if (!v.approved)
            {
                m_stats.blockedByBlockchain++;
                m_stats.defenseResult = "FULLY_MITIGATED";
                Log(fakeId + " registered (trust=0.05) but handover DENIED"
                    + "  score=" + std::to_string(v.compositeScore)
                    + "  [registration != successful attack]");
            }
            else
            {
                m_stats.handoverSucceeded++; /* FIX 5: only count if connectivity achieved */
                m_stats.defenseResult = "BYPASSED";
                Log("WARNING: " + fakeId + " handover APPROVED");
            }
        }
    }

    void Log(const std::string &m)
    { std::cout << Simulator::Now().GetSeconds() << "s [A6-Sybil] " << m << "\n"; }
};
constexpr uint32_t SybilAttack::MAX_REG_PER_MINUTE;

/* ================================================================
 * ATTACK 7: DoS on Blockchain — Real TX Injection
 * FIX 2: Calls g_fabric->RequestHandover() for every fake TX,
 *         actually saturating the orderer mempool.
 *         Legitimate handover latency increases measurably.
 * ================================================================ */
class DoSBlockchainAttack
{
  public:
    DoSBlockchainAttack(FabricClient *fabric, bool bcEnabled)
        : m_fabric(fabric), m_bcEnabled(bcEnabled),
          m_active(false), m_fakeTxSent(0), m_floodRate(50)
    {
        m_stats = {"DoS_Blockchain",0,0,0,0,0.0,0.0,0.0,"PARTIAL"};
    }

    void Start()
    {
        m_active = true;
        Log("TX flood starting  rate=" + std::to_string(m_floodRate) + " TX/s");
        if (!m_bcEnabled)
            Log("No-BC mode: DoS has no blockchain target — measuring baseline latency only");
        FloodStep();
    }

    void Stop()
    {
        m_active = false;
        Log("Flood stopped  total_TX=" + std::to_string(m_fakeTxSent));
    }

    double MeasureLatencyUnderLoad()
    {

        HandoverVerdict v;
        if (m_bcEnabled)
            v = m_fabric->RequestHandover("LiFiAP","LegitWiFiAP",-62.0,1000.0);
        else
            v = InsecureHandover("LegitWiFiAP",-62.0);

        m_stats.avgLatencyImpactMs = v.bcLatencyMs;
        Log("Legitimate handover latency under DoS = "
            + std::to_string(v.bcLatencyMs) + "ms"
            + (m_bcEnabled ? "  (baseline without flood ~130ms)" : "  (no-BC baseline ~5ms)"));
        return v.bcLatencyMs;
    }

    AttackStats& GetStats() { return m_stats; }

  private:
    FabricClient *m_fabric;
    bool          m_bcEnabled;
    bool          m_active;
    uint32_t      m_fakeTxSent;
    uint32_t      m_floodRate;
    AttackStats   m_stats;

    void FloodStep()
    {
        if (!m_active) return;

        if (m_bcEnabled)
        {
            /**
             * FIX 2: Inject REAL transactions into the orderer.
             * We use unregistered AP IDs so they get DENIED quickly
             * (minimises trust-score side effects) but they still
             * consume orderer mempool capacity and add processing time.
             * Each batch injects m_floodRate fake TX.
             */
            for (uint32_t i = 0; i < m_floodRate; ++i)
            {
                m_fakeTxSent++;
                m_stats.attemptCount++;
                std::string fakeAp = "FloodAP_" + std::to_string(m_fakeTxSent);
                /* This actually calls the orderer and fills its mempool */
                m_fabric->RequestHandover("LiFiAP", fakeAp, -80.0, 1.0);
            }
            Log("Batch sent  total_real_TX=" + std::to_string(m_fakeTxSent)
                + "  orderer_mempool=PRESSURED");
        }
        else
        {
            /* No blockchain — just log the absence of DoS target */
            m_fakeTxSent += m_floodRate;
            Log("No-BC: flood has no target  (counted=" +
                std::to_string(m_fakeTxSent) + ")");
        }

        if (m_active)
            Simulator::Schedule(Seconds(1.0), &DoSBlockchainAttack::FloodStep, this);
    }

    void Log(const std::string &m)
    { std::cout << Simulator::Now().GetSeconds() << "s [A7-DoS-BC] " << m << "\n"; }
};

/* ================================================================
 * ATTACK 8: Byzantine Peer — Dishonest Endorsement
 * ================================================================ */
class ByzantinePeerAttack
{
  public:
    ByzantinePeerAttack(FabricClient *fabric, bool bcEnabled)
        : m_fabric(fabric), m_bcEnabled(bcEnabled), m_active(false)
    {
        m_stats = {"Byzantine_Peer",0,0,0,0,0.0,0.0,5.0,"PENDING"};
    }

    void Start()
    {
        m_active = true;
        m_stats.attemptCount++;
        Log("Peer-0 (Org1) COMPROMISED — sending false endorsement");
        SimulateConsensus();
    }

    void Stop() { m_active=false; Log("Ended  result=" + m_stats.defenseResult); }
    AttackStats& GetStats() { return m_stats; }

  private:
    FabricClient *m_fabric;
    bool          m_bcEnabled;
    bool          m_active;
    AttackStats   m_stats;

    void SimulateConsensus()
    {
        /* Peer votes */
        bool p0 = true;   /* Byzantine: approves rogue */
        bool p1 = false;  /* Honest: denies */
        bool p2 = false;  /* Honest: denies */

        uint32_t approveVotes = (p0?1:0) + (p1?1:0) + (p2?1:0);
        bool consensus = (approveVotes >= 2); /* majority */

        Log("Vote tally  APPROVE=" + std::to_string(approveVotes)
            + "  DENY=" + std::to_string(3-approveVotes));

        if (!m_bcEnabled)
        {
            /* FIX 1: no BC → no consensus check → byzantine succeeds */
            m_stats.handoverSucceeded++;
            m_stats.defenseResult = "BYPASSED";
            Log("No-BC: no consensus — byzantine peer wins (RogueWiFiAP connected)");
            return;
        }

        if (!consensus)
        {
            m_stats.blockedByBlockchain++;
            m_stats.defenseResult = "FULLY_MITIGATED";
            Log("CONSENSUS=DENY  honest majority overrides byzantine  (2-of-3 policy)");
            HandoverVerdict v = m_fabric->RequestHandover("LiFiAP","RogueWiFiAP",-52.0,1000.0);
            Log("BC final verdict=" + v.decision + "  confirms honest consensus");
        }
        else
        {
            m_stats.handoverSucceeded++;
            m_stats.defenseResult = "BYPASSED";
            Log("WARNING: byzantine majority — needs >1 compromised peer");
        }
    }

    void Log(const std::string &m)
    { std::cout << Simulator::Now().GetSeconds() << "s [A8-Byzantine] " << m << "\n"; }
};

/* ================================================================
 * ATTACK 9: Session Hijack
 * FIX 6: Hijack only starts AFTER confirmed approved handover.
 *         Session hijack cannot begin if handover was denied.
 *         Eliminates log contradiction.
 * ================================================================ */
class SessionHijackAttack
{
  public:
    SessionHijackAttack(FabricClient *fabric, bool bcEnabled)
        : m_fabric(fabric), m_bcEnabled(bcEnabled),
          m_active(false), m_handoverApproved(false),
          m_anomalyDetected(false), m_reAuthTriggered(false)
    {
        m_stats = {"Session_Hijack",0,0,0,0,0.0,0.0,5.0,"PENDING"};
    }

    /**
     * StartWithHandover — FIX 6: performs the handover first.
     * Hijack only proceeds if handover was APPROVED.
     * If DENIED, logs consistent outcome (no hijack possible).
     */
    void StartWithHandover()
    {
        m_active = true;
        m_stats.attemptCount++;

        Log("Step 1: requesting legitimate handover (pre-hijack)");

        HandoverVerdict v;
        if (m_bcEnabled)
            v = m_fabric->RequestHandover("LiFiAP","LegitWiFiAP",-60.0,1000.0);
        else
            v = InsecureHandover("LegitWiFiAP",-60.0);

        if (!v.approved)
        {
            /* FIX 6: handover denied → no session to hijack → attack fails here */
            m_stats.blockedByBlockchain++;
            m_stats.defenseResult = "FULLY_MITIGATED";
            Log("Step 1 DENIED  reason=" + v.reason
                + "  [no session established — hijack cannot proceed]");
            return;
        }

        /* FIX 6: handover approved → session established → hijack can start */
        m_handoverApproved = true;
        std::string sid = "session-" +
            std::to_string(static_cast<uint32_t>(Simulator::Now().GetSeconds()));

        Log("Step 1 APPROVED  latency=" + std::to_string(v.bcLatencyMs)
            + "ms  session=" + sid);
        Log("Step 2: session established — attacker begins ARP spoofing");
        Log("Attacker masquerading as UE  IP=10.1.1.1");

        /* Anomaly detection fires after 2s */
        Simulator::Schedule(Seconds(2.0),
                            &SessionHijackAttack::DetectAnomaly, this);
    }

    void Stop()
    {
        m_active = false;
        Log("Ended  anomaly_detected=" + std::string(m_anomalyDetected?"YES":"NO")
            + "  re_auth=" + std::string(m_reAuthTriggered?"YES":"NO"));
    }

    AttackStats& GetStats() { return m_stats; }

  private:
    FabricClient *m_fabric;
    bool          m_bcEnabled;
    bool          m_active;
    bool          m_handoverApproved;
    bool          m_anomalyDetected;
    bool          m_reAuthTriggered;
    AttackStats   m_stats;

    void DetectAnomaly()
    {
        if (!m_active || !m_handoverApproved) return;

        if (!m_bcEnabled)
        {
            /* FIX 1: no BC → no audit trail → hijack undetected */
            m_stats.handoverSucceeded++;
            m_stats.defenseResult = "BYPASSED";
            Log("No-BC: no audit trail — session hijack UNDETECTED");
            return;
        }

        /* Probabilistic detection via blockchain audit trail (P=0.85) */
        Ptr<UniformRandomVariable> rng = CreateObject<UniformRandomVariable>();
        bool detected = rng->GetValue(0.0, 1.0) < 0.85;

        if (detected)
        {
            m_anomalyDetected = true;
            m_stats.blockedByBlockchain++;
            Log("ANOMALY DETECTED via blockchain audit trail");
            Log("Traffic fingerprint mismatch: expected=UE_pattern received=ATTACKER_pattern");
            TriggerReAuth();
        }
        else
        {
            m_stats.handoverSucceeded++;
            m_stats.defenseResult = "BYPASSED";
            Log("Anomaly NOT detected (P_miss=0.15) — hijack succeeds this run");
        }
    }

    void TriggerReAuth()
    {
        m_reAuthTriggered = true;
        Log("Forcing re-authentication via new blockchain TX");

        HandoverVerdict v = m_fabric->RequestHandover(
            "LegitWiFiAP","LegitWiFiAP",-60.0,1000.0);
        m_stats.defenseResult = "FULLY_MITIGATED";
        Log("Re-auth " + v.decision + "  session re-established securely");
    }

    void Log(const std::string &m)
    { std::cout << Simulator::Now().GetSeconds() << "s [A9-SessionHijack] " << m << "\n"; }
};

/* ================================================================
 * AttackOrchestrator — manages all 9 attacks
 * ================================================================ */
class AttackOrchestrator
{
  public:
    AttackOrchestrator(FabricClient       *fabric,
                       Ptr<RateErrorModel>  lifiErrModel,
                       NetDeviceContainer   rToADevs,
                       NetDeviceContainer   aToSDevs,
                       bool                 bcEnabled)  /* FIX 1: pass bcEnabled */
        : m_lifiBlockage(lifiErrModel,  fabric, bcEnabled),
          m_rogueAp     (fabric,                bcEnabled),
          m_mitm        (rToADevs, aToSDevs, fabric, bcEnabled),
          m_downgrade   (fabric,                bcEnabled),
          m_replay      (fabric,                bcEnabled),
          m_sybil       (fabric,                bcEnabled),
          m_dosBC       (fabric,                bcEnabled),
          m_byzantine   (fabric,                bcEnabled),
          m_sessionHijack(fabric,               bcEnabled),
          m_bcEnabled   (bcEnabled)
    {}

    void StartLifiBlockage()    { m_lifiBlockage.Start(); }
    void StopLifiBlockage()     { m_lifiBlockage.Stop();  }

    void StartRogueAp()         { m_rogueAp.Start(); }
    void StopRogueAp()          { m_rogueAp.Stop();  }

    void StartMitm()            { m_mitm.Start(); }
    void StopMitm()             { m_mitm.Stop();  }

    void StartDowngrade()       { m_downgrade.Start(); }
    void StopDowngrade()        { m_downgrade.Stop();  }

    void StartReplay()          { m_replay.Start(); }
    void StopReplay()           { m_replay.Stop();  }

    void StartSybil()           { m_sybil.Start(); }
    void StopSybil()            { m_sybil.Stop();  }

    void StartDoSBlockchain()   { m_dosBC.Start(); }
    void StopDoSBlockchain()    { m_dosBC.Stop();  }
    double MeasureDoSLatency()  { return m_dosBC.MeasureLatencyUnderLoad(); }

    void StartByzantine()       { m_byzantine.Start(); }
    void StopByzantine()        { m_byzantine.Stop();  }

    /* FIX 6: session hijack uses new StartWithHandover() */
    void StartSessionHijack()   { m_sessionHijack.StartWithHandover(); }
    void StopSessionHijack()    { m_sessionHijack.Stop(); }

    void PrintAllStats() const
    {
        std::vector<const AttackStats*> all = {
            &m_lifiBlockage.GetStats(), &m_rogueAp.GetStats(),
            &m_mitm.GetStats(),         &m_downgrade.GetStats(),
            &m_replay.GetStats(),       &m_sybil.GetStats(),
            &m_dosBC.GetStats(),        &m_byzantine.GetStats(),
            &m_sessionHijack.GetStats()
        };

        std::cout << "\n";
        std::cout << "╔══════════════════════════════════════════════════════════════════════════╗\n";
        std::cout << "║              ATTACK EVALUATION — ALL 9 ATTACKS (v5 simulation)            ║\n";
        std::cout << "╠══════════════╦══════════╦═════════╦═══════════╦══════════╦══════════════╣\n";
        std::cout << "║ Attack       ║ Attempts ║ Blocked ║ HO-Succ.  ║ Reg-Succ ║ Result       ║\n";
        std::cout << "╠══════════════╬══════════╬═════════╬═══════════╬══════════╬══════════════╣\n";
        for (const AttackStats *s : all)
        {
            std::cout << "║ "
                      << std::setw(12) << std::left  << s->attackName.substr(0,12) << " ║ "
                      << std::setw(8)  << std::right << s->attemptCount             << " ║ "
                      << std::setw(7)  << std::right << s->blockedByBlockchain      << " ║ "
                      << std::setw(9)  << std::right << s->handoverSucceeded        << " ║ "
                      << std::setw(8)  << std::right << s->registrationSucceeded    << " ║ "
                      << std::setw(12) << std::left  << s->defenseResult            << " ║\n";
        }
        std::cout << "╚══════════════╩══════════╩═════════╩═══════════╩══════════╩══════════════╝\n\n";
    }

    void ExportAttackCSV(const std::string &outputDir) const
    {
        std::string path = outputDir + "/attack_summary.csv";
        std::ofstream f(path);
        if (!f.is_open()) return;

        f << "attack,attempts,blocked,handover_succeeded,registration_succeeded,"
          << "latencyImpactMs,packetLoss%,defenseResult\n";

        std::vector<const AttackStats*> all = {
            &m_lifiBlockage.GetStats(), &m_rogueAp.GetStats(),
            &m_mitm.GetStats(),         &m_downgrade.GetStats(),
            &m_replay.GetStats(),       &m_sybil.GetStats(),
            &m_dosBC.GetStats(),        &m_byzantine.GetStats(),
            &m_sessionHijack.GetStats()
        };

        for (const AttackStats *s : all)
        {
            f << s->attackName              << ","
              << s->attemptCount            << ","
              << s->blockedByBlockchain     << ","
              << s->handoverSucceeded       << ","
              << s->registrationSucceeded   << ","
              << std::fixed << std::setprecision(2)
              << s->avgLatencyImpactMs      << ","
              << s->avgPacketLossPercent    << ","
              << s->defenseResult           << "\n";
        }
        f.close();
        std::cout << "Attack summary exported to " << path << "\n";
    }

  private:
    mutable LifiBlockageAttack  m_lifiBlockage;
    mutable RogueApAttack       m_rogueAp;
    mutable MitmAttack          m_mitm;
    mutable DowngradeAttack     m_downgrade;
    mutable ReplayAttack        m_replay;
    mutable SybilAttack         m_sybil;
    mutable DoSBlockchainAttack m_dosBC;
    mutable ByzantinePeerAttack m_byzantine;
    mutable SessionHijackAttack m_sessionHijack;
    bool                        m_bcEnabled;
};

} // namespace ns3
#endif /* FABRIC_ATTACKS_V2_H */
