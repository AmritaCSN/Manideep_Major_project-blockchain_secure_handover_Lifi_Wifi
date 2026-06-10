/**
 * fabric-chaincode.cc
 * ---------------------------------------------------------------
 * Implementation of the three Fabric chaincodes:
 *   ApRegistryChaincode, HandoverPolicyChaincode, EnergyChaincode
 * ---------------------------------------------------------------
 */

#include "fabric-chaincode.h"

#include "ns3/log.h"
#include "ns3/simulator.h"
#include "ns3/random-variable-stream.h"
#include "ns3/double.h"

#include <algorithm>
#include <cmath>
#include <sstream>

NS_LOG_COMPONENT_DEFINE("FabricChaincode");

namespace ns3 {

/* ================================================================
 * ApRegistryChaincode
 * ================================================================ */

ApRegistryChaincode::ApRegistryChaincode(FabricLedger *ledger)
    : m_ledger(ledger)
{
    NS_ASSERT_MSG(ledger != nullptr, "ApRegistryChaincode: null ledger");
}

void
ApRegistryChaincode::RegisterAP(const std::string &apId,
                                  const std::string &orgId,
                                  double             trustScore)
{
    NS_LOG_INFO("ApRegistry: registering AP=" << apId
                << " org=" << orgId
                << " trust=" << trustScore);
    m_ledger->RegisterAP(apId, trustScore, orgId);
}

void
ApRegistryChaincode::RevokeAP(const std::string &apId)
{
    NS_LOG_INFO("ApRegistry: revoking AP=" << apId);
    m_ledger->RevokeAP(apId);
}

const ApTrustRecord*
ApRegistryChaincode::QueryAP(const std::string &apId) const
{
    return m_ledger->QueryAP(apId);
}

bool
ApRegistryChaincode::IsRegistered(const std::string &apId) const
{
    return m_ledger->IsApRegistered(apId);
}

/* ================================================================
 * HandoverPolicyChaincode
 * ================================================================ */

HandoverPolicyChaincode::HandoverPolicyChaincode(FabricLedger *ledger)
    : m_ledger(ledger),
      m_wTrust(0.50),
      m_wRssi(0.30),
      m_wEnergy(0.20),
      m_threshold(0.55)
{
    NS_ASSERT_MSG(ledger != nullptr, "HandoverPolicyChaincode: null ledger");
}

void
HandoverPolicyChaincode::SetWeights(double wTrust, double wRssi, double wEnergy)
{
    /* Weights are normalised so they always sum to 1.0 */
    double sum = wTrust + wRssi + wEnergy;
    NS_ASSERT_MSG(sum > 0.0, "Weights must be positive");
    m_wTrust  = wTrust  / sum;
    m_wRssi   = wRssi   / sum;
    m_wEnergy = wEnergy / sum;
}

void
HandoverPolicyChaincode::SetApprovalThreshold(double threshold)
{
    m_threshold = threshold;
}

HandoverVerdict
HandoverPolicyChaincode::EvaluateHandover(const std::string &sourceAp,
                                           const std::string &targetAp,
                                           double             rssiDbm,
                                           double             energyBudgetMj)
{
    HandoverVerdict verdict;
    verdict.bcLatencyMs = SimulateBlockchainLatency();

    NS_LOG_INFO("Chaincode: EvaluateHandover  src=" << sourceAp
                << "  tgt=" << targetAp
                << "  rssi=" << rssiDbm << " dBm"
                << "  budget=" << energyBudgetMj << " mJ"
                << "  latency=" << verdict.bcLatencyMs << " ms");

    /* ---- Step 1: AP registration check ---- */
    if (!m_ledger->IsApRegistered(targetAp))
    {
        /* BUG FIX: energy cost must be recorded even for DENIED transactions.
         * Blockchain validation (endorsement + ordering) consumes CPU and
         * network energy regardless of the decision outcome.
         * We compute the blockchain overhead energy for the denial. */
        EnergyChaincode energyCC;
        double denialEnergyCost = energyCC.ComputeBlockchainOverhead(3);

        verdict.approved        = false;
        verdict.decision        = "DENIED";
        verdict.reason          = "Target AP not registered on blockchain";
        verdict.compositeScore  = 0.0;
        verdict.trustScore      = 0.0;
        verdict.rssiScore       = NormaliseRssi(rssiDbm);
        verdict.energyScore     = 0.0;
        verdict.energyCostMj    = denialEnergyCost; /* validation has a cost */
        NS_LOG_INFO("Chaincode: DENIED — AP not registered: " << targetAp
                    << "  denial_energy=" << denialEnergyCost << "mJ");
        return verdict;
    }

    /* ---- Step 2: compute individual scores ---- */
    double sTrust  = m_ledger->GetTrustScore(targetAp);
    double sRssi   = NormaliseRssi(rssiDbm);

    /* Energy cost for this handover */
    EnergyChaincode energyCC;
    /* estimate 20 ms transmission window at -65 dBm WiFi or LiFi */
    std::string medium = (targetAp.find("LiFi") != std::string::npos) ? "LiFi" : "WiFi";
    double costMj  = energyCC.ComputeEnergyCost(medium, rssiDbm, 20.0)
                   + energyCC.ComputeBlockchainOverhead(3);
    double sEnergy = NormaliseEnergy(costMj, energyBudgetMj);

    /* ---- Step 3: weighted composite score ---- */
    double composite = m_wTrust  * sTrust
                     + m_wRssi   * sRssi
                     + m_wEnergy * sEnergy;

    verdict.trustScore     = sTrust;
    verdict.rssiScore      = sRssi;
    verdict.energyScore    = sEnergy;
    verdict.compositeScore = composite;
    verdict.energyCostMj   = costMj;

    NS_LOG_INFO("Chaincode: scores  trust=" << sTrust
                << "  rssi="   << sRssi
                << "  energy=" << sEnergy
                << "  composite=" << composite
                << "  threshold=" << m_threshold);

    /* ---- Step 4: threshold decision ---- */
    if (composite >= m_threshold)
    {
        verdict.approved = true;
        verdict.decision = "APPROVED";
        verdict.reason   = "Composite score above threshold";
    }
    else
    {
        verdict.approved = false;
        verdict.decision = "DENIED";
        std::ostringstream oss;
        oss << "Composite score " << composite
            << " below threshold " << m_threshold;
        verdict.reason = oss.str();
    }

    NS_LOG_INFO("Chaincode: verdict=" << verdict.decision
                << "  reason=" << verdict.reason);

    return verdict;
}

/* ---- Private helpers ---- */

double
HandoverPolicyChaincode::NormaliseRssi(double rssiDbm) const
{
    /* Map [-90, -40] dBm → [0.0, 1.0] linearly, clamp outside range */
    const double rssiMin = -90.0;
    const double rssiMax = -40.0;
    double norm = (rssiDbm - rssiMin) / (rssiMax - rssiMin);
    if (norm < 0.0) norm = 0.0;
    if (norm > 1.0) norm = 1.0;
    return norm;
}

double
HandoverPolicyChaincode::NormaliseEnergy(double costMj, double budgetMj) const
{
    if (budgetMj <= 0.0) return 0.0;
    /* Higher cost → lower energy score */
    double ratio = costMj / budgetMj;
    double score = 1.0 - ratio;
    if (score < 0.0) score = 0.0;
    if (score > 1.0) score = 1.0;
    return score;
}

double
HandoverPolicyChaincode::SimulateBlockchainLatency() const
{
    /**
     * Realistic Hyperledger Fabric latency breakdown (ms):
     *   Client → Endorsers (network round-trip)  : ~10–30 ms
     *   Endorsement processing (chaincode exec)  : ~5–20 ms
     *   Client → Orderer (submit)                : ~5–15 ms
     *   Raft ordering + block creation           : ~50–200 ms
     *   Block delivery to peers                  : ~10–30 ms
     *   Total typical range                      : ~80–295 ms
     *
     * We model each component with a uniform distribution and sum them.
     * In a real Fabric network on a LAN this can be as low as ~100 ms.
     */
    Ptr<UniformRandomVariable> rng = CreateObject<UniformRandomVariable>();

    double endorseRtt   = rng->GetValue(10.0, 30.0);
    double chaincodeExec= rng->GetValue(5.0,  20.0);
    double submitRtt    = rng->GetValue(5.0,  15.0);
    double orderingMs   = rng->GetValue(50.0, 200.0);
    double deliveryMs   = rng->GetValue(10.0, 30.0);

    return endorseRtt + chaincodeExec + submitRtt + orderingMs + deliveryMs;
}

/* ================================================================
 * EnergyChaincode
 * ================================================================ */

EnergyChaincode::EnergyChaincode() {}

double
EnergyChaincode::ComputeEnergyCost(const std::string &medium,
                                    double             txPowerDbm,
                                    double             durationMs) const
{
    double powerMw = 0.0;

    if (medium == "LiFi")
    {
        /**
         * LiFi (VLC) energy model.
         * LED driver power scales linearly with drive current.
         * We approximate: P_total = P_idle + P_tx
         * where P_tx is roughly proportional to optical power output.
         *
         * For a typical indoor LiFi AP:
         *   Idle (LED on, no data) : ~50 mW
         *   Transmitting           : ~150–200 mW (LED fully modulated)
         *
         * txPowerDbm is used here as a relative scaling factor;
         * for LiFi it represents optical SNR level.
         */
        double scaleFactor = std::max(0.0, (txPowerDbm + 90.0) / 50.0);
        powerMw = P_IDLE_LIFI_MW + P_TX_LIFI_MW * scaleFactor;
    }
    else /* WiFi */
    {
        /**
         * WiFi 802.11ac energy model.
         * Power amplifier output: P_out = 10^(txPowerDbm/10) mW
         * Total radio power: P_total = P_idle + PA_efficiency * P_out
         * Typical PA efficiency ~35%, idle ~100 mW baseline.
         */
        double pOutMw = std::pow(10.0, txPowerDbm / 10.0); // dBm → mW
        powerMw = P_IDLE_WIFI_MW + (pOutMw / 0.35);
    }

    /* E (mJ) = P (mW) × t (ms) / 1000 */
    double energyMj = powerMw * durationMs / 1000.0;

    NS_LOG_INFO("EnergyChaincode: medium=" << medium
                << "  txPower=" << txPowerDbm << " dBm"
                << "  duration=" << durationMs << " ms"
                << "  power=" << powerMw << " mW"
                << "  energy=" << energyMj << " mJ");

    return energyMj;
}

double
EnergyChaincode::ComputeBlockchainOverhead(uint32_t numEndorsers) const
{
    /**
     * Each endorsement involves:
     *   - CPU for chaincode execution : E_CPU_ENDORSE_MJ per peer
     *   - Network message (proposal + response) : E_NETWORK_TX_MJ per TX
     *
     * Ordering adds another E_CPU_ENDORSE_MJ worth of computation.
     */
    double endorseEnergy = static_cast<double>(numEndorsers) * E_CPU_ENDORSE_MJ;
    double networkEnergy = E_NETWORK_TX_MJ;
    double orderEnergy   = E_CPU_ENDORSE_MJ; /* orderer node */

    double total = endorseEnergy + networkEnergy + orderEnergy;

    NS_LOG_INFO("EnergyChaincode: BC overhead"
                << "  endorsers=" << numEndorsers
                << "  total=" << total << " mJ");

    return total;
}

double
EnergyChaincode::ComputeHandoverSwitchingCost(const std::string &fromMedium,
                                               const std::string &toMedium) const
{
    /**
     * Handover switching energy models:
     *
     * LiFi → WiFi:
     *   WiFi radio warm-up + scan + association + 4-way handshake
     *   Approx: 30 mW × 500 ms = 15 mJ
     *
     * WiFi → LiFi:
     *   LiFi photodetector alignment + sync pulse
     *   Approx: 10 mW × 200 ms = 2 mJ
     *
     * Same medium (unlikely but handled): negligible
     */
    double costMj = 0.0;

    if (fromMedium == "LiFi" && toMedium == "WiFi")
    {
        costMj = (P_SWITCH_WIFI_MW * 500.0) / 1000.0; /* 15 mJ */
    }
    else if (fromMedium == "WiFi" && toMedium == "LiFi")
    {
        costMj = (P_SWITCH_LIFI_MW * 200.0) / 1000.0; /* 2 mJ */
    }
    else
    {
        costMj = 0.5; /* same-medium re-association */
    }

    NS_LOG_INFO("EnergyChaincode: switching cost"
                << "  from=" << fromMedium
                << "  to="   << toMedium
                << "  cost=" << costMj << " mJ");

    return costMj;
}

} // namespace ns3
