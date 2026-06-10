#ifndef FABRIC_CLIENT_H
#define FABRIC_CLIENT_H

/**
 * fabric-client.h
 * ---------------------------------------------------------------
 * Hyperledger Fabric Client SDK — ns-3 simulation layer.
 *
 * This is the ONLY interface the UE (hybrid_full.cc) needs to call.
 * All blockchain complexity is hidden behind four simple functions:
 *
 *   1. RequestHandover(sourceAp, targetAp, rssiDbm, energyBudgetMj)
 *      → Returns HandoverVerdict synchronously (latency is simulated
 *        inside the verdict's bcLatencyMs field)
 *
 *   2. RegisterAP(apId, orgId, trustScore)
 *      → Called at simulation setup to populate the ledger
 *
 *   3. RevokeAP(apId)
 *      → Called during attack scenarios (rogue AP detection)
 *
 *   4. GetMetrics()
 *      → Returns FabricMetrics snapshot for logging
 *
 * Internally FabricClient orchestrates:
 *   ApRegistryChaincode  → checks AP registration
 *   HandoverPolicyChaincode → evaluates multi-factor score
 *   EnergyChaincode      → computes energy cost
 *   FabricOrderer        → batches + commits to ledger
 *   FabricLedger         → world state + block store
 * ---------------------------------------------------------------
 */

#include "fabric-ledger.h"
#include "fabric-chaincode.h"
#include "fabric-orderer.h"

#include <string>

namespace ns3 {

/* ================================================================
 * FabricMetrics — snapshot returned to caller
 * ================================================================ */
struct FabricMetrics
{
    uint32_t totalTransactions;
    uint32_t approvedHandovers;
    uint32_t deniedHandovers;
    uint32_t blockHeight;
    double   avgLatencyMs;
    double   minLatencyMs;
    double   maxLatencyMs;
    double   totalEnergyMj;
    double   avgEnergyPerHandoverMj;
};

/* ================================================================
 * FabricClient
 * ================================================================ */
class FabricClient
{
  public:
    FabricClient();
    ~FabricClient() = default;

    /**
     * InitNetwork — call once before simulation starts.
     * Registers all legitimate APs on the blockchain.
     */
    void InitNetwork();

    /**
     * RequestHandover — main entry point for the handover module.
     *
     * Flow (mirrors real Fabric SDK):
     *   1. Construct proposal
     *   2. Send to endorsing peers (ApRegistry + HandoverPolicy chaincode)
     *   3. Collect endorsements (simulated — all 3 peers must agree)
     *   4. Submit endorsed TX to orderer
     *   5. Orderer batches and commits to ledger
     *   6. Return verdict to caller
     *
     * The entire flow latency is captured inside verdict.bcLatencyMs.
     *
     * @param sourceAp       AP the UE is currently using
     * @param targetAp       AP the UE wants to switch to
     * @param rssiDbm        RSSI of target AP measured by UE
     * @param energyBudgetMj remaining energy budget (set large if unknown)
     * @return HandoverVerdict — approved/denied + all scores + latency
     */
    HandoverVerdict RequestHandover(const std::string &sourceAp,
                                    const std::string &targetAp,
                                    double             rssiDbm,
                                    double             energyBudgetMj = 1000.0);

    /**
     * RegisterAP — wrapper for ApRegistryChaincode.
     */
    void RegisterAP(const std::string &apId,
                    const std::string &orgId,
                    double             trustScore = 1.0);

    /**
     * RevokeAP — revoke an AP mid-simulation (attack response).
     */
    void RevokeAP(const std::string &apId);

    /**
     * GetMetrics — returns current performance snapshot.
     */
    FabricMetrics GetMetrics() const;

    /**
     * Flush — call at simulation end to commit any pending transactions.
     */
    void Flush();

    /**
     * PrintSummary — print full ledger + metric summary to stdout.
     */
    void PrintSummary() const;

    /**
     * SetPolicyWeights — tune handover decision weights.
     * @param wTrust   weight for blockchain trust score (default 0.50)
     * @param wRssi    weight for RSSI score             (default 0.30)
     * @param wEnergy  weight for energy score           (default 0.20)
     */
    void SetPolicyWeights(double wTrust, double wRssi, double wEnergy);

    /**
     * SetApprovalThreshold — tune decision boundary (default 0.55).
     */
    void SetApprovalThreshold(double threshold);

    /* Access to underlying ledger for advanced queries */
    const FabricLedger* GetLedger() const { return &m_ledger; }

  private:
    FabricLedger              m_ledger;
    ApRegistryChaincode       m_apRegistry;
    HandoverPolicyChaincode   m_handoverPolicy;
    EnergyChaincode           m_energyCC;
    FabricOrderer             m_orderer;

    /* Latency statistics (in addition to what ledger stores) */
    double   m_minLatencyMs;
    double   m_maxLatencyMs;
    uint32_t m_latencySamples;
};

} // namespace ns3

/* ================================================================
 * Implementation
 * ================================================================ */
#include "ns3/log.h"
#include "ns3/simulator.h"
#include <iomanip>
#include <iostream>
#include <sstream>

#define g_log g_log_FabricClient
static ns3::LogComponent g_log_FabricClient("FabricClient", __FILE__);

namespace ns3 {

FabricClient::FabricClient()
    : m_ledger(),
      m_apRegistry(&m_ledger),
      m_handoverPolicy(&m_ledger),
      m_energyCC(),
      m_orderer(&m_ledger, 10, 2000.0),
      m_minLatencyMs(1e9),
      m_maxLatencyMs(0.0),
      m_latencySamples(0)
{
    (void)0;
}

void
FabricClient::InitNetwork()
{
    /**
     * Bootstrap the blockchain network:
     * Register all legitimate APs with their Fabric organisation
     * and initial trust scores.
     *
     * AP_LIFI        → Org1, trust=1.0 (indoor, line-of-sight, high trust)
     * AP_WIFI_LEGIT  → Org2, trust=0.95 (legitimate, slightly lower trust)
     *
     * Rogue AP is intentionally NOT registered.
     */
    (void)0;

    m_apRegistry.RegisterAP("LiFiAP",      "Org1", 1.0);
    m_apRegistry.RegisterAP("LegitWiFiAP", "Org2", 0.95);
    /* RogueWiFiAP deliberately not registered */

}

HandoverVerdict
FabricClient::RequestHandover(const std::string &sourceAp,
                               const std::string &targetAp,
                               double             rssiDbm,
                               double             energyBudgetMj)
{
    double requestTime = Simulator::Now().GetSeconds();


    /* ---- Chaincode evaluation (endorsement phase) ---- */
    HandoverVerdict verdict =
        m_handoverPolicy.EvaluateHandover(sourceAp, targetAp,
                                           rssiDbm, energyBudgetMj);

    /* ---- Build TxRecord for the orderer ---- */
    TxRecord tx;
    {
        std::ostringstream id;
        id << "tx-" << std::fixed << std::setprecision(3)
           << requestTime << "-" << (m_ledger.GetTotalTransactions() + 1);
        tx.txId         = id.str();
    }
    tx.timestamp    = requestTime;
    tx.sourceAp     = sourceAp;
    tx.targetAp     = targetAp;
    tx.decision     = verdict.decision;
    tx.trustScore   = verdict.trustScore;
    tx.rssi         = rssiDbm;
    tx.energyCostMj = verdict.energyCostMj;
    tx.bcLatencyMs  = verdict.bcLatencyMs;

    /* Simulated endorsements from 3 peers (Org1, Org2, Org3) */
    tx.endorsements = {"Peer0-Org1", "Peer1-Org2", "Peer2-Org3"};

    /* ---- Submit to orderer ---- */
    m_orderer.SubmitTransaction(tx);

    /* ---- Update latency statistics ---- */
    if (verdict.bcLatencyMs < m_minLatencyMs) m_minLatencyMs = verdict.bcLatencyMs;
    if (verdict.bcLatencyMs > m_maxLatencyMs) m_maxLatencyMs = verdict.bcLatencyMs;
    m_latencySamples++;


    return verdict;
}

void
FabricClient::RegisterAP(const std::string &apId,
                          const std::string &orgId,
                          double             trustScore)
{
    m_apRegistry.RegisterAP(apId, orgId, trustScore);
}

void
FabricClient::RevokeAP(const std::string &apId)
{
    m_apRegistry.RevokeAP(apId);
}

FabricMetrics
FabricClient::GetMetrics() const
{
    FabricMetrics m;
    m.totalTransactions      = m_ledger.GetTotalTransactions();
    m.approvedHandovers      = m_ledger.GetApprovedCount();
    m.deniedHandovers        = m_ledger.GetDeniedCount();
    m.blockHeight            = m_ledger.GetBlockHeight();
    m.avgLatencyMs           = m_ledger.GetAverageLatencyMs();
    m.minLatencyMs           = (m_latencySamples > 0) ? m_minLatencyMs : 0.0;
    m.maxLatencyMs           = m_maxLatencyMs;
    m.totalEnergyMj          = m_ledger.GetTotalEnergyMj();
    m.avgEnergyPerHandoverMj = (m.totalTransactions > 0)
                               ? m.totalEnergyMj / m.totalTransactions
                               : 0.0;
    return m;
}

void
FabricClient::Flush()
{
    m_orderer.FlushPending();
}

void
FabricClient::SetPolicyWeights(double wTrust, double wRssi, double wEnergy)
{
    m_handoverPolicy.SetWeights(wTrust, wRssi, wEnergy);
}

void
FabricClient::SetApprovalThreshold(double threshold)
{
    m_handoverPolicy.SetApprovalThreshold(threshold);
}

void
FabricClient::PrintSummary() const
{
    FabricMetrics m = GetMetrics();
    std::cout << "\n========== FABRIC CLIENT METRICS ==========\n";
    std::cout << "  Total handover requests : " << m.totalTransactions      << "\n";
    std::cout << "  Approved                : " << m.approvedHandovers      << "\n";
    std::cout << "  Denied                  : " << m.deniedHandovers        << "\n";
    std::cout << "  Block height            : " << m.blockHeight            << "\n";
    std::cout << "  Avg BC latency (ms)     : "
              << std::fixed << std::setprecision(2) << m.avgLatencyMs       << "\n";
    std::cout << "  Min BC latency (ms)     : "
              << std::fixed << std::setprecision(2) << m.minLatencyMs       << "\n";
    std::cout << "  Max BC latency (ms)     : "
              << std::fixed << std::setprecision(2) << m.maxLatencyMs       << "\n";
    std::cout << "  Total energy (mJ)       : "
              << std::fixed << std::setprecision(4) << m.totalEnergyMj      << "\n";
    std::cout << "  Avg energy/handover(mJ) : "
              << std::fixed << std::setprecision(4) << m.avgEnergyPerHandoverMj << "\n";
    std::cout << "============================================\n";

    m_ledger.PrintLedgerSummary();
}

} // namespace ns3
#undef g_log 
#endif /* FABRIC_CLIENT_H */
