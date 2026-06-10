#ifndef FABRIC_CHAINCODE_H
#define FABRIC_CHAINCODE_H

/**
 * fabric-chaincode.h
 * ---------------------------------------------------------------
 * Hyperledger Fabric Chaincode (smart contract) for ns-3.
 *
 * Implements three chaincodes exactly as they would be deployed
 * on a real Fabric network:
 *
 *  1. ApRegistryChaincode
 *     - RegisterAP / RevokeAP / QueryAP
 *     - Maintains trusted AP list in the ledger world state
 *
 *  2. HandoverPolicyChaincode
 *     - EvaluateHandover(sourceAp, targetAp, rssi, energyBudgetMj)
 *     - Computes weighted score: trust + RSSI + energy
 *     - Returns HandoverVerdict (APPROVED/DENIED + reason + score)
 *
 *  3. EnergyChaincode
 *     - ComputeEnergyCost(medium, txPowerDbm, dataRateMbps, durationMs)
 *     - Returns energy cost in millijoules
 *     - Models LiFi and WiFi power characteristics separately
 *
 * Each chaincode receives a pointer to the shared FabricLedger so
 * it can read/write world state.
 * ---------------------------------------------------------------
 */

#include "fabric-ledger.h"
#include <string>

namespace ns3 {

/* ================================================================
 * HandoverVerdict — returned by HandoverPolicyChaincode
 * ================================================================ */
struct HandoverVerdict
{
    bool        approved;
    std::string decision;     // "APPROVED" | "DENIED"
    std::string reason;       // human-readable reason
    double      compositeScore; // 0.0 – 1.0
    double      trustScore;
    double      rssiScore;
    double      energyScore;
    double      energyCostMj; // cost of THIS handover
    double      bcLatencyMs;  // simulated blockchain round-trip
};

/* ================================================================
 * 1. ApRegistryChaincode
 * ================================================================ */
class ApRegistryChaincode
{
  public:
    explicit ApRegistryChaincode(FabricLedger *ledger);

    /**
     * RegisterAP — add a trusted AP to the world state.
     * @param orgId  owning Fabric organisation
     * @param trustScore  initial trust score (0.0 – 1.0)
     */
    void RegisterAP(const std::string &apId,
                    const std::string &orgId,
                    double             trustScore = 1.0);

    /**
     * RevokeAP — mark an AP as untrusted (soft delete).
     */
    void RevokeAP(const std::string &apId);

    /**
     * QueryAP — returns pointer to world-state record or nullptr.
     */
    const ApTrustRecord* QueryAP(const std::string &apId) const;

    bool IsRegistered(const std::string &apId) const;

  private:
    FabricLedger *m_ledger;
};

/* ================================================================
 * 2. HandoverPolicyChaincode
 * ================================================================ */
class HandoverPolicyChaincode
{
  public:
    explicit HandoverPolicyChaincode(FabricLedger *ledger);

    /**
     * EvaluateHandover — core smart contract function.
     *
     * Decision formula (journal-level, cite as weighted sum):
     *
     *   S_composite = w_t * S_trust
     *               + w_r * S_rssi
     *               + w_e * S_energy
     *
     * where:
     *   S_trust  = GetTrustScore(targetAp)          from ledger
     *   S_rssi   = normalise(rssiDbm, -90, -40)     linear clamp
     *   S_energy = 1 - normalise(energyCostMj, 0, maxEnergyBudgetMj)
     *
     * Default weights: w_t=0.50, w_r=0.30, w_e=0.20
     * Approval threshold: S_composite >= 0.55
     *
     * @param sourceAp        current AP the UE is connected to
     * @param targetAp        candidate AP for handover
     * @param rssiDbm         measured RSSI of target AP (dBm)
     * @param energyBudgetMj  remaining energy budget of UE (mJ)
     * @return HandoverVerdict with full breakdown
     */
    HandoverVerdict EvaluateHandover(const std::string &sourceAp,
                                     const std::string &targetAp,
                                     double             rssiDbm,
                                     double             energyBudgetMj);

    /* Weight tuning — call before simulation starts */
    void SetWeights(double wTrust, double wRssi, double wEnergy);
    void SetApprovalThreshold(double threshold);

  private:
    FabricLedger *m_ledger;

    double m_wTrust;
    double m_wRssi;
    double m_wEnergy;
    double m_threshold;

    double NormaliseRssi(double rssiDbm) const;
    double NormaliseEnergy(double costMj, double budgetMj) const;
    double SimulateBlockchainLatency() const;
};

/* ================================================================
 * 3. EnergyChaincode
 * ================================================================ */
class EnergyChaincode
{
  public:
    EnergyChaincode();

    /**
     * ComputeEnergyCost — returns energy in millijoules.
     *
     * Model (from IEEE 802.11 and VLC energy literature):
     *
     *  LiFi:  P_tx = P_idle_lifi + alpha * txPower
     *         E = P_tx * durationMs / 1000.0   [mJ]
     *
     *  WiFi:  P_tx = P_idle_wifi + beta * 10^(txPowerDbm/10) / 1000
     *         E = P_tx * durationMs / 1000.0   [mJ]
     *
     *  Blockchain overhead:
     *         E_bc = E_cpu_per_endorsement * numEndorsers
     *              + E_network_per_tx
     *
     * @param medium      "LiFi" | "WiFi"
     * @param txPowerDbm  transmit power in dBm
     * @param durationMs  transmission duration in ms
     * @return energy cost in millijoules
     */
    double ComputeEnergyCost(const std::string &medium,
                             double             txPowerDbm,
                             double             durationMs) const;

    /**
     * ComputeBlockchainOverhead — energy cost of one blockchain
     * validation round (endorsement + ordering + commit).
     * @param numEndorsers  number of endorsing peers (default 3)
     */
    double ComputeBlockchainOverhead(uint32_t numEndorsers = 3) const;

    /**
     * ComputeHandoverSwitchingCost — energy of medium switching.
     * Includes radio warm-up, association, and re-authentication.
     * @param fromMedium  "LiFi" | "WiFi"
     * @param toMedium    "LiFi" | "WiFi"
     */
    double ComputeHandoverSwitchingCost(const std::string &fromMedium,
                                        const std::string &toMedium) const;

  private:
    /* LiFi power model parameters (from VLC literature) */
    static constexpr double P_IDLE_LIFI_MW      = 50.0;  // mW
    static constexpr double P_TX_LIFI_MW        = 150.0; // mW typical LED driver
    static constexpr double P_SWITCH_LIFI_MW    = 10.0;  // mW warm-up overhead

    /* WiFi 802.11ac power model parameters */
    static constexpr double P_IDLE_WIFI_MW      = 100.0; // mW
    static constexpr double P_TX_WIFI_BASE_MW   = 200.0; // mW at 0 dBm ref
    static constexpr double P_SWITCH_WIFI_MW    = 30.0;  // mW association overhead

    /* Blockchain CPU overhead per endorsement (modelled as ~10ms @ 100mW) */
    static constexpr double E_CPU_ENDORSE_MJ    = 1.0;   // mJ per endorser
    static constexpr double E_NETWORK_TX_MJ     = 0.2;   // mJ network per TX
};

} // namespace ns3
#endif /* FABRIC_CHAINCODE_H */
