#ifndef FABRIC_LEDGER_H
#define FABRIC_LEDGER_H

/**
 * fabric-ledger.h
 * ---------------------------------------------------------------
 * Hyperledger Fabric-inspired distributed ledger for ns-3.
 *
 * Models two storage layers exactly as real Hyperledger Fabric does:
 *   1. World State  – key/value store of CURRENT AP trust records
 *   2. Block Store  – append-only chain of immutable transaction blocks
 *
 * Each Block contains:
 *   - Block number & creation timestamp
 *   - Previous block hash (SHA-256 simplified as string digest)
 *   - One or more transactions (TxRecord)
 *
 * Each TxRecord contains:
 *   - Transaction ID (UUID-style counter)
 *   - Source AP, Target AP
 *   - Decision (APPROVED / DENIED)
 *   - Trust score, RSSI, energy cost, latency overhead
 *   - Endorsement signatures (simulated as peer IDs)
 *
 * Used by: fabric-orderer.h (writes blocks)
 *          fabric-chaincode.h (reads world state)
 *          fabric-metrics.h (reads block store for statistics)
 * ---------------------------------------------------------------
 */

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace ns3 {

/* ----------------------------------------------------------------
 * AP Trust Record  (world state entry)
 * ---------------------------------------------------------------- */
struct ApTrustRecord
{
    std::string apId;
    bool        registered;      // false = revoked / unregistered
    double      trustScore;      // 0.0 – 1.0
    uint32_t    handoverCount;   // approved handovers served
    uint32_t    rejectedCount;   // times this AP was rejected target
    double      registeredAt;   // simulation time of registration
    std::string orgId;           // Fabric organisation (Org1/Org2/Org3)
};

/* ----------------------------------------------------------------
 * Transaction Record  (one entry inside a block)
 * ---------------------------------------------------------------- */
struct TxRecord
{
    std::string txId;
    double      timestamp;       // ns-3 simulation time (seconds)
    std::string sourceAp;
    std::string targetAp;
    std::string decision;        // "APPROVED" | "DENIED"
    double      trustScore;      // score at decision time
    double      rssi;            // dBm at decision time
    double      energyCostMj;    // energy cost of this handover (mJ)
    double      bcLatencyMs;     // blockchain round-trip latency (ms)
    std::vector<std::string> endorsements; // peer IDs that endorsed
};

/* ----------------------------------------------------------------
 * Block  (unit of the append-only chain)
 * ---------------------------------------------------------------- */
struct FabricBlock
{
    uint32_t                blockNumber;
    double                  createdAt;      // simulation time
    std::string             prevHash;       // hash of previous block
    std::string             blockHash;      // hash of this block
    std::vector<TxRecord>   transactions;
};

/* ================================================================
 * FabricLedger
 * ================================================================ */
class FabricLedger
{
  public:
    FabricLedger();

    /* ---------- World State API ---------- */
    void   RegisterAP(const std::string &apId,
                      double trustScore,
                      const std::string &orgId);

    void   RevokeAP(const std::string &apId);

    bool   IsApRegistered(const std::string &apId) const;

    double GetTrustScore(const std::string &apId) const;

    void   UpdateTrustScore(const std::string &apId, double delta);

    const ApTrustRecord* QueryAP(const std::string &apId) const;

    /* ---------- Block Store API ---------- */

    /**
     * CommitBlock — called by FabricOrderer after consensus.
     * Appends the block and updates world state for each transaction.
     */
    void   CommitBlock(FabricBlock &block);

    uint32_t GetBlockHeight() const;

    const FabricBlock* GetBlock(uint32_t blockNumber) const;

    /* ---------- Audit / Statistics ---------- */
    uint32_t GetTotalTransactions() const;
    uint32_t GetApprovedCount()     const;
    uint32_t GetDeniedCount()       const;
    double   GetAverageLatencyMs()  const;
    double   GetTotalEnergyMj()     const;

    void     PrintLedgerSummary()   const;

  private:
    /* World state: apId -> record */
    std::map<std::string, ApTrustRecord> m_worldState;

    /* Block store: blockNumber -> block */
    std::vector<FabricBlock> m_blockStore;

    /* Running statistics */
    uint32_t m_totalTx;
    uint32_t m_approvedTx;
    uint32_t m_deniedTx;
    double   m_totalLatencyMs;
    double   m_totalEnergyMj;
    uint32_t m_txCounter;       // monotonic TX ID generator

    /* Helpers */
    std::string ComputeBlockHash(const FabricBlock &block) const;
    std::string GenerateTxId();
};

} // namespace ns3
#endif /* FABRIC_LEDGER_H */
