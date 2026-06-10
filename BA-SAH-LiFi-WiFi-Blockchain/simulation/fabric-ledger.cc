/**
 * fabric-ledger.cc
 * ---------------------------------------------------------------
 * Implementation of FabricLedger — world state + block store.
 * See fabric-ledger.h for full design notes.
 * ---------------------------------------------------------------
 */

#include "fabric-ledger.h"

#include "ns3/log.h"
#include "ns3/simulator.h"

#include <iomanip>
#include <sstream>

NS_LOG_COMPONENT_DEFINE("FabricLedger");

namespace ns3 {

/* ================================================================
 * Constructor
 * ================================================================ */
FabricLedger::FabricLedger()
    : m_totalTx(0),
      m_approvedTx(0),
      m_deniedTx(0),
      m_totalLatencyMs(0.0),
      m_totalEnergyMj(0.0),
      m_txCounter(0)
{
    /* Genesis block — block 0, empty, anchors the chain */
    FabricBlock genesis;
    genesis.blockNumber  = 0;
    genesis.createdAt    = 0.0;
    genesis.prevHash     = "0000000000000000";
    genesis.blockHash    = "GENESIS_BLOCK_HASH";
    m_blockStore.push_back(genesis);

    NS_LOG_INFO("FabricLedger initialised. Genesis block committed.");
}

/* ================================================================
 * World State — Registration
 * ================================================================ */
void
FabricLedger::RegisterAP(const std::string &apId,
                          double             trustScore,
                          const std::string &orgId)
{
    ApTrustRecord rec;
    rec.apId           = apId;
    rec.registered     = true;
    rec.trustScore     = trustScore;
    rec.handoverCount  = 0;
    rec.rejectedCount  = 0;
    rec.registeredAt   = Simulator::Now().GetSeconds();
    rec.orgId          = orgId;

    m_worldState[apId] = rec;

    NS_LOG_INFO("Ledger: AP registered  id=" << apId
                << "  trust=" << trustScore
                << "  org="   << orgId);
}

void
FabricLedger::RevokeAP(const std::string &apId)
{
    auto it = m_worldState.find(apId);
    if (it != m_worldState.end())
    {
        it->second.registered = false;
        NS_LOG_INFO("Ledger: AP revoked  id=" << apId);
    }
}

/* ================================================================
 * World State — Queries
 * ================================================================ */
bool
FabricLedger::IsApRegistered(const std::string &apId) const
{
    auto it = m_worldState.find(apId);
    if (it == m_worldState.end()) return false;
    return it->second.registered;
}

double
FabricLedger::GetTrustScore(const std::string &apId) const
{
    auto it = m_worldState.find(apId);
    if (it == m_worldState.end()) return 0.0;
    return it->second.trustScore;
}

void
FabricLedger::UpdateTrustScore(const std::string &apId, double delta)
{
    auto it = m_worldState.find(apId);
    if (it == m_worldState.end()) return;

    double newScore = it->second.trustScore + delta;
    /* Clamp to [0.0, 1.0] */
    if (newScore < 0.0) newScore = 0.0;
    if (newScore > 1.0) newScore = 1.0;
    it->second.trustScore = newScore;

    NS_LOG_INFO("Ledger: trust score updated  id=" << apId
                << "  delta=" << delta
                << "  new="   << newScore);
}

const ApTrustRecord*
FabricLedger::QueryAP(const std::string &apId) const
{
    auto it = m_worldState.find(apId);
    if (it == m_worldState.end()) return nullptr;
    return &it->second;
}

/* ================================================================
 * Block Store — Commit
 * ================================================================ */
void
FabricLedger::CommitBlock(FabricBlock &block)
{
    /* Link to previous block */
    const FabricBlock &prev = m_blockStore.back();
    block.prevHash     = prev.blockHash;
    block.blockNumber  = static_cast<uint32_t>(m_blockStore.size());
    block.blockHash    = ComputeBlockHash(block);

    /* Update world state for each transaction in the block */
    for (const TxRecord &tx : block.transactions)
    {
        m_totalTx++;
        m_totalLatencyMs += tx.bcLatencyMs;
        m_totalEnergyMj  += tx.energyCostMj;

        if (tx.decision == "APPROVED")
        {
            m_approvedTx++;
            auto it = m_worldState.find(tx.targetAp);
            if (it != m_worldState.end())
                it->second.handoverCount++;

            /* Positive reinforcement: slight trust score increase */
            UpdateTrustScore(tx.targetAp, +0.005);
        }
        else
        {
            m_deniedTx++;
            auto it = m_worldState.find(tx.targetAp);
            if (it != m_worldState.end())
                it->second.rejectedCount++;

            /* Negative: slight trust score decrease for suspicious AP */
            UpdateTrustScore(tx.targetAp, -0.01);
        }

        NS_LOG_INFO("Ledger TX committed  id="       << tx.txId
                    << "  " << tx.sourceAp << " -> " << tx.targetAp
                    << "  decision=" << tx.decision
                    << "  latency="  << tx.bcLatencyMs << "ms"
                    << "  energy="   << tx.energyCostMj << "mJ");
    }

    m_blockStore.push_back(block);

    NS_LOG_INFO("Ledger: block #" << block.blockNumber
                << " committed  txCount=" << block.transactions.size()
                << "  hash=" << block.blockHash.substr(0, 12) << "...");
}

/* ================================================================
 * Block Store — Queries
 * ================================================================ */
uint32_t
FabricLedger::GetBlockHeight() const
{
    return static_cast<uint32_t>(m_blockStore.size());
}

const FabricBlock*
FabricLedger::GetBlock(uint32_t blockNumber) const
{
    if (blockNumber >= m_blockStore.size()) return nullptr;
    return &m_blockStore[blockNumber];
}

/* ================================================================
 * Statistics
 * ================================================================ */
uint32_t FabricLedger::GetTotalTransactions() const { return m_totalTx; }
uint32_t FabricLedger::GetApprovedCount()     const { return m_approvedTx; }
uint32_t FabricLedger::GetDeniedCount()       const { return m_deniedTx; }

double
FabricLedger::GetAverageLatencyMs() const
{
    if (m_totalTx == 0) return 0.0;
    return m_totalLatencyMs / static_cast<double>(m_totalTx);
}

double
FabricLedger::GetTotalEnergyMj() const
{
    return m_totalEnergyMj;
}

void
FabricLedger::PrintLedgerSummary() const
{
    std::cout << "\n========== FABRIC LEDGER SUMMARY ==========\n";
    std::cout << "  Block height        : " << GetBlockHeight()        << "\n";
    std::cout << "  Total transactions  : " << m_totalTx               << "\n";
    std::cout << "  Approved            : " << m_approvedTx            << "\n";
    std::cout << "  Denied              : " << m_deniedTx              << "\n";
    std::cout << "  Avg BC latency (ms) : "
              << std::fixed << std::setprecision(2)
              << GetAverageLatencyMs()                                   << "\n";
    std::cout << "  Total energy (mJ)   : "
              << std::fixed << std::setprecision(4)
              << m_totalEnergyMj                                         << "\n";

    std::cout << "\n  --- World State ---\n";
    for (const auto &kv : m_worldState)
    {
        const ApTrustRecord &r = kv.second;
        std::cout << "  AP: " << std::setw(18) << std::left << r.apId
                  << "  registered=" << (r.registered ? "YES" : "NO ")
                  << "  trust="      << std::fixed << std::setprecision(3) << r.trustScore
                  << "  approved="   << r.handoverCount
                  << "  rejected="   << r.rejectedCount
                  << "  org="        << r.orgId
                  << "\n";
    }
    std::cout << "============================================\n\n";
}

/* ================================================================
 * Private Helpers
 * ================================================================ */

/**
 * ComputeBlockHash — lightweight deterministic hash.
 * In real Hyperledger Fabric this is SHA-256.
 * Here we build a hex digest from XOR-folded content
 * so the chain is verifiable within the simulation.
 */
std::string
FabricLedger::ComputeBlockHash(const FabricBlock &block) const
{
    /* Build a canonical string of the block's content */
    std::ostringstream oss;
    oss << block.blockNumber
        << block.createdAt
        << block.prevHash;

    for (const TxRecord &tx : block.transactions)
    {
        oss << tx.txId
            << tx.timestamp
            << tx.sourceAp
            << tx.targetAp
            << tx.decision
            << tx.trustScore
            << tx.bcLatencyMs;
    }

    /* XOR-fold into 8 bytes, represent as 16 hex chars */
    std::string s   = oss.str();
    uint64_t    acc = 0x6b5a4b3a2a1a0a00ULL; /* seed */
    for (size_t i = 0; i < s.size(); ++i)
    {
        acc ^= (static_cast<uint64_t>(static_cast<unsigned char>(s[i])) << ((i % 8) * 8));
        acc  = (acc << 7) | (acc >> 57); /* rotate left 7 */
    }

    std::ostringstream hexOut;
    hexOut << std::hex << std::setfill('0') << std::setw(16) << acc;
    return hexOut.str();
}

std::string
FabricLedger::GenerateTxId()
{
    std::ostringstream oss;
    oss << "tx-"
        << std::fixed << std::setprecision(3)
        << Simulator::Now().GetSeconds()
        << "-" << ++m_txCounter;
    return oss.str();
}

} // namespace ns3
