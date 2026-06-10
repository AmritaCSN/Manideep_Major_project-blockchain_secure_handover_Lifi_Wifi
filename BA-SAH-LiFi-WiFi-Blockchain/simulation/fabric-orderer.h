#ifndef FABRIC_ORDERER_H
#define FABRIC_ORDERER_H

/**
 * fabric-orderer.h / fabric-orderer.cc  (combined single-file for ns-3)
 * ---------------------------------------------------------------
 * Hyperledger Fabric Ordering Service — Raft consensus model.
 *
 * Real Hyperledger Fabric uses an etcd/Raft-based ordering service.
 * This module simulates the ordering service behaviour inside ns-3:
 *
 *  1. Transactions are submitted to the orderer's mempool.
 *  2. The orderer batches transactions into blocks when either:
 *       (a) the batch reaches MAX_TX_PER_BLOCK, or
 *       (b) the batch timeout BLOCK_TIMEOUT_MS elapses.
 *  3. Raft leader election delay is modelled as a one-time cost.
 *  4. Once a block is cut, it is committed to the FabricLedger.
 *  5. Total end-to-end latency per TX = endorsement + ordering + commit.
 *
 * Key parameters matching real Fabric defaults:
 *   MaxMessageCount  = 10  transactions per block
 *   BatchTimeout     = 2000 ms
 *   Raft leader delay = uniform(50, 200) ms (leader already elected)
 * ---------------------------------------------------------------
 */

#include "fabric-ledger.h"
#include "fabric-chaincode.h"

#include "ns3/simulator.h"
#include "ns3/random-variable-stream.h"

#include <queue>
#include <string>
#include <vector>

namespace ns3 {

/* ================================================================
 * FabricOrderer
 * ================================================================ */
class FabricOrderer
{
  public:
    /**
     * @param ledger       shared ledger (world state + block store)
     * @param maxTxPerBlock batch size (default 10, matching Fabric default)
     * @param batchTimeoutMs  cut block if this many ms pass (default 2000)
     */
    explicit FabricOrderer(FabricLedger *ledger,
                           uint32_t      maxTxPerBlock  = 10,
                           double        batchTimeoutMs = 2000.0);

    /**
     * SubmitTransaction — called by FabricClient after endorsement.
     * The transaction enters the mempool.  The orderer will cut
     * a block when batch is full or timeout fires.
     */
    void SubmitTransaction(const TxRecord &tx);

    /**
     * FlushPending — force-cut a block with whatever is in the mempool.
     * Call this at the end of the simulation to commit final transactions.
     */
    void FlushPending();

    uint32_t GetPendingCount()   const;
    uint32_t GetBlocksCut()      const;

  private:
    FabricLedger              *m_ledger;
    uint32_t                   m_maxTxPerBlock;
    double                     m_batchTimeoutMs;
    std::vector<TxRecord>      m_mempool;
    uint32_t                   m_blocksCut;
    double                     m_lastBatchStartTime; /* simulation time */

    void CutBlock();
    double SimulateRaftLatency() const;
};

} // namespace ns3

/* ================================================================
 * Implementation (kept in same file for easy ns-3 integration)
 * ================================================================ */

#include "ns3/log.h"
#include <iomanip>
#include <sstream>

#define g_log g_log_FabricOrderer
static ns3::LogComponent g_log_FabricOrderer("FabricOrderer", __FILE__);
namespace ns3 {

FabricOrderer::FabricOrderer(FabricLedger *ledger,
                               uint32_t      maxTxPerBlock,
                               double        batchTimeoutMs)
    : m_ledger(ledger),
      m_maxTxPerBlock(maxTxPerBlock),
      m_batchTimeoutMs(batchTimeoutMs),
      m_blocksCut(0),
      m_lastBatchStartTime(0.0)
{
    (void)0;
}

void
FabricOrderer::SubmitTransaction(const TxRecord &tx)
{
    m_mempool.push_back(tx);


    /* Start batch timer on first TX in batch */
    if (m_mempool.size() == 1)
    {
        m_lastBatchStartTime = Simulator::Now().GetSeconds();
    }

    /* Cut block if batch is full */
    if (m_mempool.size() >= static_cast<size_t>(m_maxTxPerBlock))
    {
        (void)0;
        CutBlock();
        return;
    }

    /* Cut block if batch timeout elapsed */
    double elapsed = (Simulator::Now().GetSeconds() - m_lastBatchStartTime) * 1000.0;
    if (elapsed >= m_batchTimeoutMs && !m_mempool.empty())
    {
        (void)0;
        CutBlock();
    }
}

void
FabricOrderer::FlushPending()
{
    if (!m_mempool.empty())
    {
        (void)0;
        CutBlock();
    }
}

uint32_t FabricOrderer::GetPendingCount() const { return static_cast<uint32_t>(m_mempool.size()); }
uint32_t FabricOrderer::GetBlocksCut()    const { return m_blocksCut; }

void
FabricOrderer::CutBlock()
{
    if (m_mempool.empty()) return;

    /* Simulate Raft ordering latency */
    double raftDelayMs = SimulateRaftLatency();

    FabricBlock block;
    block.blockNumber  = 0;                          /* set by ledger on commit */
    block.createdAt    = Simulator::Now().GetSeconds()
                       + raftDelayMs / 1000.0;
    block.transactions = m_mempool;

    m_mempool.clear();
    m_lastBatchStartTime = Simulator::Now().GetSeconds();


    m_ledger->CommitBlock(block);
    m_blocksCut++;
}

double
FabricOrderer::SimulateRaftLatency() const
{
    /**
     * Raft ordering latency components:
     *  - Leader heartbeat interval  : 500 ms default in Fabric
     *  - Leader already elected (steady state): log replication ~50-150 ms
     *  - Block delivery to committer peers    : 10-40 ms
     *
     * We model steady-state (leader elected) ordering latency as:
     *   uniform(60, 180) ms
     */
    Ptr<UniformRandomVariable> rng = CreateObject<UniformRandomVariable>();
    return rng->GetValue(60.0, 180.0);
}

} // namespace ns3
#undef g_log
#endif /* FABRIC_ORDERER_H */
