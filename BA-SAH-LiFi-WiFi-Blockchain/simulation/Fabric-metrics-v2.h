#ifndef FABRIC_METRICS_H
#define FABRIC_METRICS_H

/**
 * fabric-metrics.h
 * ---------------------------------------------------------------
 * Performance Evaluation Module — journal-level metrics collector.
 *
 * Collects, computes, and exports ALL metrics needed for the paper:
 *
 *  ┌─────────────────────────────────────────────────────────────┐
 *  │  Metric Category        │ Metrics                           │
 *  ├─────────────────────────┼───────────────────────────────────┤
 *  │  Latency                │ E2E delay, handover latency,      │
 *  │                         │ BC latency (with vs without)      │
 *  ├─────────────────────────┼───────────────────────────────────┤
 *  │  Throughput             │ TPS (blockchain), network Mbps    │
 *  ├─────────────────────────┼───────────────────────────────────┤
 *  │  Energy                 │ mJ/handover, total mJ, savings %  │
 *  ├─────────────────────────┼───────────────────────────────────┤
 *  │  Security               │ attacks blocked, false positives  │
 *  ├─────────────────────────┼───────────────────────────────────┤
 *  │  Scalability            │ TPS vs N_UE, latency vs N_UE      │
 *  └─────────────────────────┴───────────────────────────────────┘
 *
 * Output: CSV file + console summary table
 * ---------------------------------------------------------------
 */

#include "fabric-client.h"
#include "ns3/flow-monitor.h"
#include "ns3/flow-monitor-helper.h"

#include <fstream>
#include <map>
#include <string>
#include <vector>

namespace ns3 {

/* ================================================================
 * PerHandoverRecord — one row in the metrics CSV
 * ================================================================ */
struct PerHandoverRecord
{
    double   simTimeS;         // simulation time of handover
    std::string sourceAp;
    std::string targetAp;
    std::string decision;
    double   compositeScore;
    double   bcLatencyMs;      // blockchain round-trip
    double   energyCostMj;
    double   rssiDbm;
    double   trustScore;
    std::string attackMode;    // baseline/rogue/mitm/downgrade/blockage
};

/* ================================================================
 * LatencyComparison — with vs without blockchain
 * ================================================================ */
struct LatencyComparison
{
    double   handoverLatencyWithBcMs;
    double   handoverLatencyWithoutBcMs;
    double   overheadMs;          // difference
    double   overheadPercent;
};

/* ================================================================
 * FabricMetricsCollector
 * ================================================================ */
class FabricMetricsCollector
{
  public:
    explicit FabricMetricsCollector(FabricClient *client,
                                    const std::string &outputDir = "results");

    /**
     * RecordHandover — call every time a handover is requested.
     * @param attackMode  string label for current attack scenario
     */
    void RecordHandover(const PerHandoverRecord &record);

    /**
     * RecordFlowMonitorStats — call after simulation ends with
     * the FlowMonitor pointer to extract network-level metrics.
     */
    void RecordFlowMonitorStats(Ptr<FlowMonitor>    flowMonitor,
                                FlowMonitorHelper  &helper);

    /**
     * ComputeLatencyComparison — computes handover latency
     * with and without blockchain (baseline uses ~5ms, BC uses
     * realistic Fabric latency from ledger records).
     */
    LatencyComparison ComputeLatencyComparison() const;

    /**
     * ComputeEnergyComparison — total energy WITH blockchain
     * vs WITHOUT blockchain (baseline adds no BC overhead).
     *
     * @param numHandovers  total handovers in simulation
     * @return pair<withBc_mJ, withoutBc_mJ>
     */
    std::pair<double, double> ComputeEnergyComparison(uint32_t numHandovers) const;

    /**
     * ExportCSV — writes per-handover CSV to outputDir/fabric_metrics.csv
     */
    void ExportCSV() const;

    /**
     * ExportLatencyCSV — writes with/without BC latency comparison
     * to outputDir/latency_comparison.csv (ready for plotting)
     */
    void ExportLatencyCSV() const;

    /**
     * ExportEnergyCSV — writes energy breakdown CSV
     */
    void ExportEnergyCSV() const;

    /**
     * PrintFullReport — print formatted table to stdout
     */
    void PrintFullReport() const;

  private:
    FabricClient              *m_client;
    std::string                m_outputDir;
    std::vector<PerHandoverRecord> m_records;

    /* FlowMonitor extracted stats */
    struct FlowStats
    {
        double throughputMbps;
        double avgDelayMs;
        double avgJitterMs;
        double packetLossPercent;
        uint64_t txPackets;
        uint64_t rxPackets;
    };
    std::vector<FlowStats> m_flowStats;

    /* Baseline latency (without blockchain) — 5ms simple lookup */
    static constexpr double BASELINE_HANDOVER_LATENCY_MS = 5.0;

    /* Baseline energy per handover (without blockchain overhead) */
    static constexpr double BASELINE_ENERGY_PER_HO_MJ    = 15.5;

  public:
    /* GetClient — needed by ExportMeasuredBaseline in hybrid_full_v4 */
    const FabricClient* GetClient() const { return m_client; }
};

} // namespace ns3

/* ================================================================
 * Implementation
 * ================================================================ */
#include "ns3/log.h"
#include "ns3/simulator.h"

#include <iomanip>
#include <iostream>
#include <numeric>
#include <sstream>


namespace ns3 {

FabricMetricsCollector::FabricMetricsCollector(FabricClient      *client,
                                                const std::string &outputDir)
    : m_client(client), m_outputDir(outputDir)
{
    (void)0;
}

void
FabricMetricsCollector::RecordHandover(const PerHandoverRecord &record)
{
    m_records.push_back(record);
}

void
FabricMetricsCollector::RecordFlowMonitorStats(Ptr<FlowMonitor>   flowMonitor,
                                                FlowMonitorHelper &helper)
{
    flowMonitor->CheckForLostPackets();
    Ptr<Ipv4FlowClassifier> classifier =
        DynamicCast<Ipv4FlowClassifier>(helper.GetClassifier());
    FlowMonitor::FlowStatsContainer stats = flowMonitor->GetFlowStats();

    for (auto &kv : stats)
    {
        const FlowMonitor::FlowStats &fs = kv.second;

        FlowStats row;
        row.txPackets   = fs.txPackets;
        row.rxPackets   = fs.rxPackets;

        double duration = (fs.timeLastRxPacket - fs.timeFirstTxPacket).GetSeconds();
        if (duration > 0 && fs.rxPackets > 0)
        {
            /* Throughput in Mbps */
            row.throughputMbps = (fs.rxBytes * 8.0) / (duration * 1e6);
            /* Average delay in ms */
            row.avgDelayMs  = (fs.delaySum.GetSeconds() / fs.rxPackets) * 1000.0;
            row.avgJitterMs = (fs.jitterSum.GetSeconds() / fs.rxPackets) * 1000.0;
        }
        else
        {
            row.throughputMbps = 0.0;
            row.avgDelayMs     = 0.0;
            row.avgJitterMs    = 0.0;
        }

        if (fs.txPackets > 0)
            row.packetLossPercent = 100.0 * (1.0 - static_cast<double>(fs.rxPackets)
                                             / fs.txPackets);
        else
            row.packetLossPercent = 0.0;

        m_flowStats.push_back(row);
    }

    (void)0;
}

LatencyComparison
FabricMetricsCollector::ComputeLatencyComparison() const
{
    LatencyComparison lc;

    if (m_records.empty())
    {
        /**
         * BUG FIX: When m_records is empty (e.g. single-attack runs where
         * the attack calls m_fabric->RequestHandover() directly rather than
         * through FabricHandover() in hybrid_full_v3.cc), the comparison
         * was returning {0.0, 5.0, ...} giving "With blockchain: 0.00 ms".
         *
         * Fix: fall back to the ledger's average latency, which IS populated
         * for ALL blockchain transactions regardless of how they were submitted.
         */
        double ledgerAvg = m_client->GetMetrics().avgLatencyMs;
        if (ledgerAvg > 0.0)
        {
            lc.handoverLatencyWithBcMs    = ledgerAvg;
            lc.handoverLatencyWithoutBcMs = BASELINE_HANDOVER_LATENCY_MS;
            lc.overheadMs      = lc.handoverLatencyWithBcMs - lc.handoverLatencyWithoutBcMs;
            lc.overheadPercent = (lc.overheadMs / lc.handoverLatencyWithoutBcMs) * 100.0;
        }
        else
        {
            /* Truly no blockchain activity — BC was disabled */
            lc = {0.0, BASELINE_HANDOVER_LATENCY_MS, 0.0, 0.0};
        }
        return lc;
    }

    /* Average blockchain latency from per-handover records */
    double sumBcMs = 0.0;
    for (const auto &r : m_records) sumBcMs += r.bcLatencyMs;
    lc.handoverLatencyWithBcMs    = sumBcMs / m_records.size();
    lc.handoverLatencyWithoutBcMs = BASELINE_HANDOVER_LATENCY_MS;
    lc.overheadMs      = lc.handoverLatencyWithBcMs - lc.handoverLatencyWithoutBcMs;
    lc.overheadPercent = (lc.overheadMs / lc.handoverLatencyWithoutBcMs) * 100.0;

    return lc;
}

std::pair<double, double>
FabricMetricsCollector::ComputeEnergyComparison(uint32_t numHandovers) const
{
    FabricMetrics fm = m_client->GetMetrics();

    double withBc = fm.totalEnergyMj;

    /* Use ledger TX count if caller passes 0 */
    uint32_t n = (numHandovers > 0) ? numHandovers : fm.totalTransactions;
    double withoutBc = static_cast<double>(n) * BASELINE_ENERGY_PER_HO_MJ;

    return {withBc, withoutBc};
}

void
FabricMetricsCollector::ExportCSV() const
{
    std::string path = m_outputDir + "/fabric_metrics.csv";
    std::ofstream f(path);
    if (!f.is_open())
    {
        (void)0;
        return;
    }

    f << "simTime,sourceAp,targetAp,decision,compositeScore,"
      << "bcLatencyMs,energyCostMj,rssiDbm,trustScore,attackMode\n";

    for (const auto &r : m_records)
    {
        f << std::fixed << std::setprecision(3) << r.simTimeS << ","
          << r.sourceAp       << ","
          << r.targetAp       << ","
          << r.decision        << ","
          << std::setprecision(4) << r.compositeScore << ","
          << std::setprecision(2) << r.bcLatencyMs    << ","
          << std::setprecision(4) << r.energyCostMj   << ","
          << std::setprecision(1) << r.rssiDbm        << ","
          << std::setprecision(3) << r.trustScore      << ","
          << r.attackMode      << "\n";
    }

    f.close();
    (void)0;
}

void
FabricMetricsCollector::ExportLatencyCSV() const
{
    std::string path = m_outputDir + "/latency_comparison.csv";
    std::ofstream f(path);
    if (!f.is_open()) return;

    LatencyComparison lc = ComputeLatencyComparison();

    f << "scenario,handoverLatencyMs\n";
    f << "Without_Blockchain," << std::fixed << std::setprecision(2)
      << lc.handoverLatencyWithoutBcMs << "\n";
    f << "With_Blockchain,"    << std::fixed << std::setprecision(2)
      << lc.handoverLatencyWithBcMs    << "\n";

    /* Per-record breakdown for time-series plot */
    f << "\nsimTime,bcLatencyMs,decision\n";
    for (const auto &r : m_records)
    {
        f << std::fixed << std::setprecision(3) << r.simTimeS << ","
          << std::setprecision(2) << r.bcLatencyMs << ","
          << r.decision << "\n";
    }

    f.close();
}

void
FabricMetricsCollector::ExportEnergyCSV() const
{
    std::string path = m_outputDir + "/energy_comparison.csv";
    std::ofstream f(path);
    if (!f.is_open()) return;

    auto [withBc, withoutBc] =
        ComputeEnergyComparison(static_cast<uint32_t>(m_records.size()));

    f << "scenario,totalEnergyMj,avgPerHandoverMj\n";
    f << "Without_Blockchain,"
      << std::fixed << std::setprecision(4) << withoutBc << ","
      << (m_records.empty() ? 0.0 : withoutBc / m_records.size()) << "\n";
    f << "With_Blockchain,"
      << std::fixed << std::setprecision(4) << withBc << ","
      << (m_records.empty() ? 0.0 : withBc / m_records.size()) << "\n";

    f.close();
}

void
FabricMetricsCollector::PrintFullReport() const
{
    FabricMetrics  fm = m_client->GetMetrics();
    LatencyComparison lc = ComputeLatencyComparison();
    /* Pass 0 → auto-use ledger TX count (covers direct fabric calls too) */
    auto [withBcE, withoutBcE] = ComputeEnergyComparison(0);

    std::cout << "\n";
    std::cout << "╔══════════════════════════════════════════════════════════╗\n";
    std::cout << "║         PERFORMANCE EVALUATION REPORT                   ║\n";
    std::cout << "║         Blockchain-Assisted Secure Handover              ║\n";
    std::cout << "╠══════════════════════════════════════════════════════════╣\n";

    /* --- Blockchain metrics --- */
    std::cout << "║  BLOCKCHAIN (Hyperledger Fabric-inspired)                ║\n";
    std::cout << "║  Total TX submitted    : " << std::setw(6) << fm.totalTransactions
              << "                           ║\n";
    std::cout << "║  Approved handovers    : " << std::setw(6) << fm.approvedHandovers
              << "                           ║\n";
    std::cout << "║  Denied handovers      : " << std::setw(6) << fm.deniedHandovers
              << "                           ║\n";
    std::cout << "║  Block height          : " << std::setw(6) << fm.blockHeight
              << "                           ║\n";

    /* --- Latency comparison --- */
    std::cout << "╠══════════════════════════════════════════════════════════╣\n";
    std::cout << "║  LATENCY COMPARISON                                      ║\n";
    std::cout << "║  Without blockchain    : " << std::setw(8) << std::fixed
              << std::setprecision(2) << lc.handoverLatencyWithoutBcMs << " ms              ║\n";
    std::cout << "║  With blockchain       : " << std::setw(8) << std::fixed
              << std::setprecision(2) << lc.handoverLatencyWithBcMs    << " ms              ║\n";
    std::cout << "║  Avg BC latency        : " << std::setw(8) << std::fixed
              << std::setprecision(2) << fm.avgLatencyMs               << " ms              ║\n";
    std::cout << "║  Min BC latency        : " << std::setw(8) << std::fixed
              << std::setprecision(2) << fm.minLatencyMs               << " ms              ║\n";
    std::cout << "║  Max BC latency        : " << std::setw(8) << std::fixed
              << std::setprecision(2) << fm.maxLatencyMs               << " ms              ║\n";
    std::cout << "║  Overhead              : " << std::setw(8) << std::fixed
              << std::setprecision(2) << lc.overheadMs                 << " ms ("
              << std::setprecision(1) << lc.overheadPercent            << "%)      ║\n";

    /* --- Energy comparison --- */
    std::cout << "╠══════════════════════════════════════════════════════════╣\n";
    std::cout << "║  ENERGY COMPARISON                                       ║\n";
    std::cout << "║  Without BC (total)    : " << std::setw(10) << std::fixed
              << std::setprecision(2) << withoutBcE                    << " mJ            ║\n";
    std::cout << "║  With BC (total)       : " << std::setw(10) << std::fixed
              << std::setprecision(2) << withBcE                       << " mJ            ║\n";
    std::cout << "║  Avg energy/handover   : " << std::setw(10) << std::fixed
              << std::setprecision(4) << fm.avgEnergyPerHandoverMj     << " mJ            ║\n";

    /* --- Flow Monitor stats --- */
    if (!m_flowStats.empty())
    {
        std::cout << "╠══════════════════════════════════════════════════════════╣\n";
        std::cout << "║  NETWORK PERFORMANCE (FlowMonitor)                       ║\n";
        double sumTp = 0, sumDl = 0, sumPl = 0;
        for (const auto &fs : m_flowStats)
        {
            sumTp += fs.throughputMbps;
            sumDl += fs.avgDelayMs;
            sumPl += fs.packetLossPercent;
        }
        size_t n = m_flowStats.size();
        std::cout << "║  Avg throughput        : " << std::setw(8) << std::fixed
                  << std::setprecision(3) << sumTp / n                 << " Mbps            ║\n";
        std::cout << "║  Avg E2E delay         : " << std::setw(8) << std::fixed
                  << std::setprecision(3) << sumDl / n                 << " ms              ║\n";
        std::cout << "║  Avg packet loss       : " << std::setw(8) << std::fixed
                  << std::setprecision(2) << sumPl / n                 << " %               ║\n";
    }

    std::cout << "╚══════════════════════════════════════════════════════════╝\n\n";
}

} // namespace ns3
#endif /* FABRIC_METRICS_H */
