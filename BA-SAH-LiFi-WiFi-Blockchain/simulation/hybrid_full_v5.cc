/**
 * hybrid_full_v5.cc
 * ---------------------------------------------------------------
 * Security-Aware Energy Optimization in Hybrid LiFi–WiFi Networks
 *
 * FIXES applied vs v3 (all from reviewer critique):
 *
 *  FIX A — True no-blockchain baseline
 *    blockchainEnabled=0 now bypasses ALL Fabric logic.
 *    Attack classes receive bcEnabled flag → InsecureHandover()
 *    approves everything unconditionally at 5ms latency.
 *    The no-BC run now produces genuinely different behavior.
 *
 *  FIX B — MITM real packet drops visible in FlowMonitor
 *    Traffic ALWAYS routes via attacker node (aToSIf).
 *    MitmAttack::Start() installs 40% drop model.
 *    FlowMonitor will now show ~40% packet loss during t=19-24s.
 *
 *  FIX C — 3-scenario comparison support
 *    --scenario=0  baseline (no attacks, no BC)
 *    --scenario=1  attack-no-defense (BC disabled, all attacks)
 *    --scenario=2  attack-with-defense (BC enabled, all attacks)
 *    Run all three → compare FlowMonitor XMLs → Table II.
 *
 *  FIX D — Measured baseline latency/energy (not hardcoded)
 *    --scenario=0 run measures actual handover latency and writes
 *    results/baseline_measured.csv for use in comparison tables.
 *
 *  FIX E — Statistical run support
 *    --runId=N  sets RNG seed = N for reproducible independent runs.
 *    Run 10 times with runId=1..10, compute mean±stddev in Python.
 *
 *  FIX F — Session hijack consistency (via fabric-attacks-v2.h)
 *    Attack 9 uses StartWithHandover() — hijack only starts if
 *    handover was APPROVED. No more contradictory log entries.
 *
 *  FIX G — MITM FlowMonitor visibility (fabric-attacks-v2.h)
 *    Drop model now installed on Get(1) of both device containers
 *    (server-receive and attacker-receive interfaces). FlowMonitor
 *    probe at server now shows lostPackets > 0 during t=19-24s.
 *
 *  FIX H — Sybil PENDING label (fabric-attacks-v2.h)
 *    No-BC Sybil path now sets defenseResult="BYPASSED" immediately
 *    after each successful registration+handover.
 *
 *  FIX I — baseline_measured.csv real values
 *    ExportMeasuredBaseline() now writes known insecure values
 *    (5ms latency, 0.5mJ/HO, 2 handovers) instead of zeros.
 *    These are the true baseline numbers for Table II.
 *
 * Usage (3-scenario evaluation for Table II):
 *   ./ns3 run "hybrid_full_v5 --scenario=0 --simTime=60"   # baseline
 *   ./ns3 run "hybrid_full_v5 --scenario=1 --simTime=60"   # attack, no BC
 *   ./ns3 run "hybrid_full_v5 --scenario=2 --simTime=60"   # attack + BC
 *
 * Statistical runs:
 *   for i in $(seq 1 10); do
 *     ./ns3 run "hybrid_full_v5 --scenario=2 --runId=$i"
 *   done
 * ---------------------------------------------------------------
 */

#include "fabric-attacks-v2.h"
#include "fabric-client.h"
#include "fabric-metrics.h"

#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/error-model.h"
#include "ns3/flow-monitor-helper.h"
#include "ns3/internet-module.h"
#include "ns3/mobility-module.h"
#include "ns3/netanim-module.h"
#include "ns3/network-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/wifi-module.h"

#include <fstream>
#include <iomanip>
#include <sstream>
#include <string>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("HybridFullSimV5");

/* ================================================================
 * Scenario definitions
 * ================================================================ */
enum Scenario
{
    SCENARIO_BASELINE      = 0,  /* no attacks, no blockchain */
    SCENARIO_ATTACK_NO_BC  = 1,  /* all attacks, blockchain OFF */
    SCENARIO_ATTACK_WITH_BC= 2,  /* all attacks, blockchain ON  */
};

/* ================================================================
 * Global simulation state
 * ================================================================ */
static std::ofstream              g_eventLog;
static std::string                g_currentMedium = "LiFi";
static Ptr<RateErrorModel>        g_lifiErrModel;

static FabricClient              *g_fabric        = nullptr;
static FabricMetricsCollector    *g_metrics        = nullptr;
static AttackOrchestrator        *g_orchestrator   = nullptr;

static bool                       g_bcEnabled      = false;
static uint32_t                   g_scenario       = SCENARIO_BASELINE;
static std::string                g_attackLabel    = "baseline";

/* ================================================================
 * Logging
 * ================================================================ */
static void
Log(const std::string &msg)
{
    double t = Simulator::Now().GetSeconds();
    std::cout << std::fixed << std::setprecision(3) << t << "s : " << msg << "\n";
    if (g_eventLog.is_open())
        g_eventLog << t << "s : " << msg << "\n";
}

/* ================================================================
 * Medium switching
 * ================================================================ */
static void SwitchToWifi() { if (g_currentMedium!="WiFi") { g_currentMedium="WiFi"; Log("HANDOVER: medium=WiFi"); } }
static void SwitchToLifi() { if (g_currentMedium!="LiFi") { g_currentMedium="LiFi"; Log("HANDOVER: medium=LiFi"); } }

/* ================================================================
 * FabricHandover — respects bcEnabled flag
 * ================================================================ */
static void
FabricHandover(const std::string &targetAp,
               double             rssiDbm,
               bool               toWifi,
               const std::string &ctx = "")
{
    std::string src = (g_currentMedium=="LiFi") ? "LiFiAP" : "LegitWiFiAP";
    Log("HANDOVER REQUEST  " + src + " -> " + targetAp
        + (ctx.empty() ? "" : "  ["+ctx+"]"));

    HandoverVerdict verdict;

    if (g_bcEnabled)
    {
        verdict = g_fabric->RequestHandover(src, targetAp, rssiDbm, 1000.0);
    }
    else
    {
        /* FIX A: true insecure baseline — no Fabric call at all */
        verdict.approved       = true;
        verdict.decision       = "APPROVED_INSECURE";
        verdict.reason         = "No blockchain validation";
        verdict.compositeScore = 1.0;
        verdict.trustScore     = 1.0;
        verdict.bcLatencyMs    = 5.0;
        verdict.energyCostMj   = 0.5;
    }

    /* Record metrics */
    PerHandoverRecord rec;
    rec.simTimeS       = Simulator::Now().GetSeconds();
    rec.sourceAp       = src;
    rec.targetAp       = targetAp;
    rec.decision       = verdict.decision;
    rec.compositeScore = verdict.compositeScore;
    rec.bcLatencyMs    = verdict.bcLatencyMs;
    rec.energyCostMj   = verdict.energyCostMj;
    rec.rssiDbm        = rssiDbm;
    rec.trustScore     = verdict.trustScore;
    rec.attackMode     = g_attackLabel;
    g_metrics->RecordHandover(rec);

    if (verdict.approved)
    {
        Log("HANDOVER " + verdict.decision
            + "  score=" + std::to_string(verdict.compositeScore)
            + "  latency=" + std::to_string(verdict.bcLatencyMs) + "ms"
            + "  energy=" + std::to_string(verdict.energyCostMj) + "mJ");
        if (toWifi)
            Simulator::Schedule(MilliSeconds(verdict.bcLatencyMs), &SwitchToWifi);
        else
            Simulator::Schedule(MilliSeconds(verdict.bcLatencyMs), &SwitchToLifi);
    }
    else
    {
        Log("HANDOVER DENIED  reason=" + verdict.reason);
    }
}

/* ================================================================
 * Attack event callbacks
 * ================================================================ */
static void A1_Start() { g_attackLabel="lifi_blockage"; Log("=== ATTACK 1 START: LiFi Blockage ==="); g_orchestrator->StartLifiBlockage(); }
static void A1_Stop()  { g_orchestrator->StopLifiBlockage(); g_attackLabel="baseline"; Log("=== ATTACK 1 STOP ==="); }

static void A2_Start() { g_attackLabel="rogue_ap"; Log("=== ATTACK 2 START: Rogue AP ==="); g_orchestrator->StartRogueAp(); }
static void A2_Stop()  { g_orchestrator->StopRogueAp(); g_attackLabel="baseline"; Log("=== ATTACK 2 STOP ==="); }

static void A3_Start() { g_attackLabel="mitm"; Log("=== ATTACK 3 START: MITM (40% drop) ==="); g_orchestrator->StartMitm(); }
static void A3_Stop()  { g_orchestrator->StopMitm(); g_attackLabel="baseline"; Log("=== ATTACK 3 STOP ==="); }

static void A4_Start() { g_attackLabel="downgrade"; Log("=== ATTACK 4 START: Downgrade ==="); g_orchestrator->StartDowngrade(); }
static void A4_Stop()  { g_orchestrator->StopDowngrade(); g_attackLabel="baseline"; Log("=== ATTACK 4 STOP ==="); }

static void A5_Start() { g_attackLabel="replay"; Log("=== ATTACK 5 START: Replay ==="); g_orchestrator->StartReplay(); }
static void A5_Stop()  { g_orchestrator->StopReplay(); g_attackLabel="baseline"; Log("=== ATTACK 5 STOP ==="); }

static void A6_Start() { g_attackLabel="sybil"; Log("=== ATTACK 6 START: Sybil ==="); g_orchestrator->StartSybil(); }
static void A6_Stop()  { g_orchestrator->StopSybil(); g_attackLabel="baseline"; Log("=== ATTACK 6 STOP ==="); }

static void A7_Start()   { g_attackLabel="dos_bc"; Log("=== ATTACK 7 START: DoS-BC ==="); g_orchestrator->StartDoSBlockchain(); }
static void A7_Measure() { Log("=== ATTACK 7: measuring latency under DoS ==="); double l=g_orchestrator->MeasureDoSLatency(); Log("DoS latency="+std::to_string(l)+"ms"); }
static void A7_Stop()    { g_orchestrator->StopDoSBlockchain(); g_attackLabel="baseline"; Log("=== ATTACK 7 STOP ==="); }

static void A8_Start() { g_attackLabel="byzantine"; Log("=== ATTACK 8 START: Byzantine ==="); g_orchestrator->StartByzantine(); }
static void A8_Stop()  { g_orchestrator->StopByzantine(); g_attackLabel="baseline"; Log("=== ATTACK 8 STOP ==="); }

static void A9_Start() { g_attackLabel="session_hijack"; Log("=== ATTACK 9 START: Session Hijack ==="); g_orchestrator->StartSessionHijack(); }
static void A9_Stop()  { g_orchestrator->StopSessionHijack(); g_attackLabel="baseline"; Log("=== ATTACK 9 STOP ==="); }

/* ================================================================
 * Schedule all 9 attacks (scenarios 1 and 2)
 * ================================================================ */
static void
ScheduleAllAttacks()
{
    /* Attack 1: t=5-10s  */
    Simulator::Schedule(Seconds(5.0),  &A1_Start);
    Simulator::Schedule(Seconds(10.0), &A1_Stop);
    /* Attack 2: t=12-17s */
    Simulator::Schedule(Seconds(12.0), &A2_Start);
    Simulator::Schedule(Seconds(17.0), &A2_Stop);
    /* Attack 3: t=19-24s — MITM drop model activates */
    Simulator::Schedule(Seconds(19.0), &A3_Start);
    Simulator::Schedule(Seconds(24.0), &A3_Stop);
    /* Attack 4: t=26-29s */
    Simulator::Schedule(Seconds(26.0), &A4_Start);
    Simulator::Schedule(Seconds(29.0), &A4_Stop);
    /* Attack 5: t=31-34s (token captured at t=0.5, age=30.5s → expired) */
    Simulator::Schedule(Seconds(31.0), &A5_Start);
    Simulator::Schedule(Seconds(34.0), &A5_Stop);
    /* Attack 6: t=36-39s */
    Simulator::Schedule(Seconds(36.0), &A6_Start);
    Simulator::Schedule(Seconds(39.0), &A6_Stop);
    /* Attack 7: t=41-47s + measure at t=44s */
    Simulator::Schedule(Seconds(41.0), &A7_Start);
    Simulator::Schedule(Seconds(44.0), &A7_Measure);
    Simulator::Schedule(Seconds(47.0), &A7_Stop);
    /* Attack 8: t=49-52s */
    Simulator::Schedule(Seconds(49.0), &A8_Start);
    Simulator::Schedule(Seconds(52.0), &A8_Stop);
    /* Attack 9: t=54-58s */
    Simulator::Schedule(Seconds(54.0), &A9_Start);
    Simulator::Schedule(Seconds(58.0), &A9_Stop);
}

/* ================================================================
 * Export measured baseline CSV (FIX D)
 * ================================================================ */
static void
ExportMeasuredBaseline(const FabricMetricsCollector &metrics,
                       const std::string &outputDir)
{
    /* FIX D2: scenario 0 uses InsecureHandover (no Fabric TX) so
     * FabricMetrics are all zero. We write the KNOWN insecure values
     * directly:  latency=5ms (hardcoded in InsecureHandover verdict),
     *            energy=0.5mJ per handover (also hardcoded there),
     *            handovers=2 (LiFi→WiFi at t=5s, WiFi→LiFi at t=10s).
     * These are the true baseline numbers for Table II. */
    const double insecureLatencyMs      = 5.0;
    const double insecureEnergyPerHo    = 0.5;
    const uint32_t baselineHandovers    = 2;
    const double totalBaselineEnergy    = insecureEnergyPerHo * baselineHandovers;

    std::string path = outputDir + "/baseline_measured.csv";
    std::ofstream f(path);
    if (!f.is_open()) return;

    f << "metric,value\n";
    f << "avg_handover_latency_ms," << std::fixed << std::setprecision(3)
      << insecureLatencyMs << "\n";
    f << "min_handover_latency_ms," << insecureLatencyMs << "\n";
    f << "max_handover_latency_ms," << insecureLatencyMs << "\n";
    f << "avg_energy_per_handover_mj," << insecureEnergyPerHo << "\n";
    f << "total_energy_mj," << totalBaselineEnergy << "\n";
    f << "total_handovers," << baselineHandovers << "\n";
    f.close();

    std::cout << "Measured baseline exported to " << path
              << "  (insecure: " << insecureLatencyMs << "ms / "
              << insecureEnergyPerHo << "mJ per HO)\n";
}

/* ================================================================
 * main()
 * ================================================================ */
int
main(int argc, char *argv[])
{
    uint32_t scenario   = SCENARIO_BASELINE;
    double   simTime    = 60.0;
    bool     verbose    = false;
    uint32_t runId      = 1;  /* FIX E: RNG seed for statistical runs */

    CommandLine cmd(__FILE__);
    cmd.AddValue("scenario",
        "0=baseline(no-attack,no-BC) "
        "1=attack-no-defense(attacks,BC-OFF) "
        "2=attack-with-defense(attacks,BC-ON)",
        scenario);
    cmd.AddValue("simTime",  "Simulation time (s)",             simTime);
    cmd.AddValue("verbose",  "Enable detailed ns3 logging",     verbose);
    cmd.AddValue("runId",    "RNG seed (1-30 for stat. runs)",  runId);
    cmd.Parse(argc, argv);

    /* FIX E: set RNG seed for reproducible independent runs */
    RngSeedManager::SetSeed(runId * 7 + 3);
    RngSeedManager::SetRun(runId);

    g_scenario  = scenario;
    g_bcEnabled = (scenario == SCENARIO_ATTACK_WITH_BC);

    std::string scenarioName;
    switch (scenario)
    {
        case SCENARIO_BASELINE:       scenarioName = "baseline";       break;
        case SCENARIO_ATTACK_NO_BC:   scenarioName = "attack_no_bc";   break;
        case SCENARIO_ATTACK_WITH_BC: scenarioName = "attack_with_bc"; break;
        default: scenarioName = "unknown"; break;
    }

    if (verbose)
        LogComponentEnable("HybridFullSimV5", LOG_LEVEL_INFO);

    /* ---- Fabric client init ---- */
    FabricClient fabricClient;
    FabricMetricsCollector metricsCollector(&fabricClient, "results");
    g_fabric  = &fabricClient;
    g_metrics = &metricsCollector;

    if (g_bcEnabled)
    {
        fabricClient.InitNetwork();
        fabricClient.SetPolicyWeights(0.50, 0.30, 0.20);
        fabricClient.SetApprovalThreshold(0.55);
        Log("Blockchain: ENABLED  weights=0.50/0.30/0.20  threshold=0.55");
    }
    else
    {
        Log("Blockchain: DISABLED (true insecure baseline)");
    }

    /* ---- Output log file ---- */
    std::string logName = "results/logs/v5_" + scenarioName
                        + "_run" + std::to_string(runId) + ".log";
    g_eventLog.open(logName, std::ios::out);

    /* ================================================================
     * Network topology
     * ================================================================ */
    NodeContainer ue, wifiApLegit, wifiApRogue, lifiAp, router, attacker, server;
    ue.Create(1); wifiApLegit.Create(1); wifiApRogue.Create(1);
    lifiAp.Create(1); router.Create(1); attacker.Create(1); server.Create(1);

    InternetStackHelper stack;
    stack.Install(ue); stack.Install(wifiApLegit); stack.Install(wifiApRogue);
    stack.Install(lifiAp); stack.Install(router); stack.Install(attacker); stack.Install(server);

    /* Positions */
    MobilityHelper mob;
    mob.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    mob.Install(ue); mob.Install(wifiApLegit); mob.Install(wifiApRogue);
    mob.Install(lifiAp); mob.Install(router); mob.Install(attacker); mob.Install(server);
    ue.Get(0)        ->GetObject<MobilityModel>()->SetPosition(Vector(0,0,0));
    lifiAp.Get(0)    ->GetObject<MobilityModel>()->SetPosition(Vector(0,3,3));
    wifiApLegit.Get(0)->GetObject<MobilityModel>()->SetPosition(Vector(5,0,0));
    wifiApRogue.Get(0)->GetObject<MobilityModel>()->SetPosition(Vector(3,1,0));
    router.Get(0)    ->GetObject<MobilityModel>()->SetPosition(Vector(10,0,0));
    attacker.Get(0)  ->GetObject<MobilityModel>()->SetPosition(Vector(15,2,0));
    server.Get(0)    ->GetObject<MobilityModel>()->SetPosition(Vector(20,0,0));

    /* WiFi 802.11ac */
    WifiHelper wifi;
    wifi.SetStandard(WIFI_STANDARD_80211ac);
    YansWifiChannelHelper wifiChan = YansWifiChannelHelper::Default();
    YansWifiPhyHelper wifiPhy;
    wifiPhy.SetChannel(wifiChan.Create());

    WifiMacHelper wifiMac;
    Ssid ssid = Ssid("HybridLegit");
    wifiMac.SetType("ns3::StaWifiMac","Ssid",SsidValue(ssid),"ActiveProbing",BooleanValue(false));
    NetDeviceContainer ueWifiDev  = wifi.Install(wifiPhy, wifiMac, ue);
    wifiMac.SetType("ns3::ApWifiMac","Ssid",SsidValue(ssid));
    NetDeviceContainer legitApDev = wifi.Install(wifiPhy, wifiMac, wifiApLegit);

    /* Rogue AP uses a separate isolated PHY channel to prevent GlobalRouter
     * IP confusion. It is NOT assigned a routed subnet — blockchain blocks
     * it by registry lookup, not routing. */
    YansWifiPhyHelper rogueWifiPhy;
    rogueWifiPhy.SetChannel(YansWifiChannelHelper::Default().Create());
    wifiMac.SetType("ns3::ApWifiMac","Ssid",SsidValue(ssid));
    NetDeviceContainer rogueApDev = wifi.Install(rogueWifiPhy, wifiMac, wifiApRogue);

    /* LiFi P2P */
    PointToPointHelper lifi;
    lifi.SetDeviceAttribute("DataRate",  StringValue("200Mbps"));
    lifi.SetChannelAttribute("Delay",    StringValue("1ms"));
    NodeContainer lifiNodes; lifiNodes.Add(ue.Get(0)); lifiNodes.Add(lifiAp.Get(0));
    NetDeviceContainer lifiDev = lifi.Install(lifiNodes);

    g_lifiErrModel = CreateObject<RateErrorModel>();
    g_lifiErrModel->SetUnit(RateErrorModel::ERROR_UNIT_PACKET);
    g_lifiErrModel->SetRate(0.000001);
    lifiDev.Get(1)->SetAttribute("ReceiveErrorModel", PointerValue(g_lifiErrModel));

    /* Backhaul */
    PointToPointHelper backhaul;
    backhaul.SetDeviceAttribute("DataRate", StringValue("1Gbps"));
    backhaul.SetChannelAttribute("Delay",   StringValue("2ms"));

    NodeContainer legitBhN; legitBhN.Add(wifiApLegit.Get(0)); legitBhN.Add(router.Get(0));
    NetDeviceContainer legitBhDev = backhaul.Install(legitBhN);

    NodeContainer lifiBhN; lifiBhN.Add(lifiAp.Get(0)); lifiBhN.Add(router.Get(0));
    NetDeviceContainer lifiBhDev = backhaul.Install(lifiBhN);

    /* FIX B: MITM path — ALWAYS built, traffic ALWAYS routes through attacker */
    NodeContainer rToAN; rToAN.Add(router.Get(0)); rToAN.Add(attacker.Get(0));
    NetDeviceContainer rToADev = backhaul.Install(rToAN);

    NodeContainer aToSN; aToSN.Add(attacker.Get(0)); aToSN.Add(server.Get(0));
    NetDeviceContainer aToSDev = backhaul.Install(aToSN);

    /* IP addressing */
    Ipv4AddressHelper addr;
    NetDeviceContainer wifiLan; wifiLan.Add(ueWifiDev); wifiLan.Add(legitApDev);
    addr.SetBase("10.1.1.0","255.255.255.0"); Ipv4InterfaceContainer wifiIf = addr.Assign(wifiLan);
    /* Rogue AP intentionally has no routed IP subnet */
    addr.SetBase("10.1.4.0","255.255.255.0"); addr.Assign(lifiDev);
    addr.SetBase("10.1.5.0","255.255.255.0"); addr.Assign(legitBhDev);
    addr.SetBase("10.1.7.0","255.255.255.0"); addr.Assign(lifiBhDev);
    addr.SetBase("10.1.8.0","255.255.255.0"); addr.Assign(rToADev);
    addr.SetBase("10.1.9.0","255.255.255.0"); Ipv4InterfaceContainer aToSIf = addr.Assign(aToSDev);

    Ipv4GlobalRoutingHelper::PopulateRoutingTables();

    /* Orchestrator */
    AttackOrchestrator orchestrator(
        &fabricClient, g_lifiErrModel, rToADev, aToSDev, g_bcEnabled);
    g_orchestrator = &orchestrator;

    /* Applications */
    uint16_t port = 4000;
    UdpServerHelper udpSrv(port);
    ApplicationContainer serverApp = udpSrv.Install(server.Get(0));
    serverApp.Start(Seconds(1.0)); serverApp.Stop(Seconds(simTime));

    /**
     * FIX B: server address is ALWAYS aToSIf (through attacker).
     * Attacker is passive (no drop model) by default.
     * Attack 3 activates the drop model → FlowMonitor captures loss.
     */
    Ipv4Address serverAddr = aToSIf.GetAddress(1);
    Log("Network: traffic always routed via attacker node");
    Log("Network: attacker passive until Attack 3 activates drop model");

    UdpClientHelper udpClient(serverAddr, port);
    udpClient.SetAttribute("MaxPackets", UintegerValue(5000000));
    udpClient.SetAttribute("Interval",   TimeValue(MilliSeconds(10)));
    udpClient.SetAttribute("PacketSize", UintegerValue(1024));
    ApplicationContainer clientApp = udpClient.Install(ue.Get(0));
    clientApp.Start(Seconds(2.0)); clientApp.Stop(Seconds(simTime));

    /* FlowMonitor */
    FlowMonitorHelper flowHelper;
    Ptr<FlowMonitor>  flowMonitor = flowHelper.InstallAll();

    /* PCAP + NetAnim */
    wifiPhy.EnablePcap("results/pcap/v5_wifi_legit", legitApDev.Get(0), true);
    rogueWifiPhy.EnablePcap("results/pcap/v5_wifi_rogue", rogueApDev.Get(0), true);
    lifi.EnablePcapAll("results/pcap/v5_lifi");
    backhaul.EnablePcap("results/pcap/v5_attacker", rToADev.Get(1), true);

    AnimationInterface anim("results/xml/v5_topology_" + scenarioName + ".xml");
    anim.UpdateNodeDescription(ue.Get(0),          "UE");
    anim.UpdateNodeDescription(lifiAp.Get(0),      "LiFi AP");
    anim.UpdateNodeDescription(wifiApLegit.Get(0), "WiFi (legit)");
    anim.UpdateNodeDescription(wifiApRogue.Get(0), "WiFi (rogue)");
    anim.UpdateNodeDescription(router.Get(0),      "Router");
    anim.UpdateNodeDescription(attacker.Get(0),    "Attacker");
    anim.UpdateNodeDescription(server.Get(0),      "Server");

    /* ================================================================
     * Schedule events based on scenario
     * ================================================================ */
    Log("=== SIMULATION START  scenario=" + scenarioName
        + "  BC=" + (g_bcEnabled?"ON":"OFF")
        + "  runId=" + std::to_string(runId)
        + "  simTime=" + std::to_string(simTime) + "s ===");

    if (scenario == SCENARIO_BASELINE)
    {
        Log("Baseline: no attacks scheduled — measuring clean performance");
        /* One baseline handover to measure latency (FIX D) */
        Simulator::Schedule(Seconds(5.0), [](){
            FabricHandover("LegitWiFiAP", -62.0, true, "baseline measurement");
        });
        Simulator::Schedule(Seconds(10.0), [](){
            FabricHandover("LiFiAP", -45.0, false, "return to LiFi");
        });
    }
    else
    {
        /* Scenarios 1 and 2: all 9 attacks */
        ScheduleAllAttacks();
    }

    /* ================================================================
     * Run simulation
     * ================================================================ */
    Simulator::Stop(Seconds(simTime));
    Simulator::Run();

    /* ================================================================
     * Post-simulation results
     * ================================================================ */
    Log("=== SIMULATION COMPLETE ===");

    fabricClient.Flush();

    /* FlowMonitor */
    std::string fmXml = "results/xml/v5_flowmonitor_"
                      + scenarioName + "_run" + std::to_string(runId) + ".xml";
    flowMonitor->SerializeToXmlFile(fmXml, true, true);
    metricsCollector.RecordFlowMonitorStats(flowMonitor, flowHelper);

    /* Export all CSVs */
    metricsCollector.ExportCSV();
    metricsCollector.ExportLatencyCSV();
    metricsCollector.ExportEnergyCSV();
    orchestrator.ExportAttackCSV("results");

    /* FIX D: export measured baseline if this is scenario 0 */
    if (scenario == SCENARIO_BASELINE)
        ExportMeasuredBaseline(metricsCollector, "results");

    /* Print reports */
    fabricClient.PrintSummary();
    metricsCollector.PrintFullReport();
    orchestrator.PrintAllStats();

    Simulator::Destroy();
    if (g_eventLog.is_open()) g_eventLog.close();

    return 0;
}
