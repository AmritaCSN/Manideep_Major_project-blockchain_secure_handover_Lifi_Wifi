#!/usr/bin/env python3
"""
analyze_stats.py — Statistical analysis for hybrid LiFi-WiFi simulation
Security-Aware Energy Optimization in Hybrid LiFi–WiFi Networks

Use from ns-3 root:
  cd ~/ns-3-dev
  python3 scratch/hybrid-project/analyze_stats.py

This version is fixed for:
  - v5_flowmonitor_* XML files
  - ns-3 time strings such as 3.53215e10ns
  - CSV columns such as handoverLatencyMs, bcLatencyMs, totalLatencyMs
  - repeated header rows inside CSV files
"""

import os
import csv
import math
import re
import xml.etree.ElementTree as ET

# ── Configuration ─────────────────────────────────────────────────────────────

FLOW_PREFIX = "v5"
N_RUNS = 10


def find_results_dir():
    """
    Allows the script to run from:
      1) ~/ns-3-dev
      2) ~/ns-3-dev/scratch/hybrid-project
    """
    script_dir = os.path.dirname(os.path.abspath(__file__))

    candidates = [
        os.path.abspath("results"),
        os.path.abspath(os.path.join(script_dir, "..", "..", "results")),
        os.path.abspath(os.path.join(script_dir, "results")),
    ]

    for path in candidates:
        if os.path.isdir(os.path.join(path, "xml")):
            return path

    # fallback
    return os.path.abspath("results")


RESULTS_DIR = find_results_dir()
STATS_DIR = os.path.join(RESULTS_DIR, "stats_output")
os.makedirs(STATS_DIR, exist_ok=True)

# ── Helpers ──────────────────────────────────────────────────────────────────


def mean(vals):
    return sum(vals) / len(vals) if vals else 0.0


def stddev(vals):
    if len(vals) < 2:
        return 0.0
    m = mean(vals)
    return math.sqrt(sum((x - m) ** 2 for x in vals) / (len(vals) - 1))


def ci95(vals):
    """95% confidence interval half-width using t=2.262 for n=10, df=9."""
    if len(vals) < 2:
        return 0.0
    return 2.262 * stddev(vals) / math.sqrt(len(vals))


def fmt(m, s, c):
    return f"{m:.3f} ± {s:.3f} (95% CI ±{c:.3f})"


def safe_float(value):
    """
    Safely extract a number from strings like:
      187.92
      187.92ms
      3.53215e10ns
      4898.0 mJ
    Returns None if no number is found.
    """
    if value is None:
        return None

    text = str(value).strip().replace("+", "").replace(",", "")
    if not text:
        return None

    match = re.search(r"[-+]?\d*\.?\d+(?:[eE][-+]?\d+)?", text)
    if not match:
        return None

    try:
        return float(match.group(0))
    except ValueError:
        return None


def safe_int(value):
    x = safe_float(value)
    return int(x) if x is not None else 0


def parse_time_to_ns(value):
    """
    Convert ns-3 time strings into nanoseconds.

    Examples:
      3.53215e10ns -> 35321500000 ns
      12.5ms       -> 12500000 ns
      2s           -> 2000000000 ns
    """
    if value is None:
        return 0.0

    text = str(value).strip().replace("+", "")
    number = safe_float(text)

    if number is None:
        return 0.0

    lower = text.lower()

    if lower.endswith("ns"):
        return number
    if lower.endswith("us") or lower.endswith("µs"):
        return number * 1e3
    if lower.endswith("ms"):
        return number * 1e6
    if lower.endswith("s"):
        return number * 1e9

    # If no unit is present, assume ns because FlowMonitor stores delaySum in ns.
    return number


def first_numeric(row, columns):
    """
    Return first valid numeric value from possible column names.
    """
    for col in columns:
        if col in row:
            value = safe_float(row.get(col))
            if value is not None:
                return value
    return None


# ── Parse FlowMonitor XML ─────────────────────────────────────────────────────


def parse_flowmonitor(xml_path):
    """Return (throughput_mbps, e2e_delay_ms, packet_loss_pct) or None."""

    if not os.path.exists(xml_path):
        return None

    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()

        flows = root.find("FlowStats")
        if flows is None:
            flows = root.find(".//FlowStats")

        if flows is None:
            print(f"  WARNING: FlowStats section not found in {xml_path}")
            return None

        total_rx_bytes = 0
        total_tx_pkts = 0
        total_rx_pkts = 0
        total_lost = 0
        total_delay_ns = 0.0

        # Your applications start at 2s and stop at 60s.
        sim_duration_s = 58.0

        valid_flows = 0

        for flow in flows.findall("Flow"):
            rx_bytes = safe_int(flow.get("rxBytes", 0))
            tx_pkts = safe_int(flow.get("txPackets", 0))
            rx_pkts = safe_int(flow.get("rxPackets", 0))
            lost = safe_int(flow.get("lostPackets", 0))
            delay_ns = parse_time_to_ns(flow.get("delaySum", "0"))

            total_rx_bytes += rx_bytes
            total_tx_pkts += tx_pkts
            total_rx_pkts += rx_pkts
            total_lost += lost
            total_delay_ns += delay_ns
            valid_flows += 1

        if valid_flows == 0:
            print(f"  WARNING: no Flow entries found in {xml_path}")
            return None

        throughput = (total_rx_bytes * 8) / (sim_duration_s * 1e6)
        loss_pct = (total_lost / total_tx_pkts * 100) if total_tx_pkts > 0 else 0.0
        delay_ms = (total_delay_ns / total_rx_pkts / 1e6) if total_rx_pkts > 0 else 0.0

        return throughput, delay_ms, loss_pct

    except Exception as e:
        print(f"  WARNING: could not parse {xml_path}: {e}")
        return None


# ── Parse Latency CSV ─────────────────────────────────────────────────────────


def parse_latency_csv(csv_path):
    """
    Return (no_bc_ms, with_bc_ms) or None.

    Supports different possible formats:
      scenario,handoverLatencyMs
      scenario,bcLatencyMs
      scenario,totalLatencyMs
      scenario,avgLatencyMs
      noBcLatencyMs,withBcLatencyMs
    """

    if not os.path.exists(csv_path):
        return None

    try:
        no_bc = None
        with_bc = None

        with open(csv_path, newline="") as f:
            reader = csv.DictReader(f)

            for row in reader:
                # Skip empty or malformed rows
                if not row:
                    continue

                scenario = str(row.get("scenario", "")).strip()
                scenario_lower = scenario.lower()

                # Skip repeated header rows
                if scenario_lower == "scenario":
                    continue

                value = first_numeric(
                    row,
                    [
                        "handoverLatencyMs",
                        "totalLatencyMs",
                        "avgLatencyMs",
                        "latencyMs",
                        "bcLatencyMs",
                        "handover_latency_ms",
                        "latency_ms",
                    ],
                )

                # Row-based format
                if value is not None and scenario_lower:
                    if (
                        "without" in scenario_lower
                        or "no_bc" in scenario_lower
                        or "nobc" in scenario_lower
                        or "no-blockchain" in scenario_lower
                    ):
                        no_bc = value

                    elif (
                        "with" in scenario_lower
                        or "with_bc" in scenario_lower
                        or "withbc" in scenario_lower
                        or "blockchain" in scenario_lower
                    ):
                        with_bc = value

                # Column-based format
                if no_bc is None:
                    no_bc = first_numeric(
                        row,
                        [
                            "Without_Blockchain",
                            "withoutBlockchainMs",
                            "noBcLatencyMs",
                            "no_bc_ms",
                            "latencyNoBcMs",
                        ],
                    )

                if with_bc is None:
                    with_bc = first_numeric(
                        row,
                        [
                            "With_Blockchain",
                            "withBlockchainMs",
                            "withBcLatencyMs",
                            "bcLatencyMs",
                            "with_bc_ms",
                            "latencyWithBcMs",
                        ],
                    )

        if no_bc is None and with_bc is None:
            return None

        return no_bc, with_bc

    except Exception as e:
        print(f"  WARNING: could not parse {csv_path}: {e}")
        return None


# ── Parse Energy CSV ──────────────────────────────────────────────────────────


def parse_energy_csv(csv_path):
    """Return (without_bc_mj, with_bc_mj) or None."""

    if not os.path.exists(csv_path):
        return None

    try:
        no_bc = None
        with_bc = None

        with open(csv_path, newline="") as f:
            reader = csv.DictReader(f)

            for row in reader:
                if not row:
                    continue

                scenario = str(row.get("scenario", "")).strip()
                scenario_lower = scenario.lower()

                if scenario_lower == "scenario":
                    continue

                value = first_numeric(
                    row,
                    [
                        "totalEnergyMj",
                        "totalEnergyMJ",
                        "energyMj",
                        "energy_mj",
                        "total_energy_mj",
                    ],
                )

                if value is not None and scenario_lower:
                    if (
                        "without" in scenario_lower
                        or "no_bc" in scenario_lower
                        or "nobc" in scenario_lower
                        or "no-blockchain" in scenario_lower
                    ):
                        no_bc = value

                    elif (
                        "with" in scenario_lower
                        or "with_bc" in scenario_lower
                        or "withbc" in scenario_lower
                        or "blockchain" in scenario_lower
                    ):
                        with_bc = value

                if no_bc is None:
                    no_bc = first_numeric(
                        row,
                        [
                            "Without_Blockchain",
                            "withoutBlockchainMj",
                            "noBcEnergyMj",
                            "no_bc_mj",
                        ],
                    )

                if with_bc is None:
                    with_bc = first_numeric(
                        row,
                        [
                            "With_Blockchain",
                            "withBlockchainMj",
                            "withBcEnergyMj",
                            "bcEnergyMj",
                            "with_bc_mj",
                        ],
                    )

        if no_bc is None and with_bc is None:
            return None

        return no_bc, with_bc

    except Exception as e:
        print(f"  WARNING: could not parse {csv_path}: {e}")
        return None


# ── Parse Attack Summary CSV ──────────────────────────────────────────────────


def parse_attack_csv(csv_path):
    """Return dict: attack_name -> metrics."""

    if not os.path.exists(csv_path):
        return None

    try:
        attacks = {}

        with open(csv_path, newline="") as f:
            reader = csv.DictReader(f)

            for row in reader:
                if not row:
                    continue

                attack = str(row.get("attack", "")).strip()

                # Skip empty rows or repeated header rows
                if not attack or attack.lower() == "attack":
                    continue

                attacks[attack] = {
                    "attempts": safe_int(row.get("attempts", 0)),
                    "blocked": safe_int(row.get("blocked", 0)),
                    "ho_succ": safe_int(row.get("handover_succeeded", 0)),
                    "latency": safe_float(row.get("latencyImpactMs", 0)) or 0.0,
                    "loss": safe_float(row.get("packetLoss%", 0)) or 0.0,
                    "defense": str(row.get("defenseResult", "")).strip(),
                }

        return attacks if attacks else None

    except Exception as e:
        print(f"  WARNING: could not parse {csv_path}: {e}")
        return None


# ── Collect data across runs ──────────────────────────────────────────────────

print("=" * 60)
print("Statistical Analysis — Hybrid LiFi-WiFi Simulation")
print(f"Results directory: {RESULTS_DIR}")
print(f"Collecting data from {N_RUNS} runs per scenario")
print("=" * 60)

scenarios = {
    0: "baseline",
    1: "attack_no_bc",
    2: "attack_with_bc",
}

net = {s: {"throughput": [], "delay": [], "loss": []} for s in scenarios}

latency_no_bc = []
latency_with_bc = []
energy_no_bc = []
energy_with_bc = []

attack_data = {}

for run in range(1, N_RUNS + 1):
    print(f"\n  Run {run}:")

    for sc_id, sc_name in scenarios.items():
        xml = os.path.join(
            RESULTS_DIR,
            "xml",
            f"{FLOW_PREFIX}_flowmonitor_{sc_name}_run{run}.xml",
        )

        if not os.path.exists(xml):
            print(f"    sc{sc_id}: FlowMonitor XML not found — {xml}")
            continue

        fm = parse_flowmonitor(xml)

        if fm is not None:
            net[sc_id]["throughput"].append(fm[0])
            net[sc_id]["delay"].append(fm[1])
            net[sc_id]["loss"].append(fm[2])

            print(
                f"    sc{sc_id}: throughput={fm[0]:.3f} Mbps  "
                f"delay={fm[1]:.2f}ms  loss={fm[2]:.1f}%"
            )
        else:
            print(f"    sc{sc_id}: FlowMonitor XML exists but could not be parsed")

    lat_csv = os.path.join(RESULTS_DIR, "latency_comparison.csv")
    lat = parse_latency_csv(lat_csv)

    if lat is not None:
        no_bc_val, with_bc_val = lat

        if no_bc_val is not None:
            latency_no_bc.append(no_bc_val)

        if with_bc_val is not None:
            latency_with_bc.append(with_bc_val)

    eng_csv = os.path.join(RESULTS_DIR, "energy_comparison.csv")
    eng = parse_energy_csv(eng_csv)

    if eng is not None:
        no_bc_val, with_bc_val = eng

        if no_bc_val is not None:
            energy_no_bc.append(no_bc_val)

        if with_bc_val is not None:
            energy_with_bc.append(with_bc_val)

    atk_csv = os.path.join(RESULTS_DIR, "attack_summary.csv")
    atk = parse_attack_csv(atk_csv)

    if atk:
        for name, vals in atk.items():
            if name not in attack_data:
                attack_data[name] = {
                    "blocked": [],
                    "ho_succ": [],
                    "latency": [],
                    "loss": [],
                    "defense": vals["defense"],
                }

            attack_data[name]["blocked"].append(vals["blocked"])
            attack_data[name]["ho_succ"].append(vals["ho_succ"])
            attack_data[name]["latency"].append(vals["latency"])
            attack_data[name]["loss"].append(vals["loss"])


# ── Compute statistics ────────────────────────────────────────────────────────

print("\n" + "=" * 60)
print("RESULTS")
print("=" * 60)

print("\nTable I — Network Performance (mean ± std dev, 95% CI)")
print(f"{'Metric':<30} {'Scenario 0':>25} {'Scenario 1':>25} {'Scenario 2':>25}")
print("-" * 105)

for metric, label, unit in [
    ("throughput", "Throughput", "Mbps"),
    ("delay", "E2E delay", "ms"),
    ("loss", "Packet loss", "%"),
]:
    row = f"  {label} ({unit}){'':10}"

    for sc_id in [0, 1, 2]:
        vals = net[sc_id][metric]

        if vals:
            m, s, c = mean(vals), stddev(vals), ci95(vals)
            row += f"  {m:.3f}±{s:.3f}(CI±{c:.3f})"
        else:
            row += "  n/a"

    print(row)


print("\nTable II — Blockchain Performance")

if latency_no_bc or latency_with_bc:
    if latency_no_bc:
        m0, s0, c0 = mean(latency_no_bc), stddev(latency_no_bc), ci95(latency_no_bc)
        print(f"  Handover latency without BC:  {fmt(m0, s0, c0)} ms")
    else:
        print("  Handover latency without BC:  n/a")

    if latency_with_bc:
        m1, s1, c1 = mean(latency_with_bc), stddev(latency_with_bc), ci95(latency_with_bc)
        print(f"  Handover latency with BC:     {fmt(m1, s1, c1)} ms")
    else:
        print("  Handover latency with BC:     n/a")

    if latency_no_bc and latency_with_bc:
        overhead = mean(latency_with_bc) - mean(latency_no_bc)
        print(f"  BC overhead:                  {overhead:.2f} ms avg")
else:
    print("  Latency CSV not found or no valid numeric latency values")


if energy_no_bc and energy_with_bc:
    m0, s0, c0 = mean(energy_no_bc), stddev(energy_no_bc), ci95(energy_no_bc)
    m1, s1, c1 = mean(energy_with_bc), stddev(energy_with_bc), ci95(energy_with_bc)

    saving_pct = (1 - mean(energy_with_bc) / mean(energy_no_bc)) * 100

    print(f"  Total energy without BC:      {fmt(m0, s0, c0)} mJ")
    print(f"  Total energy with BC:         {fmt(m1, s1, c1)} mJ")
    print(f"  Energy saving:                {saving_pct:.1f}%")
else:
    print("  Energy CSV not found or no valid numeric energy values")


if attack_data:
    print("\nTable III — Attack Evaluation")
    print(f"  {'Attack':<20} {'Blocked(mean)':>14} {'HO-Succ(mean)':>14} Defense")
    print("  " + "-" * 65)

    for name, vals in attack_data.items():
        mb = mean(vals["blocked"])
        mh = mean(vals["ho_succ"])
        defense = vals["defense"]

        print(f"  {name:<20} {mb:>14.1f} {mh:>14.1f}   {defense}")


# ── Write CSV outputs ─────────────────────────────────────────────────────────

table2_path = os.path.join(STATS_DIR, "table2_network.csv")
table3_path = os.path.join(STATS_DIR, "table3_attacks.csv")
summary_path = os.path.join(STATS_DIR, "summary_report.txt")

with open(table2_path, "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(
        [
            "metric",
            "scenario",
            "mean",
            "stddev",
            "ci95_halfwidth",
            "unit",
            "n_runs",
        ]
    )

    for metric, label, unit in [
        ("throughput", "Throughput", "Mbps"),
        ("delay", "E2E delay", "ms"),
        ("loss", "Packet loss", "%"),
    ]:
        for sc_id, sc_name in scenarios.items():
            vals = net[sc_id][metric]

            if vals:
                w.writerow(
                    [
                        label,
                        sc_name,
                        f"{mean(vals):.4f}",
                        f"{stddev(vals):.4f}",
                        f"{ci95(vals):.4f}",
                        unit,
                        len(vals),
                    ]
                )

    for label, vals, unit in [
        ("HO latency no-BC", latency_no_bc, "ms"),
        ("HO latency with-BC", latency_with_bc, "ms"),
        ("Total energy no-BC", energy_no_bc, "mJ"),
        ("Total energy with-BC", energy_with_bc, "mJ"),
    ]:
        if vals:
            w.writerow(
                [
                    label,
                    "comparison",
                    f"{mean(vals):.4f}",
                    f"{stddev(vals):.4f}",
                    f"{ci95(vals):.4f}",
                    unit,
                    len(vals),
                ]
            )


with open(table3_path, "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(
        [
            "attack",
            "mean_blocked",
            "stddev_blocked",
            "mean_ho_succ",
            "mean_latency_impact_ms",
            "mean_packet_loss_pct",
            "defense_result",
            "n_runs",
        ]
    )

    for name, vals in attack_data.items():
        w.writerow(
            [
                name,
                f"{mean(vals['blocked']):.2f}",
                f"{stddev(vals['blocked']):.2f}",
                f"{mean(vals['ho_succ']):.2f}",
                f"{mean(vals['latency']):.2f}",
                f"{mean(vals['loss']):.2f}",
                vals["defense"],
                len(vals["blocked"]),
            ]
        )


with open(summary_path, "w") as f:
    f.write("Security-Aware Energy Optimization in Hybrid LiFi-WiFi Networks\n")
    f.write("Statistical Summary Report\n")
    f.write("=" * 60 + "\n\n")

    f.write(f"Results directory: {RESULTS_DIR}\n")
    f.write(f"Runs per scenario: {N_RUNS}\n")
    f.write("Scenarios: 0=baseline, 1=attack-no-defense, 2=attack-with-defense\n\n")

    f.write("Network Performance\n")
    f.write("-" * 60 + "\n")

    for sc_id, sc_name in scenarios.items():
        f.write(f"\nScenario {sc_id} — {sc_name}\n")

        for metric, label, unit in [
            ("throughput", "Throughput", "Mbps"),
            ("delay", "E2E delay", "ms"),
            ("loss", "Packet loss", "%"),
        ]:
            vals = net[sc_id][metric]

            if vals:
                f.write(
                    f"  {label}: {mean(vals):.3f} ± {stddev(vals):.3f} "
                    f"(95% CI ±{ci95(vals):.3f}) {unit}\n"
                )
            else:
                f.write(f"  {label}: n/a\n")

    f.write("\nBlockchain / Energy Performance\n")
    f.write("-" * 60 + "\n")

    if latency_no_bc:
        f.write(
            f"HO latency without BC: {mean(latency_no_bc):.2f} ± "
            f"{stddev(latency_no_bc):.2f} ms "
            f"(95% CI ±{ci95(latency_no_bc):.2f} ms)\n"
        )

    if latency_with_bc:
        f.write(
            f"HO latency with BC: {mean(latency_with_bc):.2f} ± "
            f"{stddev(latency_with_bc):.2f} ms "
            f"(95% CI ±{ci95(latency_with_bc):.2f} ms)\n"
        )

    if latency_no_bc and latency_with_bc:
        overhead = mean(latency_with_bc) - mean(latency_no_bc)
        f.write(f"BC overhead: {overhead:.2f} ms avg\n")

    if energy_no_bc and energy_with_bc:
        saving = (1 - mean(energy_with_bc) / mean(energy_no_bc)) * 100
        f.write(
            f"Energy saving: {saving:.1f}% "
            f"({mean(energy_no_bc):.1f} mJ -> {mean(energy_with_bc):.1f} mJ)\n"
        )

    if attack_data:
        fully_mitigated = sum(
            1 for v in attack_data.values() if v["defense"] == "FULLY_MITIGATED"
        )

        f.write("\nAttack Evaluation\n")
        f.write("-" * 60 + "\n")
        f.write(f"Attacks fully mitigated: {fully_mitigated}/{len(attack_data)}\n")

        for name, vals in attack_data.items():
            f.write(
                f"{name}: blocked={mean(vals['blocked']):.2f}, "
                f"handover_success={mean(vals['ho_succ']):.2f}, "
                f"defense={vals['defense']}\n"
            )


print(f"\nOutput files written to {STATS_DIR}/")
print("  table2_network.csv  — Network + BC performance")
print("  table3_attacks.csv  — Attack evaluation")
print("  summary_report.txt  — Human-readable summary")
print("\nDone.")
