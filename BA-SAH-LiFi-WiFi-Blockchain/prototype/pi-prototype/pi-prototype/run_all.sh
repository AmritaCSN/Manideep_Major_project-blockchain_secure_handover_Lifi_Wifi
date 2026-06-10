#!/bin/bash
# run_all.sh
# Start all 5 processes for the LiFi-WiFi blockchain prototype
# Run this script from the pi-prototype directory:
#   chmod +x run_all.sh
#   ./run_all.sh

echo ""
echo "================================================"
echo " LiFi-WiFi Blockchain Handover Prototype"
echo " Raspberry Pi 4 — Stage 1"
echo " Garrepelly Manideep | Amrita Vishwa Vidyapeetham"
echo "================================================"
echo ""

# Kill any previous instances
pkill -f blockchain_node.py 2>/dev/null
pkill -f lifi_ap.py         2>/dev/null
pkill -f wifi_ap.py         2>/dev/null
pkill -f dashboard.py       2>/dev/null
pkill -f ue_simulator.py    2>/dev/null
sleep 1

# Start each process in background, log to file
echo "[1/5] Starting blockchain node (port 5001)..."
python3 blockchain_node.py > logs/blockchain.log 2>&1 &
sleep 2

echo "[2/5] Starting LiFi AP emulator (port 5002)..."
python3 lifi_ap.py > logs/lifi.log 2>&1 &
sleep 1

echo "[3/5] Starting WiFi AP emulator (port 5003)..."
python3 wifi_ap.py > logs/wifi.log 2>&1 &
sleep 1

echo "[4/5] Starting dashboard (port 5000)..."
python3 dashboard.py > logs/dashboard.log 2>&1 &
sleep 1

echo "[5/5] Starting UE simulator..."
python3 ue_simulator.py > logs/ue.log 2>&1 &

echo ""
echo "All processes started!"
echo ""
echo "Dashboard: http://localhost:5000"
echo "         : http://$(hostname -I | awk '{print $1}'):5000"
echo ""
echo "Logs: tail -f logs/blockchain.log"
echo "      tail -f logs/ue.log"
echo ""
echo "Stop all: pkill -f 'blockchain_node|lifi_ap|wifi_ap|dashboard|ue_simulator'"
echo ""
