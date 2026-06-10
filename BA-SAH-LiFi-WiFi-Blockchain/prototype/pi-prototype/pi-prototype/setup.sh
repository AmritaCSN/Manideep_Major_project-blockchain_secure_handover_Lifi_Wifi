#!/bin/bash
# setup.sh — First-time setup on Raspberry Pi 4
# Run once: bash setup.sh

echo "Setting up LiFi-WiFi Blockchain Prototype..."

# Update system
sudo apt-get update -y

# Install Python pip if not present
sudo apt-get install -y python3-pip python3-venv

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install flask requests

# Create logs directory
mkdir -p logs

echo ""
echo "Setup complete!"
echo "To start: source venv/bin/activate && ./run_all.sh"
echo ""
