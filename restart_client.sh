#!/bin/sh
# pfSense Client Restart Script
# Usage: sh restart_client.sh
# This script stays on the pfSense firewall for manual restarts

echo "🔄 Restarting pfSense WebSocket Client..."

# Stop existing client processes
echo "🛑 Stopping existing pfsense_client processes..."
pkill -f pfsense_client 2>/dev/null && echo "   Killed pfsense_client processes" || echo "   No pfsense_client processes found"
pkill -f "python.*pfsense_client" 2>/dev/null && echo "   Killed python pfsense_client processes" || echo "   No python pfsense_client processes found"
sleep 2

# Detect Python version (same logic as deployment)
if command -v python3.11 >/dev/null 2>&1; then
  PYTHON_CMD=python3.11
elif command -v python3.10 >/dev/null 2>&1; then
  PYTHON_CMD=python3.10
elif command -v python3.9 >/dev/null 2>&1; then
  PYTHON_CMD=python3.9
elif command -v python3 >/dev/null 2>&1; then
  PYTHON_CMD=python3
else
  echo "❌ No Python interpreter found!"
  exit 1
fi

echo "🐍 Using Python interpreter: ${PYTHON_CMD}"

# Check if client script exists
if [ ! -f /usr/local/bin/pfsense_client.py ]; then
    echo "❌ Client script not found at /usr/local/bin/pfsense_client.py"
    echo "   Run the deployment script first to install the client"
    exit 1
fi

# Check if config exists
if [ ! -f /usr/local/etc/pfsense_client.yaml ]; then
    echo "❌ Configuration not found at /usr/local/etc/pfsense_client.yaml"
    echo "   Run the deployment script first to install the configuration"
    exit 1
fi

# Start client as daemon
echo "🚀 Starting pfsense_client as daemon..."
${PYTHON_CMD} /usr/local/bin/pfsense_client.py --daemon

# Wait a moment and check if it started
sleep 3
if ps aux | grep -v grep | grep pfsense_client >/dev/null; then
    echo "✅ pfSense client started successfully as daemon"
    echo "📊 Process info:"
    ps aux | grep -v grep | grep pfsense_client
    echo ""
    echo "📋 To check logs: tail -f /var/log/pfsense_client.log"
    echo "📋 To stop: pkill -f pfsense_client"
else
    echo "❌ Failed to start pfSense client"
    echo "📋 Check logs for errors: tail -20 /var/log/pfsense_client.log"
    exit 1
fi

echo "🎯 Client restart complete!"
