#!/bin/sh
# pfSense Client Installer (HTTP Mode)
# Usage (on pfSense): fetch -o - https://raw.githubusercontent.com/<yourrepo>/install_client.sh | sh
# Or copy this file and run: sh install_client.sh

set -e

echo "🔥 Installing pfSense Client (HTTP)"

# Detect FreeBSD (pfSense)
uname_out=$(uname)
if [ "$uname_out" != "FreeBSD" ]; then
  echo "⚠️  This script is intended for pfSense/FreeBSD. Continuing anyway..."
fi

# Packages
echo "📦 Installing packages: python39 py39-pip"
pkg install -y python39 py39-pip || true

# Python deps
echo "📦 Installing Python deps: requests pyyaml psutil"
pip install --no-cache-dir requests pyyaml psutil

# Paths
mkdir -p /usr/local/bin /usr/local/etc /var/log

# Copy client script if present adjacent; otherwise, assume already placed
if [ -f client/pfsense_client.py ]; then
  echo "📋 Installing client script to /usr/local/bin/pfsense_client.py"
  cp client/pfsense_client.py /usr/local/bin/pfsense_client.py
  chmod +x /usr/local/bin/pfsense_client.py
fi

# Config
if [ ! -f /usr/local/etc/pfsense_client.yaml ]; then
  if [ -f config/client_config.yaml ]; then
    echo "📋 Writing default config to /usr/local/etc/pfsense_client.yaml"
    cp config/client_config.yaml /usr/local/etc/pfsense_client.yaml
  else
    echo "📋 Creating minimal /usr/local/etc/pfsense_client.yaml"
    cat > /usr/local/etc/pfsense_client.yaml << EOF
hq_url: "https://lnsfirewall.ngrok.app"
client_name: "opus-1"
reconnect_interval: 10
EOF
  fi
else
  echo "✅ Existing /usr/local/etc/pfsense_client.yaml detected"
fi

# Basic connectivity test
echo "🧪 Testing connectivity to HQ..."
HQ_URL=$(grep '^hq_url:' /usr/local/etc/pfsense_client.yaml | awk '{print $2}' | sed 's/"//g')
if [ -z "$HQ_URL" ]; then
  HQ_URL="https://lnsfirewall.ngrok.app"
fi
fetch -qo - "$HQ_URL/status" || true

# Test run
echo "▶️  Running client once (Ctrl+C to stop)"
python3 /usr/local/bin/pfsense_client.py --config /usr/local/etc/pfsense_client.yaml || true

echo "✅ Install complete. To run on boot, consider creating a service script."

