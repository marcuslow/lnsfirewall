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

# Pick the best available Python (prefer 3.11, then 3.10, 3.9), and ensure matching pip + psutil
if command -v python3.11 >/dev/null 2>&1; then
  PYTHON_CMD=python3.11; PYVER=311
elif command -v python3.10 >/dev/null 2>&1; then
  PYTHON_CMD=python3.10; PYVER=310
elif command -v python3.9 >/dev/null 2>&1; then
  PYTHON_CMD=python3.9; PYVER=39
elif command -v python3 >/dev/null 2>&1; then
  PYTHON_CMD=python3; PYVER=$(${PYTHON_CMD} -c 'import sys; print(f"{sys.version_info.major}{sys.version_info.minor}")' 2>/dev/null || echo "39")
else
  echo "📦 Installing Python via pkg (python39 + py39-pip)"
  pkg install -y python39 py39-pip || true
  PYTHON_CMD=python3.9; PYVER=39
fi

echo "🐍 Using Python interpreter: ${PYTHON_CMD} (py${PYVER})"

# Ensure pip for this interpreter
if ! ${PYTHON_CMD} -m pip --version >/dev/null 2>&1; then
  echo "📦 Installing pip for py${PYVER}"
  pkg install -y "py${PYVER}-pip" || true
fi

# Install psutil via pkg to avoid wheel mismatch on FreeBSD
echo "📦 Installing psutil package: py${PYVER}-psutil"
pkg install -y "py${PYVER}-psutil" || pkg install -y py39-psutil || true

# Python deps via pip (requests, pyyaml) using the same interpreter
echo "📦 Installing Python deps via pip: requests pyyaml"
${PYTHON_CMD} -m pip install --no-cache-dir --upgrade pip || true
${PYTHON_CMD} -m pip install --no-cache-dir requests pyyaml

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
idle_poll_interval: 1
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

# Test run (foreground). To run in background after logout, set up the service or use daemon(8).
echo "▶️  Running client once (Ctrl+C to stop). To keep it running after logout: sh setup_client.sh, then 'service pfsense_client start'"
python3 /usr/local/bin/pfsense_client.py --config /usr/local/etc/pfsense_client.yaml || true

echo "✅ Install complete. To run on boot, use: sh setup_client.sh && service pfsense_client start"

