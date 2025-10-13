#!/bin/sh
echo "Starting pfSense WebSocket client deployment..."

# Stop existing client processes
echo "Stopping existing pfsense_client processes..."
pkill -f pfsense_client 2>/dev/null || echo "No pfsense_client processes"
pkill -f "python.*pfsense_client" 2>/dev/null || echo "No python pfsense_client processes"
sleep 2

# Extract bundle
echo "Extracting new client bundle..."
cd /tmp
unzip -o pfsense-client-update.zip
cd pfsense-client-bundle

# Install files (simplified - no service creation)
echo "Installing client files..."

# Detect Python version
if command -v python3.11 >/dev/null 2>&1; then
  PYTHON_CMD=python3.11; PYVER=311
elif command -v python3.10 >/dev/null 2>&1; then
  PYTHON_CMD=python3.10; PYVER=310
elif command -v python3.9 >/dev/null 2>&1; then
  PYTHON_CMD=python3.9; PYVER=39
elif command -v python3 >/dev/null 2>&1; then
  PYTHON_CMD=python3; PYVER=39
else
  echo "Installing Python..."
  pkg install -y python39 py39-pip || true
  PYTHON_CMD=python3.9; PYVER=39
fi

echo "Using Python interpreter: ${PYTHON_CMD}"

# Install Python dependencies
echo "Installing Python dependencies..."
${PYTHON_CMD} -m pip install --no-cache-dir --upgrade pip || true
${PYTHON_CMD} -m pip install --no-cache-dir pyyaml websockets

# Create directories and install files
mkdir -p /usr/local/bin /usr/local/etc /var/log
cp client/pfsense_client.py /usr/local/bin/
chmod +x /usr/local/bin/pfsense_client.py
if [ -f client/psutil_stub.py ]; then
  cp client/psutil_stub.py /usr/local/bin/psutil_stub.py
  chmod 644 /usr/local/bin/psutil_stub.py
fi

# Install restart script
if [ -f restart_client.sh ]; then
  cp restart_client.sh /usr/local/bin/restart_client.sh
  chmod +x /usr/local/bin/restart_client.sh
  echo "Restart script installed to /usr/local/bin/restart_client.sh"
fi

# Install configuration if it doesn't exist
if [ ! -f /usr/local/etc/pfsense_client.yaml ]; then
    cp config/client_config.yaml /usr/local/etc/pfsense_client.yaml
    echo "Configuration installed to /usr/local/etc/pfsense_client.yaml"
else
    echo "Configuration file already exists"
fi

# Start client as daemon (in background to avoid hanging SSH)
echo "Starting pfsense_client as daemon..."
nohup ${PYTHON_CMD} /usr/local/bin/pfsense_client.py --daemon >/dev/null 2>&1 &

# Wait a moment and check if it started
sleep 3
if ps aux | grep -v grep | grep pfsense_client >/dev/null; then
    echo "✅ pfSense client started successfully as daemon"
    echo "Process info:"
    ps aux | grep -v grep | grep pfsense_client
else
    echo "❌ Failed to start pfSense client"
    echo "Recent logs:"
    tail -10 /var/log/pfsense_client.log 2>/dev/null || echo "No logs found"
fi

echo ""
echo "Deployment complete!"
echo "Client should connect to: wss://lnsfirewall.ngrok.app/ws"
echo ""
echo "📋 Available commands on this firewall:"
echo "   - Restart client: /usr/local/bin/restart_client.sh"
echo "   - View logs: tail -f /var/log/pfsense_client.log"
echo "   - Stop client: pkill -f pfsense_client"

# Cleanup
rm -f /tmp/pfsense-client-update.zip /tmp/deploy_remote.sh
rm -rf /tmp/pfsense-client-bundle
