#!/bin/sh
echo "Starting pfSense WebSocket client deployment..."

# Stop existing client/service
echo "Stopping existing pfsense_client service and processes..."
service pfsense_client stop 2>/dev/null || echo "Service not running"
pkill -f pfsense_client 2>/dev/null || echo "No pfsense_client processes"
killall -9 python3 2>/dev/null || echo "No python3 processes"
rm -f /var/run/pfsense_client.pid 2>/dev/null || true
sleep 2

# Extract bundle
echo "Extracting new client bundle..."
cd /tmp
unzip -o pfsense-client-update.zip
cd pfsense-client-bundle

# Run setup (installs files and service)
echo "Running setup script..."
chmod +x ./setup_client.sh
./setup_client.sh

# Start service
echo "Starting pfsense_client service..."
service pfsense_client start

# Show status and recent logs
echo "Deployment complete!"
echo "Service status:"
service pfsense_client status || true

echo "Client configuration (first lines):"
head -10 /usr/local/etc/pfsense_client.yaml 2>/dev/null || echo "Config not found"

echo "Recent logs:"
tail -20 /var/log/pfsense_client.log 2>/dev/null || echo "No logs yet"

echo "Client should connect to: wss://lnsfirewall.ngrok.app/ws"
echo "Ready for WebSocket connection!"

# Cleanup
rm -f /tmp/pfsense-client-update.zip /tmp/deploy_remote.sh
rm -rf /tmp/pfsense-client-bundle
