#!/usr/bin/env python3
"""
Simple pfSense WebSocket Client Distribution Script
Usage: python distribute_simple.py
"""

import os
import subprocess
import sys
import glob
from datetime import datetime

# Configuration
PFSENSE_IP = "103.26.150.122"
PFSENSE_USER = "admin"
DIST_DIR = "dist"
BUNDLE_PREFIX = "pfsense-client-bundle"

def run_command(cmd, shell=True):
    """Run a command and return the result"""
    print(f"Running: {cmd}")
    try:
        result = subprocess.run(cmd, shell=shell, check=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Command failed: {e}")
        return False

def step1_make_bundle():
    """Step 1: Create new bundle and clean old ones"""
    print("=" * 50)
    print("📦 Step 1: Creating new client bundle...")
    print("=" * 50)
    
    # Clean old zip files
    print("🧹 Cleaning old bundle files...")
    old_zips = glob.glob(f"{DIST_DIR}/{BUNDLE_PREFIX}-*.zip")
    for zip_file in old_zips:
        try:
            os.remove(zip_file)
            print(f"   Deleted: {zip_file}")
        except Exception as e:
            print(f"   Warning: Could not delete {zip_file}: {e}")
    
    # Create new bundle
    print("🔨 Creating new bundle...")
    if not run_command("make_client_bundle.bat"):
        print("❌ Failed to create bundle")
        return None
    
    # Find the new bundle file
    new_zips = glob.glob(f"{DIST_DIR}/{BUNDLE_PREFIX}-*.zip")
    if not new_zips:
        print("❌ No bundle file found after creation")
        return None
    
    bundle_file = new_zips[0]  # Should be only one after cleanup
    print(f"✅ Bundle created: {bundle_file}")
    return bundle_file

def create_deployment_script():
    """Create the deployment script"""
    deploy_script = """#!/bin/sh
echo "Starting pfSense WebSocket client deployment..."

# Stop all existing clients
echo "Stopping all existing pfsense_client processes..."
pkill -9 -f pfsense_client 2>/dev/null || echo "No processes to kill"
killall -9 python3 2>/dev/null || echo "No python3 processes"
rm -f /var/run/pfsense_client.pid 2>/dev/null || true
sleep 2

# Extract bundle
echo "Extracting new client bundle..."
cd /tmp
unzip -o pfsense-client-update.zip
cd pfsense-client-bundle

# Backup existing installation
if [ -d "/usr/local/bin/pfsense_client" ]; then
  echo "Backing up existing installation..."
  mv /usr/local/bin/pfsense_client /usr/local/bin/pfsense_client.backup.$(date +%Y%m%d-%H%M%S)
fi

# Install new client
echo "Installing new WebSocket client..."
mkdir -p /usr/local/bin/pfsense_client
cp -r * /usr/local/bin/pfsense_client/
chmod +x /usr/local/bin/pfsense_client/setup_client.sh

# Run setup
echo "Running setup script..."
cd /usr/local/bin/pfsense_client
./setup_client.sh

# Create service script
echo "Creating service script..."
cat > /usr/local/etc/rc.d/pfsense_client.sh << 'SERVICEEOF'
#!/bin/sh
. /etc/rc.subr
name="pfsense_client"
rcvar="pfsense_client_enable"
command="/usr/local/bin/python3"
command_args="/usr/local/bin/pfsense_client/client/pfsense_client.py"
pidfile="/var/run/pfsense_client.pid"
start_cmd="pfsense_client_start"
stop_cmd="pfsense_client_stop"

pfsense_client_start() {
    echo "Starting pfSense WebSocket client..."
    /usr/bin/nohup ${command} ${command_args} > /var/log/pfsense_client.log 2>&1 & echo $! > ${pidfile}
}

pfsense_client_stop() {
    if [ -f ${pidfile} ]; then
        echo "Stopping pfSense client..."
        kill $(cat ${pidfile}) 2>/dev/null
        rm -f ${pidfile}
    fi
    killall -9 python3 2>/dev/null || true
}

load_rc_config $name
run_rc_command "$1"
SERVICEEOF

chmod +x /usr/local/etc/rc.d/pfsense_client.sh

# Enable and start service
echo "Starting WebSocket client service..."
grep -q 'pfsense_client_enable="YES"' /etc/rc.conf.local 2>/dev/null || echo 'pfsense_client_enable="YES"' >> /etc/rc.conf.local
service pfsense_client start

# Show status
echo "Deployment complete!"
echo "Service status:"
service pfsense_client status

echo "Client configuration:"
head -10 /usr/local/bin/pfsense_client/config/client_config.yaml

echo "Recent logs:"
tail -20 /var/log/pfsense_client.log

echo "Client should connect to: wss://lnsfirewall.ngrok.app/ws"
echo "Ready for WebSocket connection!"

# Cleanup
rm -f /tmp/pfsense-client-update.zip /tmp/deploy_remote.sh
rm -rf /tmp/pfsense-client-bundle
"""
    
    # Write deployment script to file
    with open("deploy_remote.sh", "w", encoding='ascii', errors='ignore') as f:
        f.write(deploy_script)
    
    print("✅ Deployment script created: deploy_remote.sh")

def main():
    """Main distribution function"""
    print("🚀 pfSense WebSocket Client Distribution")
    print("=" * 50)
    print(f"Target: {PFSENSE_USER}@{PFSENSE_IP}")
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    try:
        # Step 1: Create bundle
        bundle_file = step1_make_bundle()
        if not bundle_file:
            return 1
        
        # Step 2: Create deployment script
        create_deployment_script()
        
        # Step 3: Show manual commands
        print()
        print("=" * 50)
        print("📤 Step 2: Upload files (run these commands)")
        print("=" * 50)
        print()
        print("1. Upload bundle:")
        print(f'   scp "{bundle_file}" {PFSENSE_USER}@{PFSENSE_IP}:/tmp/pfsense-client-update.zip')
        print()
        print("2. Upload deployment script:")
        print(f'   scp deploy_remote.sh {PFSENSE_USER}@{PFSENSE_IP}:/tmp/')
        print()
        print("3. Execute deployment:")
        print(f'   ssh {PFSENSE_USER}@{PFSENSE_IP} "chmod +x /tmp/deploy_remote.sh && /tmp/deploy_remote.sh"')
        print()
        print(f"🔑 Password for all commands: Lns12345678()")
        print()
        print("=" * 50)
        print("📋 After deployment:")
        print("=" * 50)
        print("1. Start HQ server: start_hq_server.bat")
        print("2. Monitor logs: ssh admin@103.26.150.122 'tail -f /var/log/pfsense_client.log'")
        print("3. Check connection: curl https://lnsfirewall.ngrok.app/status")
        print()
        print("🔌 Client will connect to: wss://lnsfirewall.ngrok.app/ws")
        
        return 0
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
