#!/usr/bin/env python3
"""
Automated pfSense WebSocket Client Distribution Script
Usage: python distribute.py
"""

import os
import subprocess
import sys
import glob
import getpass
from datetime import datetime

# Configuration
PFSENSE_IP = "103.26.150.122"
PFSENSE_USER = "root"
DIST_DIR = "dist"
BUNDLE_PREFIX = "pfsense-client-bundle"

def run_command(cmd, shell=True, check=True):
    """Run a command and return the result"""
    try:
        result = subprocess.run(cmd, shell=shell, check=check,
                              capture_output=True, text=True, encoding='utf-8', errors='replace')
        return result
    except subprocess.CalledProcessError as e:
        print(f"❌ Command failed: {cmd}")
        print(f"Error: {e.stderr}")
        return None

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
    result = run_command("make_client_bundle.bat")
    if not result:
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

def step2_upload_files(bundle_file, password):
    """Step 2: Upload bundle and deployment script"""
    print("=" * 50)
    print("📤 Step 2: Uploading files to pfSense...")
    print("=" * 50)
    
    # Create deployment script content
    deploy_script = """#!/bin/sh
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
"""

    # Write deployment script to file with Unix LF endings
    with open("deploy_remote.sh", "w", encoding='utf-8', newline='\n') as f:
        f.write(deploy_script)

    # Upload bundle
    print(f"📤 Uploading bundle: {bundle_file}")
    scp_cmd = f'scp "{bundle_file}" {PFSENSE_USER}@{PFSENSE_IP}:/tmp/pfsense-client-update.zip'

    print(f"Running: {scp_cmd}")
    print("Enter password when prompted...")
    result = run_command(scp_cmd, check=False)
    if not result or result.returncode != 0:
        print("❌ Failed to upload bundle")
        if result:
            print(f"Error: {result.stderr}")
        return False

    # Upload deployment script
    print("📤 Uploading deployment script...")
    scp_cmd2 = f'scp deploy_remote.sh {PFSENSE_USER}@{PFSENSE_IP}:/tmp/'

    print(f"Running: {scp_cmd2}")
    print("Enter password when prompted...")
    result = run_command(scp_cmd2, check=False)
    if not result or result.returncode != 0:
        print("❌ Failed to upload deployment script")
        if result:
            print(f"Error: {result.stderr}")
        return False
    
    print("✅ Files uploaded successfully")
    
    return True

def step3_deploy(password):
    """Step 3: SSH and execute deployment"""
    print("=" * 50)
    print("🚀 Step 3: Executing deployment on pfSense...")
    print("=" * 50)
    
    # SSH and execute deployment
    ssh_cmd = f'ssh {PFSENSE_USER}@{PFSENSE_IP} "if [ -f /tmp/deploy_remote.sh ]; then chmod +x /tmp/deploy_remote.sh && /tmp/deploy_remote.sh; else echo \"/tmp/deploy_remote.sh missing\"; exit 2; fi"'

    print("🔧 Executing deployment script...")
    print(f"Running: {ssh_cmd}")
    print("Enter password when prompted...")
    result = run_command(ssh_cmd, check=False)
    
    if result and result.returncode == 0:
        print("✅ Deployment completed successfully!")
        # Cleanup local deployment script after success
        try:
            os.remove("deploy_remote.sh")
        except Exception:
            pass
        return True
    else:
        print("❌ Deployment failed")
        if result:
            print(f"Error output: {result.stderr}")
        return False

def main():
    """Main distribution function"""
    print("🚀 pfSense WebSocket Client Auto-Distribution")
    print("=" * 50)
    print(f"Target: {PFSENSE_USER}@{PFSENSE_IP}")
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    # Get password
    password = getpass.getpass(f"Enter password for {PFSENSE_USER}@{PFSENSE_IP}: ")
    
    try:
        # Step 1: Create bundle
        bundle_file = step1_make_bundle()
        if not bundle_file:
            return 1
        
        # Step 2: Upload files
        if not step2_upload_files(bundle_file, password):
            return 1
        
        # Step 3: Deploy
        if not step3_deploy(password):
            return 1
        
        print()
        print("=" * 50)
        print("🎉 DISTRIBUTION COMPLETE!")
        print("=" * 50)
        print()
        print("📋 Next steps:")
        print("1. Start your HQ server: start_hq_server.bat")
        print("2. Monitor connection: ssh admin@103.26.150.122 'tail -f /var/log/pfsense_client.log'")
        print("3. Check server status: curl https://lnsfirewall.ngrok.app/status")
        print()
        print("🔌 Client should connect to: wss://lnsfirewall.ngrok.app/ws")
        print("🎯 Ready for WebSocket connection!")
        
        return 0
        
    except KeyboardInterrupt:
        print("\n❌ Distribution cancelled by user")
        return 1
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
