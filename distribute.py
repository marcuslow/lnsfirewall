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
