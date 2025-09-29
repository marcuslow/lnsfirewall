#!/usr/bin/env python3
"""
Client Update Distribution System
Handles pushing client software updates to pfSense firewalls
"""

import os
import subprocess
import glob
import tempfile
import shutil
import sqlite3
from datetime import datetime
from typing import Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)

class ClientUpdater:
    """Handles client software updates and distribution"""

    def __init__(self, repo_root: str, db_path: str):
        self.repo_root = repo_root
        self.db_path = db_path
        self.dist_dir = os.path.join(repo_root, "dist")
        self.bundle_prefix = "pfsense-client-bundle"
        self.secrets = self._load_secrets()

    def _load_secrets(self) -> Dict[str, str]:
        """Load secrets from secrets.txt or .env style file at repo root"""
        secrets_path = os.path.join(self.repo_root, "secrets.txt")
        data: Dict[str, str] = {}
        try:
            if os.path.exists(secrets_path):
                with open(secrets_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):  # skip comments/blank
                            continue
                        if "=" in line:
                            k, v = line.split("=", 1)
                            data[k.strip()] = v.strip().strip('"')
        except Exception:
            pass
        # Also allow environment variables to override
        for key in ["PFSENSE_HOST", "PFSENSE_USER", "PFSENSE_PASSWORD", "PFSENSE_SSH_KEY"]:
            if os.getenv(key):
                data[key] = os.getenv(key)
        return data

    def _which(self, exe: str) -> bool:
        return shutil.which(exe) is not None

    def run_command(self, cmd: str, shell: bool = True, check: bool = True) -> Optional[subprocess.CompletedProcess]:
        """Run a command and return the result"""
        try:
            result = subprocess.run(
                cmd, shell=shell, check=check,
                capture_output=True, text=True,
                encoding='utf-8', errors='replace',
                cwd=self.repo_root
            )
            return result
        except subprocess.CalledProcessError as e:
            logger.error(f"Command failed: {cmd}")
            logger.error(f"Error: {e.stderr}")
            return None
    
    def create_client_bundle(self) -> Optional[str]:
        """Create a new client bundle ZIP file"""
        try:
            logger.info("Creating new client bundle...")
            
            # Clean old zip files
            old_zips = glob.glob(os.path.join(self.dist_dir, f"{self.bundle_prefix}-*.zip"))
            for zip_file in old_zips:
                try:
                    os.remove(zip_file)
                    logger.info(f"Deleted old bundle: {zip_file}")
                except Exception as e:
                    logger.warning(f"Could not delete {zip_file}: {e}")
            
            # Create new bundle using existing script
            bundle_script = os.path.join(self.repo_root, "make_client_bundle.bat")
            if not os.path.exists(bundle_script):
                logger.error(f"Bundle creation script not found: {bundle_script}")
                return None
            
            result = self.run_command(bundle_script)
            if not result:
                logger.error("Failed to create bundle")
                return None
            
            # Find the new bundle file
            new_zips = glob.glob(os.path.join(self.dist_dir, f"{self.bundle_prefix}-*.zip"))
            if not new_zips:
                logger.error("No bundle file found after creation")
                return None
            
            bundle_file = new_zips[0]  # Should be only one after cleanup
            logger.info(f"Bundle created: {bundle_file}")
            return bundle_file
            
        except Exception as e:
            logger.error(f"Failed to create client bundle: {e}")
            return None
    
    def get_client_connection_info(self, client_id: str) -> Optional[Dict[str, str]]:
        """Get SSH connection info for a client from database and secrets"""
        try:
            conn = sqlite3.connect(self.db_path)
            cur = conn.cursor()

            # Get client info
            cur.execute("""
                SELECT client_name, last_seen
                FROM clients
                WHERE client_id = ?
            """, (client_id,))

            row = cur.fetchone()
            conn.close()

            if not row:
                logger.error(f"Client {client_id} not found in database")
                return None

            client_name, last_seen = row

            host = self.secrets.get("PFSENSE_HOST", "103.26.150.122")
            user = self.secrets.get("PFSENSE_USER", "root")

            return {
                "host": host,
                "user": user,
                "client_name": client_name or client_id
            }

        except Exception as e:
            logger.error(f"Failed to get client connection info: {e}")
            return None
    
    def create_deployment_script(self) -> str:
        """Create the remote deployment script"""
        deploy_script = """#!/bin/sh
echo "Starting pfSense WebSocket client update..."

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
    echo "✅ pfSense client updated and started successfully"
    echo "Process info:"
    ps aux | grep -v grep | grep pfsense_client
else
    echo "❌ Failed to start pfSense client after update"
    echo "Recent logs:"
    tail -10 /var/log/pfsense_client.log 2>/dev/null || echo "No logs found"
fi

echo ""
echo "Client update complete!"
echo "Client should connect to: wss://lnsfirewall.ngrok.app/ws"

# Cleanup
rm -f /tmp/pfsense-client-update.zip /tmp/deploy_remote.sh
rm -rf /tmp/pfsense-client-bundle
"""
        return deploy_script
    
    def upload_and_deploy(self, bundle_file: str, connection_info: Dict[str, str], password: str) -> Dict[str, Any]:
        """Upload bundle and execute deployment on remote pfSense without interactive prompts"""
        try:
            host = connection_info["host"]
            user = connection_info["user"]
            client_name = connection_info["client_name"]

            logger.info(f"Uploading update to {client_name} ({user}@{host})")

            # Create deployment script
            deploy_script = self.create_deployment_script()

            # Write deployment script to temporary file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.sh', delete=False,
                                           encoding='utf-8', newline='\n') as f:
                f.write(deploy_script)
                deploy_script_path = f.name

            try:
                key_path = self.secrets.get("PFSENSE_SSH_KEY")
                use_key = bool(key_path and os.path.exists(key_path))

                if use_key:
                    # Use OpenSSH with private key (non-interactive)
                    scp_cmd = (
                        f'scp -i "{key_path}" -o StrictHostKeyChecking=no "{bundle_file}" {user}@{host}:/tmp/pfsense-client-update.zip'
                    )
                    result = self.run_command(scp_cmd, check=False)
                    if not result or result.returncode != 0:
                        return {"success": False, "error": f"Failed to upload bundle: {result.stderr if result else 'Unknown error'}"}

                    scp_cmd2 = (
                        f'scp -i "{key_path}" -o StrictHostKeyChecking=no "{deploy_script_path}" {user}@{host}:/tmp/deploy_remote.sh'
                    )
                    result = self.run_command(scp_cmd2, check=False)
                    if not result or result.returncode != 0:
                        return {"success": False, "error": f"Failed to upload deployment script: {result.stderr if result else 'Unknown error'}"}

                    ssh_cmd = (
                        f'ssh -i "{key_path}" -o StrictHostKeyChecking=no {user}@{host} "chmod +x /tmp/deploy_remote.sh && /tmp/deploy_remote.sh"'
                    )
                    result = self.run_command(ssh_cmd, check=False)
                else:
                    # Fallback to PuTTY tools (plink/pscp) with password
                    if not self._which("plink") or not self._which("pscp"):
                        return {
                            "success": False,
                            "error": "No non-interactive SSH method available. Configure PFSENSE_SSH_KEY in secrets.txt or install PuTTY (plink/pscp) in PATH."
                        }

                    p = password or self.secrets.get("PFSENSE_PASSWORD", "")
                    if not p:
                        return {"success": False, "error": "PFSENSE_PASSWORD not set. Add it to secrets.txt to enable non-interactive SSH."}

                    # Use -batch to avoid prompts
                    scp_cmd = (
                        f'pscp -batch -pw "{p}" "{bundle_file}" {user}@{host}:/tmp/pfsense-client-update.zip'
                    )
                    result = self.run_command(scp_cmd, check=False)
                    if not result or result.returncode != 0:
                        return {"success": False, "error": f"Failed to upload bundle: {result.stderr if result else 'Unknown error'}"}

                    scp_cmd2 = (
                        f'pscp -batch -pw "{p}" "{deploy_script_path}" {user}@{host}:/tmp/deploy_remote.sh'
                    )
                    result = self.run_command(scp_cmd2, check=False)
                    if not result or result.returncode != 0:
                        return {"success": False, "error": f"Failed to upload deployment script: {result.stderr if result else 'Unknown error'}"}

                    ssh_cmd = (
                        f'plink -batch -pw "{p}" {user}@{host} "chmod +x /tmp/deploy_remote.sh && /tmp/deploy_remote.sh"'
                    )
                    result = self.run_command(ssh_cmd, check=False)

                if result and result.returncode == 0:
                    return {
                        "success": True,
                        "message": f"Client {client_name} updated successfully",
                        "output": result.stdout
                    }
                else:
                    return {
                        "success": False,
                        "error": f"Deployment failed: {result.stderr if result else 'Unknown error'}",
                        "output": result.stdout if result else None
                    }

            finally:
                # Cleanup temporary deployment script
                try:
                    os.unlink(deploy_script_path)
                except Exception:
                    pass

        except Exception as e:
            logger.error(f"Failed to upload and deploy: {e}")
            return {
                "success": False,
                "error": f"Upload/deployment error: {str(e)}"
            }
    
    def update_client(self, client_id: str, force_restart: bool = False) -> Dict[str, Any]:
        """Main method to update a client"""
        try:
            logger.info(f"Starting client update for {client_id}")
            
            # Step 1: Create bundle
            bundle_file = self.create_client_bundle()
            if not bundle_file:
                return {
                    "success": False,
                    "error": "Failed to create client bundle"
                }
            
            # Step 2: Get connection info
            connection_info = self.get_client_connection_info(client_id)
            if not connection_info:
                return {
                    "success": False,
                    "error": f"Could not get connection info for client {client_id}"
                }
            
            # Step 3: Upload and deploy (using hardcoded password for now)
            # In production, this should come from secure storage
            password = "Lns12345678()"  # From secrets.txt
            
            result = self.upload_and_deploy(bundle_file, connection_info, password)
            
            if result["success"]:
                logger.info(f"Client {client_id} updated successfully")
            else:
                logger.error(f"Failed to update client {client_id}: {result['error']}")
            
            return result
            
        except Exception as e:
            logger.error(f"Client update failed: {e}")
            return {
                "success": False,
                "error": f"Client update failed: {str(e)}"
            }
