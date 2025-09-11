#!/usr/bin/env python3
"""
Test script to verify client can connect to HQ server
"""

import requests
import json
import yaml
import sys
from pathlib import Path

def test_connection():
    """Test connection to HQ server"""
    
    # Load client config
    config_path = "config/client_config.yaml"
    try:
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
    except Exception as e:
        print(f"❌ Failed to load config: {e}")
        return False

    # Use localhost for testing since ngrok has traffic limits
    hq_url = 'http://localhost:8000'  # Override to use localhost
    client_name = config.get('client_name', 'test-client')

    print(f"🔧 Note: Using localhost instead of ngrok due to traffic limits")
    
    print(f"🔗 Testing connection to HQ server: {hq_url}")
    print(f"📋 Client name: {client_name}")
    
    # Test 1: Basic connectivity
    try:
        response = requests.get(f"{hq_url}/", timeout=10)
        print(f"✅ Basic connectivity: {response.status_code}")
    except Exception as e:
        print(f"❌ Basic connectivity failed: {e}")
        return False
    
    # Test 2: Register client
    try:
        register_data = {
            "client_id": "test-client-001",
            "client_name": client_name,
            "hostname": "test-hostname"
        }
        
        response = requests.post(
            f"{hq_url}/register",
            json=register_data,
            timeout=10
        )
        
        if response.status_code == 200:
            result = response.json()
            print(f"✅ Client registration: {result}")
        else:
            print(f"⚠️  Registration response: {response.status_code} - {response.text}")
            
    except Exception as e:
        print(f"❌ Registration failed: {e}")
        return False
    
    # Test 3: Check for commands (using correct POST /poll endpoint)
    try:
        poll_data = {
            "client_id": "test-client-001"
        }

        response = requests.post(
            f"{hq_url}/poll",
            json=poll_data,
            timeout=10
        )

        if response.status_code == 200:
            result = response.json()
            commands = result.get("commands", [])
            print(f"✅ Command polling: {len(commands)} commands pending")
        else:
            print(f"⚠️  Command polling response: {response.status_code} - {response.text}")

    except Exception as e:
        print(f"❌ Command polling failed: {e}")
        return False
    
    print("\n🎉 Connection test completed successfully!")
    print("\nNext steps:")
    print("1. Run the actual client: python3 client/pfsense_client.py")
    print("2. Or install on pfSense using: ./setup_client.sh")
    
    return True

if __name__ == "__main__":
    success = test_connection()
    sys.exit(0 if success else 1)
