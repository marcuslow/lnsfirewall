#!/usr/bin/env python3
"""
Test rules ingest with proper client registration first
"""

import requests
import json
import uuid

# Test configuration
HQ_URL = "http://localhost:8000"
TEST_CLIENT_ID = "test-registered-client"
TEST_CLIENT_NAME = "test-client"
TEST_RULES_XML = """<rule>
    <type>pass</type>
    <interface>wan</interface>
    <ipprotocol>inet</ipprotocol>
    <protocol>tcp</protocol>
    <source>
        <any/>
    </source>
    <destination>
        <any/>
    </destination>
    <descr>Test rule with registration</descr>
</rule>"""

def register_client():
    """Register a test client first"""
    print("1. Registering test client...")
    
    payload = {
        "client_id": TEST_CLIENT_ID,
        "client_name": TEST_CLIENT_NAME,
        "hostname": "test-host",
        "system_health": {"status": "test"}
    }
    
    try:
        response = requests.post(f"{HQ_URL}/register", json=payload, timeout=10)
        print(f"   Registration status: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            print(f"   ✅ Client registered successfully")
            return True
        else:
            print(f"   ❌ Registration failed: {response.text}")
            return False
            
    except Exception as e:
        print(f"   ❌ Registration exception: {e}")
        return False

def test_rules_ingest():
    """Test rules ingest with registered client"""
    print("\n2. Testing rules ingest...")
    
    payload = {
        "client_id": TEST_CLIENT_ID,
        "rules_xml": TEST_RULES_XML,
        "command_id": str(uuid.uuid4())
    }
    
    try:
        response = requests.post(f"{HQ_URL}/rules/ingest", json=payload, timeout=30)
        print(f"   Ingest status: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            print(f"   ✅ Rules ingest successful!")
            print(f"   Ruleset ID: {data.get('ruleset_id')}")
            return True
        else:
            print(f"   ❌ Ingest failed: {response.text}")
            return False
            
    except Exception as e:
        print(f"   ❌ Ingest exception: {e}")
        return False

def check_server():
    """Check if server is running"""
    try:
        response = requests.get(f"{HQ_URL}/", timeout=5)
        if response.status_code == 200:
            print("✅ Server is running")
            return True
        else:
            print(f"❌ Server returned {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Cannot connect to server: {e}")
        return False

if __name__ == "__main__":
    print("Testing Rules Ingest with Client Registration")
    print("=" * 60)
    
    if not check_server():
        exit(1)
    
    if register_client():
        if test_rules_ingest():
            print("\n✅ ALL TESTS PASSED!")
        else:
            print("\n❌ Rules ingest test failed")
    else:
        print("\n❌ Client registration failed")
