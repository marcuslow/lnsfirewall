#!/usr/bin/env python3
"""
Test script to verify the firewall rules ingest fix
Tests the /rules/ingest endpoint to ensure UUID/integer field mapping is correct
"""

import requests
import json
import uuid
import sys

# Test configuration
HQ_URL = "http://localhost:8000"
TEST_CLIENT_ID = "test-client-fix"
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
    <descr>Test rule for fix verification</descr>
</rule>"""

def test_rules_ingest():
    """Test the rules ingest endpoint"""
    print("=" * 60)
    print("Testing Rules Ingest Fix")
    print("=" * 60)
    
    # Test payload
    payload = {
        "client_id": TEST_CLIENT_ID,
        "rules_xml": TEST_RULES_XML,
        "command_id": str(uuid.uuid4())
    }
    
    print(f"1. Testing /rules/ingest with client_id: {TEST_CLIENT_ID}")
    print(f"   Rules XML length: {len(TEST_RULES_XML)} characters")
    
    try:
        # Send rules ingest request
        response = requests.post(f"{HQ_URL}/rules/ingest", json=payload, timeout=30)
        
        print(f"   Response status: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            print("   ✅ Rules ingest successful!")
            print(f"   Ruleset ID: {data.get('ruleset_id')}")
            print(f"   Rule count: {data.get('rule_count')}")
            print(f"   Size: {data.get('size_bytes')} bytes")
            
            # Test rules status endpoint
            print(f"\n2. Testing /rules/status for client: {TEST_CLIENT_ID}")
            status_response = requests.get(f"{HQ_URL}/rules/status", params={"client_id": TEST_CLIENT_ID}, timeout=10)
            
            if status_response.status_code == 200:
                status_data = status_response.json()
                print("   ✅ Rules status successful!")
                print(f"   Has rules: {status_data.get('has_rules')}")
                print(f"   Latest ruleset ID: {status_data.get('latest_ruleset_id')}")
                print(f"   Age: {status_data.get('age_minutes')} minutes")
                
                # Verify the ruleset IDs match
                if data.get('ruleset_id') == status_data.get('latest_ruleset_id'):
                    print("   ✅ Ruleset IDs match correctly!")
                    return True
                else:
                    print(f"   ❌ Ruleset ID mismatch!")
                    print(f"      Ingest returned: {data.get('ruleset_id')}")
                    print(f"      Status returned: {status_data.get('latest_ruleset_id')}")
                    return False
            else:
                print(f"   ❌ Rules status failed: {status_response.status_code}")
                print(f"   Error: {status_response.text}")
                return False
                
        else:
            print(f"   ❌ Rules ingest failed: {response.status_code}")
            print(f"   Error: {response.text}")
            return False
            
    except Exception as e:
        print(f"   ❌ Exception occurred: {e}")
        return False

def test_server_health():
    """Test if the server is running"""
    try:
        response = requests.get(f"{HQ_URL}/", timeout=5)
        if response.status_code == 200:
            print("✅ HQ Server is running")
            return True
        else:
            print(f"❌ HQ Server returned {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Cannot connect to HQ Server: {e}")
        return False

if __name__ == "__main__":
    print("Testing Firewall Rules Ingest Fix")
    print("=" * 60)
    
    # Check server health first
    if not test_server_health():
        print("\n❌ Cannot proceed - HQ Server is not accessible")
        sys.exit(1)
    
    print()
    
    # Run the test
    if test_rules_ingest():
        print("\n" + "=" * 60)
        print("✅ ALL TESTS PASSED - Fix is working correctly!")
        print("=" * 60)
        sys.exit(0)
    else:
        print("\n" + "=" * 60)
        print("❌ TESTS FAILED - Fix needs more work")
        print("=" * 60)
        sys.exit(1)
