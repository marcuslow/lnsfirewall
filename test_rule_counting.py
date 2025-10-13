#!/usr/bin/env python3
"""
Test script to verify rule counting functionality
"""

import requests
import json
import sys

# Test configuration
HQ_URL = "http://localhost:8000"
CLIENT_ID = "opus-1"  # Use the existing client

def test_server_connection():
    """Test if server is running"""
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

def test_rules_status():
    """Test rules status endpoint"""
    print("\n1. Testing rules status...")
    try:
        response = requests.get(f"{HQ_URL}/rules/status", params={"client_id": CLIENT_ID}, timeout=10)
        if response.status_code == 200:
            data = response.json()
            print(f"   ✅ Rules status successful")
            print(f"   Has rules: {data.get('has_rules')}")
            print(f"   Rule count: {data.get('rule_count')}")
            print(f"   Latest ruleset ID: {data.get('latest_ruleset_id')}")
            return data.get('has_rules', False)
        else:
            print(f"   ❌ Rules status failed: {response.status_code}")
            print(f"   Error: {response.text}")
            return False
    except Exception as e:
        print(f"   ❌ Exception: {e}")
        return False

def test_blocking_rules_query():
    """Test querying for blocking rules"""
    print("\n2. Testing blocking rules query...")
    
    # Test different variations of blocking rule queries
    queries = [
        "how many blocking rules",
        "show me blocking rules", 
        "rules for blocking",
        "block rules",
        "rejected rules"
    ]
    
    for query in queries:
        print(f"\n   Testing query: '{query}'")
        try:
            # Use the AI command center endpoint
            payload = {
                "client_id": CLIENT_ID,
                "query": query
            }
            
            response = requests.post(f"{HQ_URL}/ai/query", json=payload, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('success'):
                    print(f"   ✅ Query successful")
                    
                    # Check if we got blocking rules
                    if 'blocking' in data.get('results', {}):
                        blocking_rules = data['results']['blocking']
                        count = len(blocking_rules) if isinstance(blocking_rules, list) else 0
                        print(f"   📊 Found {count} blocking rules")
                        
                        # Show first few rules as examples
                        if count > 0:
                            print(f"   📋 First few blocking rules:")
                            for i, rule in enumerate(blocking_rules[:3], 1):
                                action = rule.get('action', 'unknown')
                                interface = rule.get('interface', 'unknown')
                                descr = rule.get('descr', 'No description')
                                print(f"      {i}. Action: {action}, Interface: {interface}")
                                print(f"         Description: {descr}")
                    else:
                        print(f"   ⚠️  No 'blocking' key in results")
                        print(f"   Available keys: {list(data.get('results', {}).keys())}")
                        
                    # Check counts
                    counts = data.get('counts', {})
                    if counts.get('blocking') is not None:
                        print(f"   📊 Count from counts field: {counts['blocking']}")
                    
                else:
                    print(f"   ❌ Query failed: {data.get('error', 'Unknown error')}")
            else:
                print(f"   ❌ HTTP error {response.status_code}: {response.text}")
                
        except Exception as e:
            print(f"   ❌ Exception: {e}")
        
        print()  # Add spacing between queries

def test_direct_rule_query():
    """Test direct rule query endpoint"""
    print("\n3. Testing direct rule query...")
    
    try:
        payload = {
            "client_id": CLIENT_ID,
            "query": "blocking rules"
        }
        
        # Check if there's a direct rules query endpoint
        response = requests.post(f"{HQ_URL}/rules/query", json=payload, timeout=30)
        
        if response.status_code == 200:
            data = response.json()
            print(f"   ✅ Direct rule query successful")
            print(f"   Response: {json.dumps(data, indent=2)}")
        elif response.status_code == 404:
            print(f"   ℹ️  No direct rule query endpoint (404)")
        else:
            print(f"   ❌ Direct rule query failed: {response.status_code}")
            print(f"   Error: {response.text}")
            
    except Exception as e:
        print(f"   ❌ Exception: {e}")

if __name__ == "__main__":
    print("Testing Rule Counting Functionality")
    print("=" * 60)
    
    if not test_server_connection():
        print("\n❌ Cannot proceed - server not accessible")
        sys.exit(1)
    
    # Test if we have rules
    has_rules = test_rules_status()
    if not has_rules:
        print("\n⚠️  No rules available for testing")
        print("   You may need to fetch rules first using get_firewall_rules")
    
    # Test blocking rules queries
    test_blocking_rules_query()
    
    # Test direct rule query
    test_direct_rule_query()
    
    print("\n" + "=" * 60)
    print("✅ Rule counting test complete!")
    print("=" * 60)
