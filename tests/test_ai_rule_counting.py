#!/usr/bin/env python3
"""
Test the AI command center rule counting functionality directly
"""

import asyncio
import sys
import os

# Add the hq directory to the path so we can import the AI command center
sys.path.append(os.path.join(os.path.dirname(__file__), 'hq'))

from ai_command_center import AICommandCenter

async def test_rule_counting():
    """Test rule counting functionality directly"""
    print("Testing AI Command Center Rule Counting")
    print("=" * 60)
    
    # Initialize AI command center
    hq_url = "http://localhost:8000"
    openai_api_key = "test-key"  # We don't need real OpenAI for this test
    ai_center = AICommandCenter(hq_url, openai_api_key)
    
    # Test client ID
    client_id = "opus-1"
    
    print(f"Testing with client: {client_id}")
    
    # Test 1: Check if we have cached rules
    print("\n1. Checking cached rules...")
    try:
        result = await ai_center.query_cached_rules(client_id, "summary")
        if result.get('success'):
            print("   ✅ Cached rules available")
            print(f"   Rule count: {result.get('rule_count', 'unknown')}")
            print(f"   Ruleset ID: {result.get('ruleset_id', 'unknown')}")
        else:
            print(f"   ❌ No cached rules: {result.get('error', 'unknown error')}")
            return False
    except Exception as e:
        print(f"   ❌ Exception checking cached rules: {e}")
        return False
    
    # Test 2: Query for blocking rules
    print("\n2. Querying for blocking rules...")
    try:
        result = await ai_center.query_cached_rules(client_id, "blocking rules")
        if result.get('success'):
            print("   ✅ Blocking rules query successful")
            
            results = result.get('results', {})
            counts = result.get('counts', {})
            
            print(f"   Results keys: {list(results.keys())}")
            print(f"   Counts: {counts}")
            
            # Check for blocking rules
            if 'blocking' in results:
                blocking_rules = results['blocking']
                count = len(blocking_rules) if isinstance(blocking_rules, list) else 0
                print(f"   📊 Found {count} blocking rules")
                
                # Show details of first few rules
                if count > 0:
                    print(f"   📋 First few blocking rules:")
                    for i, rule in enumerate(blocking_rules[:3], 1):
                        action = rule.get('action', 'unknown')
                        interface = rule.get('interface', 'unknown')
                        descr = rule.get('descr', 'No description')[:50]
                        src_addr = rule.get('src_addr', 'any')
                        dst_addr = rule.get('dst_addr', 'any')
                        print(f"      {i}. Action: {action}, Interface: {interface}")
                        print(f"         Description: {descr}")
                        print(f"         Source: {src_addr} -> Destination: {dst_addr}")
                        print()
                        
                return True
            else:
                print(f"   ⚠️  No 'blocking' key in results")
                print(f"   Available keys: {list(results.keys())}")
                return False
        else:
            print(f"   ❌ Blocking rules query failed: {result.get('error', 'unknown error')}")
            return False
    except Exception as e:
        print(f"   ❌ Exception querying blocking rules: {e}")
        return False

    # Test 3: Try different query variations
    print("\n3. Testing different query variations...")
    queries = [
        "how many blocking rules",
        "block rules",
        "rejected rules", 
        "rules that block traffic"
    ]
    
    for query in queries:
        print(f"\n   Testing: '{query}'")
        try:
            result = await ai_center.query_cached_rules(client_id, query)
            if result.get('success'):
                results = result.get('results', {})
                counts = result.get('counts', {})
                
                if 'blocking' in results:
                    count = len(results['blocking'])
                    print(f"      ✅ Found {count} blocking rules")
                elif 'blocking' in counts and counts['blocking'] is not None:
                    print(f"      ✅ Count: {counts['blocking']} blocking rules")
                else:
                    print(f"      ⚠️  No blocking results for this query")
                    print(f"      Available keys: {list(results.keys())}")
            else:
                print(f"      ❌ Query failed: {result.get('error', 'unknown')}")
        except Exception as e:
            print(f"      ❌ Exception: {e}")

if __name__ == "__main__":
    asyncio.run(test_rule_counting())
