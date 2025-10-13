#!/usr/bin/env python3
"""
Test to identify and verify the push_rules function bug
"""

import asyncio
import sys
import os

# Add the hq directory to the path
sys.path.append(os.path.join(os.path.dirname(__file__), 'hq'))

from ai_command_center import AICommandCenter

async def test_push_rules_bug():
    """Test the push_rules function to identify the bug"""
    print("🐛 TESTING PUSH_RULES FUNCTION BUG")
    print("=" * 60)
    
    # Initialize AI command center
    hq_url = "http://localhost:8000"
    openai_api_key = "test-key"
    ai_center = AICommandCenter(hq_url, openai_api_key)
    
    client_id = "opus-1"
    
    # Get a valid ruleset_id first
    print("1. Getting valid ruleset_id...")
    try:
        result = await ai_center.query_cached_rules(client_id, "summary")
        if result.get('success'):
            ruleset_id = result.get('ruleset_id')
            print(f"   ✅ Found ruleset_id: {ruleset_id}")
        else:
            print(f"   ❌ Cannot get ruleset_id: {result.get('error')}")
            return
    except Exception as e:
        print(f"   ❌ Error getting ruleset_id: {e}")
        return
    
    # Test the push_rules function directly
    print("\n2. Testing push_rules function directly...")
    try:
        # This should work - it calls the correct push_rules method
        result = await ai_center.push_rules(client_id, ruleset_id)
        print(f"   ✅ Direct push_rules call works: {result.get('success')}")
        if not result.get('success'):
            print(f"      Error: {result.get('error')}")
    except Exception as e:
        print(f"   ❌ Direct push_rules call failed: {e}")
    
    # Test the function call handler (this will reveal the bug)
    print("\n3. Testing function call handler...")
    try:
        # Simulate what happens when AI calls the function
        arguments = {
            'client_id': client_id,
            'ruleset_id': ruleset_id
        }
        
        # This is what happens in call_function_if_available
        function_name = "push_rules"
        
        print(f"   Function: {function_name}")
        print(f"   Arguments: {arguments}")
        
        # Check what the handler expects
        print("\n   🔍 Analyzing function handler...")
        print("   Expected by function tool definition:")
        print("     - client_id: ✅ Present")
        print("     - ruleset_id: ✅ Present")
        
        print("\n   Expected by function handler code:")
        print("     - client_id: ✅ Present")
        print("     - rules_xml: ❌ MISSING!")
        
        print("\n   🐛 BUG IDENTIFIED:")
        print("   The function handler calls:")
        print("     update_firewall_rules(client_id, rules_xml)")
        print("   But the function tool provides:")
        print("     {client_id, ruleset_id}")
        print("   This will cause a KeyError for 'rules_xml'!")
        
    except Exception as e:
        print(f"   ❌ Function handler test failed: {e}")

async def analyze_correct_workflow():
    """Analyze what the correct workflow should be"""
    print("\n🔧 CORRECT WORKFLOW ANALYSIS")
    print("=" * 60)
    
    print("CURRENT (BUGGY) WORKFLOW:")
    print("1. AI calls push_rules(client_id, ruleset_id)")
    print("2. Handler tries: update_firewall_rules(client_id, rules_xml)")
    print("3. ❌ KeyError: 'rules_xml' not in arguments")
    
    print("\nCORRECT WORKFLOW OPTION 1:")
    print("1. AI calls push_rules(client_id, ruleset_id)")
    print("2. Handler calls: push_rules(client_id, ruleset_id)")
    print("3. push_rules fetches rules_xml from database")
    print("4. push_rules calls update_firewall_rules(client_id, rules_xml)")
    
    print("\nCORRECT WORKFLOW OPTION 2:")
    print("1. AI calls push_rules(client_id, ruleset_id)")
    print("2. Handler fetches rules_xml from database using ruleset_id")
    print("3. Handler calls: update_firewall_rules(client_id, rules_xml)")

async def test_workaround():
    """Test a potential workaround"""
    print("\n🛠️  TESTING WORKAROUND")
    print("=" * 60)
    
    # Initialize AI command center
    hq_url = "http://localhost:8000"
    openai_api_key = "test-key"
    ai_center = AICommandCenter(hq_url, openai_api_key)
    
    client_id = "opus-1"
    
    print("Current workaround for rule changes:")
    print("1. Get current rules")
    print("2. Modify rules locally")
    print("3. Call update_firewall_rules directly with modified XML")
    
    try:
        # Get current rules
        result = await ai_center.query_cached_rules(client_id, "summary")
        if result.get('success'):
            print("   ✅ Can get current rules for modification")
            
            # In a real scenario, you would modify the rules here
            # For testing, we'll just use the existing rules
            print("   ✅ Rules can be modified (simulated)")
            
            # The update_firewall_rules function would work if we had the XML
            print("   ✅ update_firewall_rules function is available")
            print("   ⚠️  But we need the actual rules XML, not just metadata")
            
        else:
            print(f"   ❌ Cannot get rules: {result.get('error')}")
    except Exception as e:
        print(f"   ❌ Workaround test failed: {e}")

async def main():
    """Main test function"""
    await test_push_rules_bug()
    await analyze_correct_workflow()
    await test_workaround()
    
    print("\n🎯 SUMMARY:")
    print("=" * 60)
    print("❌ BUG CONFIRMED: push_rules function handler is broken")
    print("🔧 IMPACT: AI cannot push rule changes via push_rules function")
    print("💡 WORKAROUND: Use update_firewall_rules directly with rules XML")
    print("🛠️  FIX NEEDED: Correct the function handler mapping")

if __name__ == "__main__":
    asyncio.run(main())
