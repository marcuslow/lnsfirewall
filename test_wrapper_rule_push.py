#!/usr/bin/env python3
"""
Test script to verify rule push workflow with wrapper client
"""

import asyncio
import sys
import os
import json
import time
import requests

# Add the hq directory to the path
sys.path.append(os.path.join(os.path.dirname(__file__), 'hq'))

from ai_command_center import AICommandCenter

async def test_complete_workflow():
    """Test the complete rule push workflow"""
    print("🧪 TESTING COMPLETE RULE PUSH WORKFLOW")
    print("=" * 80)
    
    # Initialize AI command center
    hq_url = "http://localhost:8000"
    openai_api_key = "test-key"
    ai_center = AICommandCenter(hq_url, openai_api_key)
    
    wrapper_client_id = "test-wrapper"
    
    print("📋 Test Plan:")
    print("1. Wait for wrapper client to connect")
    print("2. Get current rules from wrapper")
    print("3. Test push_rules function (fixed)")
    print("4. Test rule modification workflow")
    print("5. Verify file changes on Windows")
    
    # Step 1: Wait for client connection
    print(f"\n1️⃣  WAITING FOR WRAPPER CLIENT CONNECTION")
    print("-" * 50)
    
    max_wait = 30
    connected = False
    
    for i in range(max_wait):
        try:
            response = requests.get(f"{hq_url}/clients", timeout=5)
            if response.status_code == 200:
                clients = response.json().get('clients', {})
                if wrapper_client_id in clients:
                    client_info = clients[wrapper_client_id]
                    print(f"✅ Wrapper client connected!")
                    print(f"   Client ID: {wrapper_client_id}")
                    print(f"   Connection: {client_info.get('connection_type', 'unknown')}")
                    print(f"   Last seen: {client_info.get('last_seen', 'unknown')}")
                    connected = True
                    break
        except Exception as e:
            pass
        
        print(f"   Waiting... ({i+1}/{max_wait})")
        await asyncio.sleep(1)
    
    if not connected:
        print(f"❌ Wrapper client not connected after {max_wait} seconds")
        print("   Make sure to run: python wrapper_pfsense_client.py --client-id test-wrapper")
        return False
    
    # Step 2: Get current rules
    print(f"\n2️⃣  GETTING CURRENT RULES FROM WRAPPER")
    print("-" * 50)
    
    try:
        result = await ai_center.get_firewall_rules(wrapper_client_id)
        if result.get('success'):
            print("✅ Successfully retrieved rules from wrapper")
            print(f"   Rule count: {result.get('rule_count', 'unknown')}")
            print(f"   Config size: {result.get('config_size', 'unknown')} bytes")
            
            # Ingest the rules
            rules_xml = result.get('rules_xml', '')
            if rules_xml:
                print("✅ Rules XML retrieved, ingesting...")
                # The get_firewall_rules method should automatically ingest
            else:
                print("⚠️  No rules XML in response")
        else:
            print(f"❌ Failed to get rules: {result.get('error')}")
            return False
    except Exception as e:
        print(f"❌ Error getting rules: {e}")
        return False
    
    # Step 3: Test push_rules function (now fixed)
    print(f"\n3️⃣  TESTING FIXED PUSH_RULES FUNCTION")
    print("-" * 50)
    
    try:
        # Get the latest ruleset ID
        status_result = await ai_center.get_rules_status(wrapper_client_id)
        if status_result.get('success') and status_result.get('has_rules'):
            ruleset_id = status_result.get('latest_ruleset_id')
            print(f"✅ Found latest ruleset: {ruleset_id}")
            
            # Test the fixed push_rules function
            push_result = await ai_center.push_rules(wrapper_client_id, ruleset_id)
            if push_result.get('success'):
                print("✅ push_rules function works correctly!")
                print(f"   Command ID: {push_result.get('command_id')}")
                
                # Wait for command completion
                command_id = push_result.get('command_id')
                if command_id:
                    print("   Waiting for command completion...")
                    for i in range(10):
                        status = await ai_center.get_command_status(command_id)
                        if status.get('status') == 'completed':
                            response_data = status.get('response_data', {})
                            if isinstance(response_data, str):
                                response_data = json.loads(response_data)
                            
                            if response_data.get('status') == 'success':
                                print("✅ Rule push completed successfully!")
                                print(f"   Message: {response_data.get('message')}")
                                print(f"   Backup file: {response_data.get('backup_file')}")
                                print(f"   Rules applied: {response_data.get('rules_applied')}")
                                break
                            else:
                                print(f"❌ Rule push failed: {response_data.get('message')}")
                                break
                        await asyncio.sleep(1)
                    else:
                        print("⚠️  Command did not complete within timeout")
            else:
                print(f"❌ push_rules failed: {push_result.get('error')}")
        else:
            print("❌ No rules available to push")
    except Exception as e:
        print(f"❌ Error testing push_rules: {e}")
    
    # Step 4: Test rule modification workflow
    print(f"\n4️⃣  TESTING RULE MODIFICATION WORKFLOW")
    print("-" * 50)
    
    try:
        # Get current rules for modification
        result = await ai_center.query_cached_rules(wrapper_client_id, "summary")
        if result.get('success'):
            print("✅ Retrieved cached rules for modification")
            
            # Create a modified version (add a test rule)
            current_rules = result.get('results', {}).get('summary', {}).get('rules_xml', '')
            if current_rules:
                # Add a simple test rule
                test_rule = '''
        <rule>
            <type>block</type>
            <interface>wan</interface>
            <ipprotocol>inet</ipprotocol>
            <statetype>keep state</statetype>
            <direction>in</direction>
            <protocol>tcp</protocol>
            <source>
                <any/>
            </source>
            <destination>
                <network>wan</network>
                <port>1234</port>
            </destination>
            <descr>Test rule added by wrapper test</descr>
        </rule>'''
                
                modified_rules = current_rules + test_rule
                print("✅ Created modified rules with test rule")
                print(f"   Original rules: {current_rules.count('<rule')} rules")
                print(f"   Modified rules: {modified_rules.count('<rule')} rules")
                
                # Push the modified rules
                update_result = await ai_center.update_firewall_rules(wrapper_client_id, modified_rules)
                if update_result.get('success'):
                    print("✅ Modified rules sent successfully!")
                    print(f"   Command ID: {update_result.get('command_id')}")
                    
                    # Wait for completion
                    command_id = update_result.get('command_id')
                    if command_id:
                        print("   Waiting for rule modification completion...")
                        for i in range(10):
                            status = await ai_center.get_command_status(command_id)
                            if status.get('status') == 'completed':
                                response_data = status.get('response_data', {})
                                if isinstance(response_data, str):
                                    response_data = json.loads(response_data)
                                
                                if response_data.get('status') == 'success':
                                    print("✅ Rule modification completed successfully!")
                                    print(f"   Message: {response_data.get('message')}")
                                    print(f"   Rules applied: {response_data.get('rules_applied')}")
                                    break
                                else:
                                    print(f"❌ Rule modification failed: {response_data.get('message')}")
                                    break
                            await asyncio.sleep(1)
                        else:
                            print("⚠️  Rule modification did not complete within timeout")
                else:
                    print(f"❌ Failed to send modified rules: {update_result.get('error')}")
            else:
                print("❌ No rules XML available for modification")
        else:
            print(f"❌ Failed to get cached rules: {result.get('error')}")
    except Exception as e:
        print(f"❌ Error testing rule modification: {e}")
    
    # Step 5: Verify file changes
    print(f"\n5️⃣  VERIFYING FILE CHANGES ON WINDOWS")
    print("-" * 50)
    
    sim_dir = os.path.join(os.getcwd(), "pfsense_simulation")
    config_file = os.path.join(sim_dir, "cf", "conf", "config.xml")
    backup_dir = os.path.join(sim_dir, "backups")
    
    if os.path.exists(config_file):
        print(f"✅ Config file exists: {config_file}")
        
        with open(config_file, 'r') as f:
            content = f.read()
        
        rule_count = content.count('<rule')
        print(f"   Current rule count in file: {rule_count}")
        
        if "Test rule added by wrapper test" in content:
            print("✅ Test rule found in config file!")
        else:
            print("⚠️  Test rule not found in config file")
        
        # Check backups
        if os.path.exists(backup_dir):
            backups = [f for f in os.listdir(backup_dir) if f.startswith('config.xml.backup')]
            print(f"✅ Backup files created: {len(backups)}")
            for backup in backups[-3:]:  # Show last 3 backups
                backup_path = os.path.join(backup_dir, backup)
                backup_time = time.ctime(os.path.getmtime(backup_path))
                print(f"   {backup} (created: {backup_time})")
        else:
            print("⚠️  Backup directory not found")
    else:
        print(f"❌ Config file not found: {config_file}")
    
    print(f"\n" + "=" * 80)
    print("✅ WORKFLOW TEST COMPLETE")
    print("=" * 80)
    
    return True

async def main():
    """Main test function"""
    print("🚀 Starting wrapper client rule push test")
    print("Make sure the HQ server is running and the wrapper client is started!")
    print("To start wrapper client: python wrapper_pfsense_client.py --client-id test-wrapper")
    print()
    
    input("Press Enter when wrapper client is running...")
    
    success = await test_complete_workflow()
    
    if success:
        print("\n🎉 All tests completed! Check the pfsense_simulation directory for results.")
    else:
        print("\n❌ Some tests failed. Check the output above for details.")

if __name__ == "__main__":
    asyncio.run(main())
