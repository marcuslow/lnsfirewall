#!/usr/bin/env python3
"""
Simple test to get the exact count of blocking rules
"""

import asyncio
import sys
import os

# Add the hq directory to the path
sys.path.append(os.path.join(os.path.dirname(__file__), 'hq'))

from ai_command_center import AICommandCenter

async def get_blocking_count():
    """Get the exact count of blocking rules"""
    print("Getting Blocking Rules Count")
    print("=" * 40)
    
    # Initialize AI command center
    hq_url = "http://localhost:8000"
    openai_api_key = "test-key"
    ai_center = AICommandCenter(hq_url, openai_api_key)
    
    client_id = "opus-1"
    
    try:
        # Query for blocking rules
        result = await ai_center.query_cached_rules(client_id, "blocking rules")
        
        if result.get('success'):
            results = result.get('results', {})
            counts = result.get('counts', {})
            
            if 'blocking' in results:
                blocking_rules = results['blocking']
                count = len(blocking_rules)
                
                print(f"✅ Found {count} blocking rules")
                print(f"📊 Count from counts field: {counts.get('blocking', 'N/A')}")
                
                print(f"\n📋 All {count} blocking rules:")
                for i, rule in enumerate(blocking_rules, 1):
                    action = rule.get('action', 'unknown')
                    interface = rule.get('interface', 'unknown')
                    descr = rule.get('descr', 'No description')
                    src_addr = rule.get('src_addr', 'any')
                    dst_addr = rule.get('dst_addr', 'any')
                    protocol = rule.get('protocol', 'any')
                    
                    print(f"\n{i}. Action: {action}")
                    print(f"   Interface: {interface}")
                    print(f"   Protocol: {protocol}")
                    print(f"   Source: {src_addr}")
                    print(f"   Destination: {dst_addr}")
                    print(f"   Description: {descr}")
                
                return count
            else:
                print("❌ No blocking rules found")
                return 0
        else:
            print(f"❌ Query failed: {result.get('error', 'unknown')}")
            return 0
            
    except Exception as e:
        print(f"❌ Exception: {e}")
        return 0

if __name__ == "__main__":
    count = asyncio.run(get_blocking_count())
    print(f"\n" + "=" * 40)
    print(f"🔥 ANSWER: There are {count} blocking rules")
    print("=" * 40)
