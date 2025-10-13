#!/usr/bin/env python3
"""
Test threat intelligence function
"""
import asyncio
import sys
import os
import json
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from hq.ai_command_center import AICommandCenter

async def test_threat_intel():
    print("=" * 60)
    print("THREAT INTELLIGENCE TEST")
    print("=" * 60)
    
    ai_center = AICommandCenter(
        hq_url="http://localhost:8000",
        openai_api_key="test-key"
    )
    
    print("🔍 Testing threat intelligence detection...")
    try:
        result = await ai_center.query_logs("opus-1", "threat intelligence", days=7, top_n=10)
        
        print(f"✅ Query completed!")
        print(f"📊 Result keys: {list(result.keys())}")
        
        if result.get('success'):
            results = result.get('results', {})
            print(f"📋 Results keys: {list(results.keys())}")
            
            if 'threat_intel_analysis' in results:
                threat_intel = results['threat_intel_analysis']
                print(f"\n🔍 Threat intel details:")
                print(f"   Success: {threat_intel.get('success', False)}")
                print(f"   Total IPs checked: {threat_intel.get('total_ips_checked', 0)}")
                print(f"   Malicious IPs found: {threat_intel.get('malicious_ips_found', 0)}")
                print(f"   API calls made: {threat_intel.get('api_calls_made', 0)}")
                
                if 'malicious_ips' in threat_intel:
                    malicious = threat_intel['malicious_ips']
                    print(f"   Malicious IPs: {len(malicious) if isinstance(malicious, list) else 'N/A'}")
                    if isinstance(malicious, list) and len(malicious) > 0:
                        print(f"   First malicious IP: {malicious[0]}")
            else:
                print("❌ No threat_intel_analysis in results")
        else:
            print(f"❌ Query failed: {result.get('error')}")
            
    except Exception as e:
        print(f"❌ Exception: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(test_threat_intel())
