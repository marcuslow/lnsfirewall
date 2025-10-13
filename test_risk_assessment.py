#!/usr/bin/env python3
"""
Test risk assessment function
"""
import asyncio
import sys
import os
import json
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from hq.ai_command_center import AICommandCenter

async def test_risk_assessment():
    print("=" * 60)
    print("RISK ASSESSMENT TEST")
    print("=" * 60)
    
    ai_center = AICommandCenter(
        hq_url="http://localhost:8000",
        openai_api_key="test-key"
    )
    
    print("🔍 Testing risk assessment...")
    try:
        result = await ai_center.perform_risk_assessment("opus-1", days=7)
        
        print(f"✅ Risk assessment completed!")
        print(f"📊 Result keys: {list(result.keys())}")
        
        if result.get('success'):
            print("✅ Risk assessment succeeded!")
            print(f"   Risk level: {result.get('risk_level', 'Unknown')}")
            print(f"   Key findings: {len(result.get('key_findings', []))} items")
        else:
            print(f"❌ Risk assessment failed: {result.get('error')}")
            
    except Exception as e:
        print(f"❌ Exception: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(test_risk_assessment())
