#!/usr/bin/env python3
"""
Test scanning detection in detail
"""
import asyncio
import sys
import os
import json
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from hq.ai_command_center import AICommandCenter

async def test_scanning_detailed():
    print("=" * 60)
    print("DETAILED SCANNING TEST")
    print("=" * 60)
    
    ai_center = AICommandCenter(
        hq_url="http://localhost:8000",
        openai_api_key="test-key"
    )
    
    print("🔍 Testing scanning detection...")
    try:
        result = await ai_center.query_logs("opus-1", "scanning", days=7, top_n=10)
        
        print(f"✅ Query completed!")
        print(f"📊 Result keys: {list(result.keys())}")
        
        # Print full result for debugging
        print("\n📋 Full result:")
        print(json.dumps(result, indent=2, default=str))
        
        # Check specific fields
        if 'scanning_activity' in result:
            scanning = result['scanning_activity']
            print(f"\n🔍 Scanning activity details:")
            print(json.dumps(scanning, indent=2, default=str))
        
        if 'analysis_type' in result:
            print(f"\n📊 Analysis type: {result['analysis_type']}")
            
    except Exception as e:
        print(f"❌ Exception: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(test_scanning_detailed())
