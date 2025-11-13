#!/usr/bin/env python3
"""
Test threat intelligence function in detail
"""
import asyncio
import sys
import os
import json
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from hq.ai_command_center import AICommandCenter

async def test_threat_intel_detailed():
    print("=" * 60)
    print("DETAILED THREAT INTELLIGENCE TEST")
    print("=" * 60)
    
    ai_center = AICommandCenter(
        hq_url="http://localhost:8000",
        openai_api_key="test-key"
    )
    
    print("🔍 Testing threat intelligence detection...")
    try:
        result = await ai_center.query_logs("opus-1", "threat intelligence", days=7, top_n=10)
        
        print(f"✅ Query completed!")
        
        # Print full result for debugging
        print("\n📋 Full result:")
        print(json.dumps(result, indent=2, default=str))
            
    except Exception as e:
        print(f"❌ Exception: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(test_threat_intel_detailed())
