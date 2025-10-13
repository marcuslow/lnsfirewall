#!/usr/bin/env python3
"""Test the fresh logs check"""
import asyncio
from hq.ai_command_center import AICommandCenter

async def test():
    ai = AICommandCenter(
        hq_url="http://localhost:8000",
        openai_api_key="test-key"
    )
    
    print("=" * 60)
    print("Testing _ensure_fresh_logs with 1 hour threshold")
    print("=" * 60)
    
    # Test with opus-1
    print("\n1. Checking freshness for opus-1...")
    result = await ai._ensure_fresh_logs("opus-1", max_age_hours=1)
    
    print(f"\nResult:")
    print(f"  Fresh: {result.get('fresh')}")
    print(f"  Age (hours): {result.get('age_hours')}")
    print(f"  Refreshed: {result.get('refreshed')}")
    print(f"  Error: {result.get('error', 'None')}")
    
    if result.get('fresh'):
        print("\n✅ Logs are fresh - should skip download")
    else:
        print("\n⚠️  Logs are stale - will download")
    
    # Now test perform_risk_assessment to see if it skips download
    print("\n" + "=" * 60)
    print("Testing perform_risk_assessment (should skip download)")
    print("=" * 60)
    
    print("\n2. Running risk assessment...")
    assessment = await ai.perform_risk_assessment("opus-1", days=7, force_refresh=False)
    
    if assessment.get('success'):
        print("\n✅ Risk assessment succeeded!")
        a = assessment.get('assessment', {})
        print(f"  Risk level: {a.get('risk_level')}")
        print(f"  Key findings: {len(a.get('key_findings', []))} items")
        for finding in a.get('key_findings', [])[:5]:
            print(f"    - {finding}")
    else:
        print(f"\n❌ Risk assessment failed: {assessment.get('error')}")

asyncio.run(test())

