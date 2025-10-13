#!/usr/bin/env python3
"""Test what 'summary' query returns"""
import asyncio
from hq.ai_command_center import AICommandCenter

async def test():
    ai = AICommandCenter(
        hq_url="http://localhost:8000",
        openai_api_key="test-key"
    )
    
    print("Testing 'summary' query...")
    result = await ai.query_logs(
        client_id="opus-1",
        query="summary",
        days=7,
        auto_refresh=False
    )
    
    print(f"\nSuccess: {result.get('success')}")
    print(f"\nResults keys: {list(result.get('results', {}).keys())}")
    print(f"\nFull results:")
    import json
    print(json.dumps(result.get('results', {}), indent=2))

asyncio.run(test())

