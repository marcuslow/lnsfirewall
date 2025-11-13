#!/usr/bin/env python3
"""Test log query functionality"""
import asyncio
import os
import sys
from dotenv import load_dotenv

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from hq.ai_command_center import AICommandCenter

load_dotenv()

async def test():
    print("=" * 80)
    print("Testing AI Command Center - Log Query")
    print("=" * 80)
    
    # Initialize
    hq_url = "http://localhost:8000"
    openai_api_key = os.getenv("OPENAI_API_KEY")
    db_path = "hq_database.db"
    
    if not openai_api_key:
        print("❌ ERROR: OPENAI_API_KEY not found in .env")
        return
    
    print(f"\n✓ Initializing AI Command Center...")
    ai_center = AICommandCenter(hq_url=hq_url, openai_api_key=openai_api_key, db_path=db_path)
    
    print(f"✓ Testing geographic analysis query...")
    try:
        response = await ai_center.chat_with_ai("Which countries are the attacks on opus-1 coming from?")
        print(f"\n{'=' * 80}")
        print("RESPONSE:")
        print(f"{'=' * 80}")
        print(response[:500] + "..." if len(response) > 500 else response)
        print(f"{'=' * 80}")
        print("\n✅ SUCCESS!")
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(test())
