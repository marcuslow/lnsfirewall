#!/usr/bin/env python3
"""
Test port scanning detection specifically
"""
import asyncio
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from hq.ai_command_center import AICommandCenter

async def test_port_scanning():
    print("=" * 60)
    print("PORT SCANNING DETECTION TEST")
    print("=" * 60)
    
    ai_center = AICommandCenter(
        hq_url="http://localhost:8000",
        openai_api_key="test-key"
    )
    
    # Test the exact question from the test suite
    question = "Has opus-1 detected any port scanning activity recently?"
    print(f"🔍 Question: {question}")
    print()
    
    try:
        print("⏳ Querying AI Console...")
        response = await ai_center.chat_with_ai(question)
        
        print("✅ Response received!")
        print()
        print("─" * 60)
        print("AI CONSOLE RESPONSE:")
        print("─" * 60)
        print(response)
        print("─" * 60)
        
        # Check if response mentions scanning results
        response_lower = response.lower()
        if any(word in response_lower for word in ['scan', 'scanning', 'vertical', 'horizontal', 'sweep']):
            print("✅ Response mentions scanning analysis")
        else:
            print("❌ Response does not mention scanning analysis")
            
        if 'port number' in response_lower or 'specify' in response_lower:
            print("❌ Response is asking for clarification instead of running analysis")
        else:
            print("✅ Response provides direct analysis")
            
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(test_port_scanning())
