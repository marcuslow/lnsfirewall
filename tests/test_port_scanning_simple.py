#!/usr/bin/env python3
"""
Simple test to see what the AI is actually calling for port scanning questions
"""
import asyncio
import sys
import os
import json
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from hq.ai_command_center import AICommandCenter

# Mock the OpenAI API to see what functions are being called
class MockOpenAI:
    def __init__(self):
        self.calls = []
    
    async def chat_completions_create(self, **kwargs):
        self.calls.append(kwargs)
        # Return a mock response that calls query_logs with "scanning"
        return type('MockResponse', (), {
            'choices': [type('Choice', (), {
                'message': type('Message', (), {
                    'tool_calls': [type('ToolCall', (), {
                        'function': type('Function', (), {
                            'name': 'query_logs',
                            'arguments': json.dumps({
                                'client_id': 'opus-1',
                                'query': 'scanning'
                            })
                        })()
                    })()]
                })()
            })]
        })()

async def test_port_scanning_ai_call():
    print("=" * 60)
    print("PORT SCANNING AI CALL TEST")
    print("=" * 60)
    
    # Create AI center with mock OpenAI
    ai_center = AICommandCenter(
        hq_url="http://localhost:8000",
        openai_api_key="test-key"
    )
    
    # Replace the OpenAI client with our mock
    mock_openai = MockOpenAI()
    
    # Test the exact question from the test suite
    question = "Has opus-1 detected any port scanning activity recently?"
    print(f"🔍 Question: {question}")
    print()
    
    try:
        # Manually call the function that should be called
        print("🔧 Testing direct query_logs call with 'scanning'...")
        result = await ai_center.query_logs("opus-1", "scanning", days=7)
        
        if result.get('success'):
            print("✅ Direct query_logs('scanning') works!")
            if 'scanning_activity' in result.get('results', {}):
                scanning = result['results']['scanning_activity']
                print(f"   Found {scanning.get('total_vertical_scans', 0)} vertical scans")
                print(f"   Found {scanning.get('total_horizontal_scans', 0)} horizontal scans")
            else:
                print("❌ No scanning_activity in results")
        else:
            print(f"❌ Direct query_logs failed: {result.get('error')}")
            
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(test_port_scanning_ai_call())
