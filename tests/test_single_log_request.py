#!/usr/bin/env python3
"""
Simple test to trigger one log request and see server debug output
"""
import asyncio
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from hq.ai_command_center import AICommandCenter

async def test_single_log_request():
    print("=" * 60)
    print("SINGLE LOG REQUEST TEST")
    print("=" * 60)
    
    ai_center = AICommandCenter(
        hq_url="http://localhost:8000",
        openai_api_key="test-key"
    )
    
    print("🔄 Requesting logs for opus-1...")
    print("👀 Watch the SERVER terminal for debug messages!")
    print()
    
    try:
        result = await ai_center.request_client_logs("opus-1", days=1)
        print(f"📊 Request result: {result}")
        
        if result.get('success'):
            print("✅ Log request successful!")
            print("⏳ Waiting 5 seconds for processing...")
            await asyncio.sleep(5)
            
            # Check if logs were stored
            import sqlite3
            conn = sqlite3.connect('hq_database.db')
            cursor = conn.cursor()
            
            cursor.execute('SELECT COUNT(*) FROM logs WHERE client_id = ?', ('8cbb62eecbb00579',))
            count = cursor.fetchone()[0]
            print(f"📊 Logs in database after request: {count}")
            
            conn.close()
        else:
            print(f"❌ Log request failed: {result}")
            
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(test_single_log_request())
