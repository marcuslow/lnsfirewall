#!/usr/bin/env python3
"""Test log storage after fixes"""
import asyncio
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from hq.ai_command_center import AICommandCenter

async def test_log_storage():
    print("=" * 80)
    print("Testing Log Storage After Fixes")
    print("=" * 80)
    
    # Initialize AI Command Center
    ai_center = AICommandCenter(
        hq_url="http://localhost:8000",
        openai_api_key="test-key"  # Not needed for this test
    )
    
    # Request logs for opus-1
    client_id = "opus-1"
    print(f"\n🔄 Requesting logs for {client_id}...")
    
    try:
        result = await ai_center.request_client_logs(client_id, days=1)
        print(f"📊 Request result: {result}")
        
        if result.get('success'):
            # Wait for logs to be processed
            print("⏳ Waiting 10 seconds for logs to be processed...")
            await asyncio.sleep(10)
            
            # Check if logs are now in database
            import sqlite3
            conn = sqlite3.connect('hq_database.db')
            cursor = conn.cursor()
            
            cursor.execute('SELECT COUNT(*) FROM logs WHERE client_id = ?', ('8cbb62eecbb00579',))
            count = cursor.fetchone()[0]
            print(f"📊 Logs in database: {count}")
            
            if count > 0:
                cursor.execute('''
                    SELECT id, timestamp, compressed, size_bytes, LENGTH(log_data) as data_len
                    FROM logs 
                    WHERE client_id = ? 
                    ORDER BY timestamp DESC 
                    LIMIT 1
                ''', ('8cbb62eecbb00579',))
                
                row = cursor.fetchone()
                if row:
                    log_id, timestamp, compressed, size_bytes, data_len = row
                    print(f"✅ Latest log entry:")
                    print(f"   ID: {log_id}")
                    print(f"   Timestamp: {timestamp}")
                    print(f"   Compressed: {compressed}")
                    print(f"   Size bytes: {size_bytes}")
                    print(f"   Data length: {data_len}")
                    
                    # Test LogQueryEngine
                    print(f"\n🔍 Testing LogQueryEngine...")
                    from hq.lqe import LogQueryEngine
                    lqe = LogQueryEngine.from_db('hq_database.db', '8cbb62eecbb00579', since_days=1)
                    print(f"✅ LogQueryEngine loaded {len(lqe.entries)} entries")
                    
                    if lqe.entries:
                        sample = lqe.entries[0]
                        print(f"   Sample entry: {sample}")
            
            conn.close()
        else:
            print(f"❌ Failed to request logs: {result}")
            
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(test_log_storage())
