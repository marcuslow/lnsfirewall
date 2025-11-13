#!/usr/bin/env python3

import asyncio
import requests
import sqlite3
import time
from hq.ai_command_center import AICommandCenter

async def test_log_normalization():
    print("🧪 Testing Client Name Normalization for Logs")
    print("=" * 60)
    
    # Initialize AI Command Center
    ai = AICommandCenter(hq_url="http://localhost:8000", openai_api_key="dummy")
    
    # Step 1: Request logs for opus-1 (by name)
    print("\n📥 Step 1: Requesting logs for 'opus-1' (7 days)...")
    result = await ai.request_client_logs("opus-1", 7)
    print(f"Request result: {result.get('success', False)}")
    
    if result.get('success'):
        command_id = result.get('command_id')
        print(f"Command ID: {command_id}")
        
        # Wait for logs to be processed
        print("\n⏳ Step 2: Waiting 15 seconds for logs to be processed...")
        await asyncio.sleep(15)
        
        # Step 3: Check what's stored in the database
        print("\n🔍 Step 3: Checking database storage...")
        conn = sqlite3.connect('hq_database.db')
        cur = conn.cursor()
        
        # Check logs table
        cur.execute('SELECT DISTINCT client_id FROM logs')
        stored_client_ids = [row[0] for row in cur.fetchall()]
        print(f"Client IDs in logs table: {stored_client_ids}")
        
        # Count logs per client_id
        for client_id in stored_client_ids:
            cur.execute('SELECT COUNT(*) FROM logs WHERE client_id = ?', (client_id,))
            count = cur.fetchone()[0]
            print(f"  {client_id}: {count} log entries")
        
        conn.close()
        
        # Step 4: Test LogQueryEngine with normalized name
        print("\n🔍 Step 4: Testing LogQueryEngine with 'opus-1'...")
        from hq.lqe import LogQueryEngine
        lqe = LogQueryEngine.from_db('hq_database.db', 'opus-1', since_days=7)
        print(f"Found {len(lqe.entries)} log entries for 'opus-1'")
        
        # Step 5: Test LogQueryEngine with hash ID
        print("\n🔍 Step 5: Testing LogQueryEngine with hash ID '8cbb62eecbb00579'...")
        lqe2 = LogQueryEngine.from_db('hq_database.db', '8cbb62eecbb00579', since_days=7)
        print(f"Found {len(lqe2.entries)} log entries for '8cbb62eecbb00579'")
        
        # Step 6: Test AI query_logs function
        print("\n🤖 Step 6: Testing AI query_logs with 'opus-1'...")
        query_result = await ai.query_logs('opus-1', 'summary', days=7)
        print(f"AI query_logs success: {query_result.get('success', False)}")
        if query_result.get('success'):
            summary = query_result.get('results', {}).get('summary', {})
            total_entries = summary.get('total_entries', 0)
            print(f"Total entries found by AI: {total_entries}")
        
        print("\n✅ Test completed!")
        
        # Summary
        print("\n📊 SUMMARY:")
        print(f"- Logs stored under client_id: {stored_client_ids}")
        print(f"- LogQueryEngine('opus-1'): {len(lqe.entries)} entries")
        print(f"- LogQueryEngine('8cbb62eecbb00579'): {len(lqe2.entries)} entries")
        print(f"- AI query_logs('opus-1'): {query_result.get('success', False)}")
        
        # Check if normalization worked
        if 'opus-1' in stored_client_ids:
            print("✅ SUCCESS: Logs are now stored with normalized client name 'opus-1'!")
        elif '8cbb62eecbb00579' in stored_client_ids:
            print("❌ ISSUE: Logs are still stored with hash ID, normalization didn't work")
        else:
            print("❓ UNKNOWN: Unexpected client_id in database")
            
    else:
        print(f"❌ Failed to request logs: {result.get('error', 'unknown error')}")

if __name__ == "__main__":
    asyncio.run(test_log_normalization())
