#!/usr/bin/env python3
"""
Test script for raw log parsing refactor.
Verifies that client sends raw logs and server parses them correctly.
"""
import asyncio
import aiohttp
import sqlite3
from datetime import datetime

HQ_URL = "http://localhost:8000"

async def test_raw_log_collection():
    """Test requesting logs from client and verify server-side parsing"""
    
    print("=" * 60)
    print("🧪 Testing Raw Log Collection & Server-Side Parsing")
    print("=" * 60)
    
    async with aiohttp.ClientSession() as session:
        # Step 1: Get connected clients
        print("\n📋 Step 1: Getting connected clients...")
        async with session.get(f"{HQ_URL}/clients") as resp:
            if resp.status == 200:
                data = await resp.json()
                clients = data.get('clients', {})
                if not clients:
                    print("❌ No clients connected!")
                    return False
                
                # Get first client
                client_id = list(clients.keys())[0]
                client_name = clients[client_id].get('client_name', 'unknown')
                print(f"✅ Found client: {client_name} ({client_id[:8]}...)")
            else:
                print(f"❌ Failed to get clients: {resp.status}")
                return False
        
        # Step 2: Request logs
        print("\n📋 Step 2: Requesting logs from client...")
        async with session.post(f"{HQ_URL}/command", json={
            "client_id": client_id,
            "command_type": "get_logs",
            "params": {"days": 1}
        }) as resp:
            if resp.status == 200:
                result = await resp.json()
                command_id = result.get("command_id")
                print(f"✅ Command queued: {command_id}")
                
                # Wait for completion
                print("\n⏳ Waiting for logs to be collected and parsed...")
                for i in range(60):  # 2 minutes max
                    await asyncio.sleep(2)
                    async with session.get(f"{HQ_URL}/command/{command_id}") as check_resp:
                        if check_resp.status == 200:
                            status_data = await check_resp.json()
                            status = status_data.get("status")
                            
                            if status == "completed":
                                print(f"✅ Logs collected and parsed successfully!")
                                break
                            elif status == "failed":
                                print(f"❌ Log collection failed: {status_data.get('progress')}")
                                return False
                            elif status == "in_progress":
                                progress = status_data.get('progress', {})
                                stage = progress.get('stage', 'unknown')
                                pct = progress.get('progress_pct', 0)
                                print(f"   Progress: {stage} - {pct}%")
                        else:
                            print(f"   Waiting... ({i+1}/60)")
                else:
                    print("⏰ Timeout waiting for logs")
                    return False
            else:
                print(f"❌ Failed to queue command: {resp.status}")
                return False
        
        # Step 3: Verify database storage
        print("\n📋 Step 3: Verifying database storage...")
        conn = sqlite3.connect('hq_database.db')
        cur = conn.cursor()
        
        # Get client name (normalized)
        normalized_client_name = client_name.lower()
        
        # Check log_entries table
        cur.execute('''
            SELECT COUNT(*), 
                   COUNT(CASE WHEN log_type = 'filter' THEN 1 END) as filter_count,
                   COUNT(CASE WHEN log_type = 'pfblockerng' THEN 1 END) as pfblocker_count,
                   COUNT(CASE WHEN log_type = 'unparsed' THEN 1 END) as unparsed_count,
                   COUNT(CASE WHEN action = 'block' THEN 1 END) as blocked_count
            FROM log_entries 
            WHERE client_id = ?
        ''', (normalized_client_name,))
        
        row = cur.fetchone()
        total, filter_count, pfblocker_count, unparsed_count, blocked_count = row
        
        print(f"\n📊 Database Results:")
        print(f"   Total entries: {total:,}")
        print(f"   Filter logs: {filter_count:,}")
        print(f"   pfBlockerNG logs: {pfblocker_count:,}")
        print(f"   Unparsed: {unparsed_count:,}")
        print(f"   Blocked actions: {blocked_count:,}")
        
        # Calculate parsing success rate
        if total > 0:
            parsed = filter_count + pfblocker_count
            success_rate = (parsed / total) * 100
            print(f"\n✅ Parsing success rate: {success_rate:.1f}%")
            
            if success_rate < 90:
                print(f"⚠️  Warning: Low parsing success rate!")
        
        # Show sample entries
        print(f"\n📝 Sample Entries:")
        cur.execute('''
            SELECT id, log_type, action, source_ip, dest_ip, dest_port, protocol
            FROM log_entries 
            WHERE client_id = ?
            ORDER BY id DESC
            LIMIT 5
        ''', (normalized_client_name,))
        
        for row in cur.fetchall():
            entry_id, log_type, action, src_ip, dst_ip, dst_port, protocol = row
            print(f"   ID {entry_id}: {log_type:12} {action or 'N/A':6} {src_ip or 'N/A':15} -> {dst_ip or 'N/A':15}:{dst_port or 'N/A'} ({protocol or 'N/A'})")
        
        # Check protocol distribution
        print(f"\n📊 Protocol Distribution:")
        cur.execute('''
            SELECT protocol, COUNT(*) as count
            FROM log_entries 
            WHERE client_id = ? AND protocol IS NOT NULL
            GROUP BY protocol
            ORDER BY count DESC
            LIMIT 10
        ''', (normalized_client_name,))
        
        for protocol, count in cur.fetchall():
            print(f"   {protocol:10}: {count:,}")
        
        conn.close()
        
        print("\n" + "=" * 60)
        print("✅ Test Complete!")
        print("=" * 60)
        
        return True

if __name__ == "__main__":
    asyncio.run(test_raw_log_collection())

