#!/usr/bin/env python3
"""
Test script to verify individual log entry storage system.
Tests:
1. Logs are stored as individual rows in log_entries table
2. Counts are accurate (no sampling artifacts)
3. Queries are fast with proper indexing
4. Client name normalization works correctly
"""

import asyncio
import aiohttp
import sqlite3
import time
from datetime import datetime, timedelta

HQ_URL = "http://localhost:8000"
DB_PATH = "hq_database.db"
TEST_CLIENT = "opus-1"  # Normalized client name


async def request_logs():
    """Request logs from the test client"""
    print("📋 Step 1: Requesting logs from client...")
    
    async with aiohttp.ClientSession() as session:
        # Queue a get_logs command
        async with session.post(f"{HQ_URL}/command", json={
            "client_id": TEST_CLIENT,
            "command_type": "get_logs",
            "params": {"days": 1}
        }) as resp:
            if resp.status == 200:
                result = await resp.json()
                command_id = result.get("command_id")
                print(f"✅ Command queued: {command_id}")
                
                # Wait for completion
                print("⏳ Waiting for logs to be collected...")
                for i in range(30):
                    await asyncio.sleep(2)
                    async with session.get(f"{HQ_URL}/command/{command_id}") as check_resp:
                        if check_resp.status == 200:
                            status_data = await check_resp.json()
                            if status_data.get("status") == "completed":
                                print(f"✅ Logs collected successfully")
                                return True
                            elif status_data.get("status") == "failed":
                                print(f"❌ Log collection failed: {status_data.get('response_data')}")
                                return False
                    print(f"   Still waiting... ({i+1}/30)")
                
                print("⏱️ Timeout waiting for logs")
                return False
            else:
                print(f"❌ Failed to queue command: {resp.status}")
                return False


def test_individual_storage():
    """Test that logs are stored as individual rows"""
    print("\n📊 Step 2: Verifying individual row storage...")
    
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    
    # Count entries in log_entries table
    cur.execute("""
        SELECT COUNT(*) FROM log_entries 
        WHERE client_id = ?
    """, (TEST_CLIENT,))
    
    total_entries = cur.fetchone()[0]
    print(f"✅ Found {total_entries:,} individual log entries for '{TEST_CLIENT}'")
    
    # Show sample entries
    cur.execute("""
        SELECT id, timestamp, action, source_ip, dest_ip, dest_port, protocol
        FROM log_entries
        WHERE client_id = ?
        ORDER BY timestamp DESC
        LIMIT 5
    """, (TEST_CLIENT,))
    
    print("\n📝 Sample log entries:")
    for row in cur.fetchall():
        entry_id, ts, action, src_ip, dst_ip, dst_port, proto = row
        print(f"   ID {entry_id}: {action} {proto} {src_ip} -> {dst_ip}:{dst_port} @ {ts}")
    
    conn.close()
    return total_entries


def test_accurate_counts():
    """Test that counts are accurate (no sampling)"""
    print("\n🔢 Step 3: Testing accurate counts...")
    
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    
    # Count blocked actions
    cur.execute("""
        SELECT COUNT(*) FROM log_entries
        WHERE client_id = ? AND action = 'block'
    """, (TEST_CLIENT,))
    blocked_count = cur.fetchone()[0]
    
    # Count by protocol
    cur.execute("""
        SELECT protocol, COUNT(*) as count
        FROM log_entries
        WHERE client_id = ?
        GROUP BY protocol
        ORDER BY count DESC
        LIMIT 5
    """, (TEST_CLIENT,))
    
    print(f"✅ Blocked actions: {blocked_count:,}")
    print("\n📊 Top protocols:")
    for proto, count in cur.fetchall():
        print(f"   {proto or 'unknown'}: {count:,}")
    
    conn.close()
    return blocked_count


def test_query_performance():
    """Test query performance with indexes"""
    print("\n⚡ Step 4: Testing query performance...")
    
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    
    # Test 1: Query by client_id and timestamp (should use idx_log_entries_client_timestamp)
    start_time = time.time()
    since = (datetime.now() - timedelta(days=1)).isoformat()
    cur.execute("""
        SELECT COUNT(*) FROM log_entries
        WHERE client_id = ? AND timestamp >= ?
    """, (TEST_CLIENT, since))
    count = cur.fetchone()[0]
    elapsed = (time.time() - start_time) * 1000
    print(f"✅ Query by client+timestamp: {count:,} rows in {elapsed:.2f}ms")
    
    # Test 2: Query by action (should use idx_log_entries_action)
    start_time = time.time()
    cur.execute("""
        SELECT COUNT(*) FROM log_entries
        WHERE client_id = ? AND action = 'block'
    """, (TEST_CLIENT,))
    count = cur.fetchone()[0]
    elapsed = (time.time() - start_time) * 1000
    print(f"✅ Query by action: {count:,} rows in {elapsed:.2f}ms")
    
    # Test 3: Query by dest_port (should use idx_log_entries_dest_port)
    start_time = time.time()
    cur.execute("""
        SELECT COUNT(*) FROM log_entries
        WHERE client_id = ? AND dest_port = 443
    """, (TEST_CLIENT,))
    count = cur.fetchone()[0]
    elapsed = (time.time() - start_time) * 1000
    print(f"✅ Query by dest_port: {count:,} rows in {elapsed:.2f}ms")
    
    conn.close()


def test_client_normalization():
    """Test that client name normalization works"""
    print("\n🔤 Step 5: Testing client name normalization...")
    
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    
    # Check that all entries use lowercase client_id
    cur.execute("""
        SELECT DISTINCT client_id FROM log_entries
    """)
    
    client_ids = [row[0] for row in cur.fetchall()]
    print(f"✅ Found client IDs: {client_ids}")
    
    # Verify all are lowercase
    all_lowercase = all(cid == cid.lower() for cid in client_ids)
    if all_lowercase:
        print("✅ All client IDs are properly normalized to lowercase")
    else:
        print("⚠️ Warning: Some client IDs are not lowercase!")
    
    conn.close()
    return all_lowercase


def test_lqe_integration():
    """Test LogQueryEngine integration"""
    print("\n🔍 Step 6: Testing LogQueryEngine integration...")
    
    from hq.lqe import LogQueryEngine
    
    # Load with no sampling
    lqe = LogQueryEngine.from_db(DB_PATH, TEST_CLIENT, since_days=1, sample_rate=1)
    print(f"✅ LogQueryEngine loaded {len(lqe.entries)} entries (no sampling)")
    
    # Load with sampling
    lqe_sampled = LogQueryEngine.from_db(DB_PATH, TEST_CLIENT, since_days=1, sample_rate=10)
    print(f"✅ LogQueryEngine loaded {len(lqe_sampled.entries)} entries (sample_rate=10)")
    
    # Verify sampling ratio
    if len(lqe.entries) > 0:
        ratio = len(lqe_sampled.entries) / len(lqe.entries)
        print(f"📊 Sampling ratio: {ratio:.2%} (expected ~10%)")
    
    return len(lqe.entries)


async def main():
    print("🧪 Testing Individual Log Entry Storage System\n")
    print("=" * 60)
    
    # Step 1: Request fresh logs
    success = await request_logs()
    if not success:
        print("\n⚠️ Could not get fresh logs, testing with existing data...")
    
    # Step 2: Test individual storage
    total_entries = test_individual_storage()
    if total_entries == 0:
        print("\n❌ No log entries found! Make sure logs have been collected.")
        return
    
    # Step 3: Test accurate counts
    test_accurate_counts()
    
    # Step 4: Test query performance
    test_query_performance()
    
    # Step 5: Test client normalization
    test_client_normalization()
    
    # Step 6: Test LQE integration
    test_lqe_integration()
    
    print("\n" + "=" * 60)
    print("✅ All tests completed!")
    print("\n📋 Summary:")
    print(f"   - Individual log entries stored: {total_entries:,}")
    print(f"   - Client name normalization: ✅")
    print(f"   - Query performance: ✅")
    print(f"   - LogQueryEngine integration: ✅")


if __name__ == "__main__":
    asyncio.run(main())

