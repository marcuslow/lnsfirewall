#!/usr/bin/env python3
"""Test script to verify log querying works correctly"""
import sqlite3
import sys
from datetime import datetime, timedelta

DB_PATH = 'hq_database.db'

def test_direct_query():
    """Test direct database query"""
    print("=" * 60)
    print("TEST 1: Direct Database Query")
    print("=" * 60)
    
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    
    # Check what client_ids exist
    print("\n1. Checking available client_ids...")
    cur.execute('SELECT DISTINCT client_id, COUNT(*) FROM log_entries GROUP BY client_id')
    clients = cur.fetchall()
    print(f"   Found {len(clients)} client(s):")
    for client_id, count in clients:
        print(f"   - {client_id}: {count:,} entries")
    
    if not clients:
        print("   ❌ No log entries found in database!")
        conn.close()
        return False
    
    # Use the first client for testing
    test_client = clients[0][0]
    print(f"\n2. Testing with client_id: '{test_client}'")
    
    # Get date range
    cur.execute('''
        SELECT MIN(log_timestamp), MAX(log_timestamp), COUNT(*)
        FROM log_entries
        WHERE client_id = ?
    ''', (test_client,))
    min_date, max_date, total = cur.fetchone()
    print(f"   Date range: {min_date} to {max_date}")
    print(f"   Total entries: {total:,}")
    
    # Get action breakdown
    print("\n3. Action breakdown:")
    cur.execute('''
        SELECT action, COUNT(*) 
        FROM log_entries 
        WHERE client_id = ?
        GROUP BY action
        ORDER BY COUNT(*) DESC
    ''', (test_client,))
    actions = cur.fetchall()
    for action, count in actions:
        print(f"   - {action}: {count:,}")
    
    # Get sample blocked entries
    print("\n4. Sample blocked entries:")
    cur.execute('''
        SELECT log_timestamp, source_ip, dest_ip, dest_port, protocol, action
        FROM log_entries
        WHERE client_id = ? AND action IN ('block', 'blocked', 'reject')
        LIMIT 5
    ''', (test_client,))
    blocked = cur.fetchall()
    if blocked:
        for entry in blocked:
            print(f"   {entry[0]} | {entry[1]} -> {entry[2]}:{entry[3]} | {entry[4]} | {entry[5]}")
    else:
        print("   ❌ No blocked entries found!")
    
    conn.close()
    return len(blocked) > 0


def test_lqe():
    """Test LogQueryEngine"""
    print("\n" + "=" * 60)
    print("TEST 2: LogQueryEngine")
    print("=" * 60)
    
    try:
        from hq.lqe import LogQueryEngine
        
        # Get client_id from database
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute('SELECT DISTINCT client_id FROM log_entries LIMIT 1')
        row = cur.fetchone()
        conn.close()
        
        if not row:
            print("❌ No client_id found in database")
            return False
        
        test_client = row[0]
        print(f"\n1. Loading logs for client_id: '{test_client}'")
        
        # Load with LogQueryEngine
        lqe = LogQueryEngine.from_db(DB_PATH, test_client, since_days=7, sample_rate=1)
        
        print(f"   ✅ Loaded {len(lqe.entries)} entries")
        
        if len(lqe.entries) == 0:
            print("   ❌ LogQueryEngine loaded 0 entries!")
            return False
        
        # Test filters
        print("\n2. Testing filters:")
        blocked = lqe.filter_blocked()
        allowed = lqe.filter_allowed()
        print(f"   - Blocked: {len(blocked)}")
        print(f"   - Allowed: {len(allowed)}")
        
        # Test summary
        print("\n3. Testing summary:")
        summary = lqe.summarize(top_n=5)
        print(f"   - Total entries: {summary['total_entries']}")
        print(f"   - Blocked count: {summary['blocked_count']}")
        print(f"   - Allowed count: {summary['allowed_count']}")
        print(f"   - Top blocked IPs: {summary['top_src_ips'][:3]}")
        
        # Test detection methods
        print("\n4. Testing detection methods:")
        brute_force = lqe.detect_brute_force(threshold=5)
        print(f"   - Brute force attempts: {len(brute_force)}")
        
        port_scans = lqe.detect_port_scans(threshold=10)
        print(f"   - Port scans: {len(port_scans)}")
        
        top_blocked = lqe.get_top_blocked_ips(top_n=5)
        print(f"   - Top blocked IPs: {len(top_blocked)}")
        if top_blocked:
            for ip, count in top_blocked[:3]:
                print(f"     * {ip}: {count} blocks")
        
        return summary['blocked_count'] > 0
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_ai_command_center():
    """Test AI Command Center query_logs"""
    print("\n" + "=" * 60)
    print("TEST 3: AI Command Center query_logs")
    print("=" * 60)
    
    try:
        import asyncio
        from hq.ai_command_center import AICommandCenter
        
        async def run_test():
            ai = AICommandCenter(
                hq_url="http://localhost:8000",
                openai_api_key="test-key"
            )
            
            print("\n1. Testing query_logs with 'opus-1'...")
            result = await ai.query_logs(
                client_id="opus-1",
                query="risk assessment",
                days=7,
                auto_refresh=False  # Don't fetch new logs
            )
            
            if result.get('success'):
                print("   ✅ Query succeeded!")
                results = result.get('results', {})
                print(f"   - Risk level: {results.get('risk_level', 'Unknown')}")
                print(f"   - Blocked events: {results.get('blocked_events', {}).get('count', 0)}")
                print(f"   - Brute force: {results.get('potential_brute_force', {}).get('count', 0)}")
                print(f"   - Port scans: {results.get('potential_port_scans', {}).get('count', 0)}")
                
                blocked_count = results.get('blocked_events', {}).get('count', 0)
                return blocked_count > 0
            else:
                print(f"   ❌ Query failed: {result.get('error')}")
                return False
        
        return asyncio.run(run_test())
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    print("\n🔍 Testing Log Query System\n")
    
    test1_pass = test_direct_query()
    test2_pass = test_lqe()
    test3_pass = test_ai_command_center()
    
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"Test 1 (Direct DB Query): {'✅ PASS' if test1_pass else '❌ FAIL'}")
    print(f"Test 2 (LogQueryEngine):  {'✅ PASS' if test2_pass else '❌ FAIL'}")
    print(f"Test 3 (AI Command Center): {'✅ PASS' if test3_pass else '❌ FAIL'}")
    
    if all([test1_pass, test2_pass, test3_pass]):
        print("\n🎉 All tests passed!")
        sys.exit(0)
    else:
        print("\n❌ Some tests failed!")
        sys.exit(1)

