#!/usr/bin/env python3
"""
Isolated test for log storage and 6-hour freshness rule
Tests each component separately to identify the exact issue
"""
import asyncio
import sqlite3
import json
import gzip
import base64
import sys
import os
from datetime import datetime, timedelta

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Test configuration
DB_PATH = 'hq_database.db'
TEST_CLIENT_ID = '8cbb62eecbb00579'  # opus-1
HQ_URL = "http://localhost:8000"

def test_1_database_connection():
    """Test 1: Verify database connection and schema"""
    print("=" * 60)
    print("TEST 1: Database Connection & Schema")
    print("=" * 60)
    
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Check if logs table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='logs'")
        table_exists = cursor.fetchone() is not None
        print(f"✅ Logs table exists: {table_exists}")
        
        if table_exists:
            # Check schema
            cursor.execute("PRAGMA table_info(logs)")
            columns = cursor.fetchall()
            print(f"✅ Table schema: {[col[1] for col in columns]}")
            
            # Check current log count
            cursor.execute("SELECT COUNT(*) FROM logs WHERE client_id = ?", (TEST_CLIENT_ID,))
            count = cursor.fetchone()[0]
            print(f"📊 Current logs for {TEST_CLIENT_ID}: {count}")
        
        conn.close()
        return True
    except Exception as e:
        print(f"❌ Database test failed: {e}")
        return False

def test_2_manual_log_insertion():
    """Test 2: Manually insert a log entry to verify INSERT works"""
    print("\n" + "=" * 60)
    print("TEST 2: Manual Log Insertion")
    print("=" * 60)
    
    try:
        # Create sample log data
        sample_logs = [
            {"timestamp": "2025-10-01T16:00:00", "action": "block", "src": "1.2.3.4", "dst_port": 80},
            {"timestamp": "2025-10-01T16:00:01", "action": "block", "src": "5.6.7.8", "dst_port": 443}
        ]
        logs_json = json.dumps(sample_logs)
        
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Insert test log
        cursor.execute('''
            INSERT INTO logs (client_id, timestamp, log_data, compressed, size_bytes)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            TEST_CLIENT_ID,
            datetime.now(),
            logs_json,
            False,
            len(logs_json)
        ))
        conn.commit()
        
        # Verify insertion
        cursor.execute("SELECT COUNT(*) FROM logs WHERE client_id = ?", (TEST_CLIENT_ID,))
        count = cursor.fetchone()[0]
        print(f"✅ Manual insertion successful. Total logs: {count}")
        
        # Get the inserted log
        cursor.execute('''
            SELECT id, timestamp, size_bytes, LENGTH(log_data) as data_len
            FROM logs 
            WHERE client_id = ? 
            ORDER BY timestamp DESC 
            LIMIT 1
        ''', (TEST_CLIENT_ID,))
        
        row = cursor.fetchone()
        if row:
            log_id, timestamp, size_bytes, data_len = row
            print(f"✅ Latest log: ID={log_id}, timestamp={timestamp}, size={size_bytes}, data_len={data_len}")
        
        conn.close()
        return True
    except Exception as e:
        print(f"❌ Manual insertion failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_3_freshness_check():
    """Test 3: Test the 6-hour freshness check logic"""
    print("\n" + "=" * 60)
    print("TEST 3: 6-Hour Freshness Check")
    print("=" * 60)
    
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Check current freshness
        cursor.execute('''
            SELECT MAX(timestamp) as last_log_time
            FROM logs
            WHERE client_id = ?
        ''', (TEST_CLIENT_ID,))
        
        row = cursor.fetchone()
        if not row or not row[0]:
            print("❌ No logs found - freshness check should trigger download")
            conn.close()
            return False
        
        last_log_time = datetime.fromisoformat(row[0])
        age = datetime.now() - last_log_time
        age_hours = age.total_seconds() / 3600
        
        print(f"📅 Current time: {datetime.now().isoformat()}")
        print(f"📅 Last log time: {last_log_time.isoformat()}")
        print(f"⏳ Age: {age_hours:.2f} hours")
        
        is_fresh = age_hours <= 6
        print(f"🚦 Status: {'🟢 FRESH' if is_fresh else '🔴 STALE'} (threshold: 6 hours)")
        
        # Test with artificially old timestamp
        old_time = datetime.now() - timedelta(hours=8)
        cursor.execute('''
            UPDATE logs 
            SET timestamp = ? 
            WHERE client_id = ? 
            ORDER BY timestamp DESC 
            LIMIT 1
        ''', (old_time, TEST_CLIENT_ID))
        conn.commit()
        
        # Re-check freshness
        cursor.execute('''
            SELECT MAX(timestamp) as last_log_time
            FROM logs
            WHERE client_id = ?
        ''', (TEST_CLIENT_ID,))
        
        row = cursor.fetchone()
        last_log_time = datetime.fromisoformat(row[0])
        age = datetime.now() - last_log_time
        age_hours = age.total_seconds() / 3600
        
        print(f"\n🧪 After setting old timestamp:")
        print(f"📅 Last log time: {last_log_time.isoformat()}")
        print(f"⏳ Age: {age_hours:.2f} hours")
        print(f"🚦 Status: {'🟢 FRESH' if age_hours <= 6 else '🔴 STALE'} (should be STALE)")
        
        conn.close()
        return age_hours > 6  # Should be stale
    except Exception as e:
        print(f"❌ Freshness check failed: {e}")
        import traceback
        traceback.print_exc()
        return False

async def test_4_ai_command_center_freshness():
    """Test 4: Test AICommandCenter's _ensure_fresh_logs method"""
    print("\n" + "=" * 60)
    print("TEST 4: AICommandCenter Freshness Check")
    print("=" * 60)
    
    try:
        from hq.ai_command_center import AICommandCenter
        
        ai_center = AICommandCenter(
            hq_url=HQ_URL,
            openai_api_key="test-key"
        )
        
        # Test freshness check
        print("🔍 Testing _ensure_fresh_logs method...")
        freshness = await ai_center._ensure_fresh_logs(TEST_CLIENT_ID, max_age_hours=6)
        
        print(f"📊 Freshness result: {freshness}")
        print(f"   Fresh: {freshness.get('fresh')}")
        print(f"   Age hours: {freshness.get('age_hours')}")
        print(f"   Refreshed: {freshness.get('refreshed')}")
        
        if freshness.get('error'):
            print(f"   Error: {freshness.get('error')}")
        
        return True
    except Exception as e:
        print(f"❌ AICommandCenter freshness test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_5_decompression():
    """Test 5: Test log decompression from actual server response"""
    print("\n" + "=" * 60)
    print("TEST 5: Log Decompression Test")
    print("=" * 60)
    
    try:
        # Get actual compressed log data from commands table
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT response_data
            FROM commands
            WHERE command_type = 'get_logs' AND status = 'completed'
            ORDER BY created_at DESC
            LIMIT 1
        ''')
        
        row = cursor.fetchone()
        if not row or not row[0]:
            print("❌ No completed get_logs commands found")
            return False
        
        response_data = json.loads(row[0])
        logs_data = response_data.get('logs')
        is_compressed = response_data.get('compressed', False)
        
        print(f"📊 Found logs data: type={type(logs_data)}, compressed={is_compressed}")
        print(f"   Data length: {len(logs_data) if isinstance(logs_data, str) else 'N/A'}")
        
        if is_compressed and isinstance(logs_data, str):
            print("🔄 Testing decompression...")
            
            # Test decompression
            decoded_data = base64.b64decode(logs_data)
            decompressed_data = gzip.decompress(decoded_data)
            logs_json = decompressed_data.decode('utf-8')
            
            print(f"✅ Decompression successful: {len(logs_json):,} chars")
            
            # Parse JSON
            parsed_logs = json.loads(logs_json)
            print(f"✅ JSON parsing successful: {len(parsed_logs)} log entries")
            
            if parsed_logs:
                sample = parsed_logs[0]
                print(f"   Sample entry: {sample}")
        
        conn.close()
        return True
    except Exception as e:
        print(f"❌ Decompression test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def cleanup_test_data():
    """Clean up test data"""
    print("\n" + "=" * 60)
    print("CLEANUP: Removing test data")
    print("=" * 60)
    
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute("DELETE FROM logs WHERE client_id = ?", (TEST_CLIENT_ID,))
        deleted = cursor.rowcount
        conn.commit()
        conn.close()
        
        print(f"✅ Cleaned up {deleted} test log entries")
    except Exception as e:
        print(f"❌ Cleanup failed: {e}")

async def main():
    """Run all tests"""
    print("🧪 LOG STORAGE & FRESHNESS ISOLATED TESTS")
    print("=" * 80)
    
    results = []
    
    # Run tests
    results.append(("Database Connection", test_1_database_connection()))
    results.append(("Manual Log Insertion", test_2_manual_log_insertion()))
    results.append(("Freshness Check Logic", test_3_freshness_check()))
    results.append(("AICommandCenter Freshness", await test_4_ai_command_center_freshness()))
    results.append(("Log Decompression", test_5_decompression()))
    
    # Summary
    print("\n" + "=" * 80)
    print("TEST RESULTS SUMMARY")
    print("=" * 80)
    
    passed = 0
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{test_name:<30} {status}")
        if result:
            passed += 1
    
    print(f"\nOverall: {passed}/{len(results)} tests passed")
    
    # Cleanup
    cleanup_test_data()

if __name__ == "__main__":
    asyncio.run(main())
