#!/usr/bin/env python3
"""Check raw logs in database"""
import sqlite3
import json
import gzip
import base64

def check_raw_logs():
    print("=" * 80)
    print("Checking Raw Logs in Database")
    print("=" * 80)
    
    conn = sqlite3.connect('hq_database.db')
    cursor = conn.cursor()
    
    # Check if there are ANY logs at all
    cursor.execute('SELECT COUNT(*) FROM logs')
    total_logs = cursor.fetchone()[0]
    print(f"📊 Total logs in database: {total_logs}")
    
    if total_logs == 0:
        print("❌ NO LOGS FOUND - This confirms the storage issue")
        
        # Let's check if the logs table exists and has the right schema
        cursor.execute("PRAGMA table_info(logs)")
        columns = cursor.fetchall()
        print(f"\n📋 Logs table schema:")
        for col in columns:
            print(f"  {col[1]} ({col[2]})")
        
        # Check if there are any recent INSERT attempts by looking at the database file size
        import os
        db_size = os.path.getsize('hq_database.db')
        print(f"\n💾 Database file size: {db_size:,} bytes")
        
        conn.close()
        return
    
    # If there are logs, examine them
    cursor.execute('''
        SELECT id, client_id, timestamp, compressed, size_bytes, 
               LENGTH(log_data) as data_length
        FROM logs
        ORDER BY timestamp DESC
        LIMIT 5
    ''')
    
    rows = cursor.fetchall()
    print(f"\n📋 Recent logs:")
    print(f"{'ID':<5} {'Client':<25} {'Timestamp':<20} {'Compressed':<10} {'Size':<10} {'Data Len':<10}")
    print("-" * 90)
    
    for row in rows:
        log_id, client_id, timestamp, compressed, size_bytes, data_length = row
        print(f"{log_id:<5} {client_id:<25} {timestamp:<20} {compressed:<10} {size_bytes:<10} {data_length:<10}")
    
    # Try to decode one log entry
    if rows:
        cursor.execute('SELECT log_data, compressed FROM logs ORDER BY timestamp DESC LIMIT 1')
        log_data, compressed = cursor.fetchone()
        
        print(f"\n🔍 Examining latest log entry:")
        print(f"   Compressed: {compressed}")
        print(f"   Raw data length: {len(log_data)}")
        
        try:
            if compressed:
                # Try to decompress
                decoded_data = base64.b64decode(log_data)
                decompressed_data = gzip.decompress(decoded_data)
                parsed_logs = json.loads(decompressed_data.decode('utf-8'))
            else:
                parsed_logs = json.loads(log_data)
            
            print(f"   ✅ Successfully parsed logs")
            print(f"   Type: {type(parsed_logs)}")
            if isinstance(parsed_logs, list):
                print(f"   Count: {len(parsed_logs)}")
                if parsed_logs:
                    print(f"   Sample entry: {str(parsed_logs[0])[:100]}...")
            elif isinstance(parsed_logs, dict):
                print(f"   Keys: {list(parsed_logs.keys())}")
                
        except Exception as e:
            print(f"   ❌ Failed to parse logs: {e}")
    
    conn.close()

if __name__ == "__main__":
    check_raw_logs()
