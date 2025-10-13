#!/usr/bin/env python3
"""Debug log freshness in detail"""
import sqlite3
from datetime import datetime

def debug_freshness():
    print("=" * 80)
    print("Debugging Log Freshness - Detailed")
    print("=" * 80)
    
    conn = sqlite3.connect('hq_database.db')
    cursor = conn.cursor()
    
    # Check the logs table structure
    cursor.execute("PRAGMA table_info(logs)")
    columns = cursor.fetchall()
    print(f"\n📋 Logs table structure:")
    for col in columns:
        print(f"  {col[1]} ({col[2]})")
    
    # Check latest logs for opus-1 client
    client_id = '8cbb62eecbb00579'  # opus-1's actual ID

    cursor.execute('''
        SELECT timestamp, size_bytes, compressed
        FROM logs
        WHERE client_id = ?
        ORDER BY timestamp DESC
        LIMIT 10
    ''', (client_id,))

    recent_logs = cursor.fetchall()
    print(f"\n🔍 Recent logs for {client_id}:")
    print(f"{'Timestamp':<25} {'Size (bytes)':<12} {'Compressed':<10}")
    print("-" * 50)

    for log in recent_logs:
        timestamp, size_bytes, compressed = log
        print(f"{timestamp:<25} {size_bytes:<12} {compressed:<10}")
    
    # Check the MAX timestamp query that the freshness check uses
    cursor.execute('''
        SELECT MAX(timestamp) as last_log_time
        FROM logs
        WHERE client_id = ?
    ''', (client_id,))
    
    row = cursor.fetchone()
    if row and row[0]:
        last_log_time = row[0]
        print(f"\n⏰ MAX timestamp from freshness check: {last_log_time}")
        
        # Calculate age
        last_time = datetime.fromisoformat(last_log_time)
        age = datetime.now() - last_time
        age_hours = age.total_seconds() / 3600
        
        print(f"📅 Current time: {datetime.now().isoformat()}")
        print(f"📅 Last log time: {last_time.isoformat()}")
        print(f"⏳ Age: {age_hours:.2f} hours")
        print(f"🚦 Status: {'🟢 FRESH' if age_hours <= 6 else '🔴 STALE'} (threshold: 6 hours)")
    else:
        print(f"\n❌ No logs found for {client_id}")
    
    # Check total log count
    cursor.execute('''
        SELECT COUNT(*) as total_logs
        FROM logs
        WHERE client_id = ?
    ''', (client_id,))

    row = cursor.fetchone()
    if row:
        total_logs = row[0]
        print(f"\n📊 Total logs for {client_id}: {total_logs}")

    # Check when logs were last inserted (not the log timestamp, but when they were stored)
    cursor.execute('''
        SELECT id, timestamp, size_bytes
        FROM logs
        WHERE client_id = ?
        ORDER BY id DESC
        LIMIT 1
    ''', (client_id,))

    row = cursor.fetchone()
    if row:
        log_id, timestamp, size_bytes = row
        print(f"📥 Last inserted log: ID {log_id}, timestamp {timestamp}, size {size_bytes} bytes")
    
    conn.close()

if __name__ == "__main__":
    debug_freshness()
