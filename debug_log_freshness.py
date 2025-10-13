#!/usr/bin/env python3
"""Debug log freshness checking"""
import asyncio
import sqlite3
from datetime import datetime

async def check_log_freshness():
    print("=" * 80)
    print("Debugging Log Freshness")
    print("=" * 80)
    
    # Check logs table
    conn = sqlite3.connect('hq_database.db')
    cursor = conn.cursor()
    
    # Get latest log timestamp for opus-1 client
    cursor.execute('''
        SELECT client_id, MAX(timestamp) as last_log_time, COUNT(*) as log_count
        FROM logs
        GROUP BY client_id
        ORDER BY last_log_time DESC
    ''')
    
    rows = cursor.fetchall()
    
    print(f"\n📊 Log Freshness by Client:")
    print(f"{'Client ID':<20} {'Last Log Time':<25} {'Age (hours)':<12} {'Count':<10}")
    print("-" * 80)
    
    for row in rows:
        client_id, last_log_time, count = row
        if last_log_time:
            last_time = datetime.fromisoformat(last_log_time)
            age = datetime.now() - last_time
            age_hours = age.total_seconds() / 3600
            
            status = "🟢 FRESH" if age_hours <= 6 else "🔴 STALE"
            print(f"{client_id:<20} {last_log_time:<25} {age_hours:<12.1f} {count:<10} {status}")
        else:
            print(f"{client_id:<20} {'No logs':<25} {'N/A':<12} {count:<10} ❌ EMPTY")
    
    # Check specific client (opus-1 or its actual ID)
    print(f"\n🔍 Detailed check for opus-1:")
    cursor.execute('''
        SELECT client_id, timestamp, action, src, dst_port
        FROM logs
        WHERE client_id LIKE '%opus%' OR client_id = '8cbb62eecbb00579'
        ORDER BY timestamp DESC
        LIMIT 5
    ''')
    
    recent_logs = cursor.fetchall()
    if recent_logs:
        print(f"Recent logs:")
        for log in recent_logs:
            print(f"  {log[0]} | {log[1]} | {log[2]} | {log[3]} | {log[4]}")
    else:
        print("No logs found for opus-1")
    
    conn.close()

if __name__ == "__main__":
    asyncio.run(check_log_freshness())
