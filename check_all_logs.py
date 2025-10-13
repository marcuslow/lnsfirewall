#!/usr/bin/env python3
"""Check all logs in database"""
import sqlite3
from datetime import datetime

def check_all_logs():
    print("=" * 80)
    print("Checking All Logs in Database")
    print("=" * 80)
    
    conn = sqlite3.connect('hq_database.db')
    cursor = conn.cursor()
    
    # Check all client IDs with logs
    cursor.execute('''
        SELECT client_id, COUNT(*) as log_count, MIN(timestamp) as first_log, MAX(timestamp) as last_log
        FROM logs
        GROUP BY client_id
        ORDER BY log_count DESC
    ''')
    
    rows = cursor.fetchall()
    
    if not rows:
        print("❌ NO LOGS FOUND IN DATABASE")
        return
    
    print(f"\n📊 Logs by Client:")
    print(f"{'Client ID':<25} {'Count':<8} {'First Log':<20} {'Last Log':<20} {'Age (hours)':<12}")
    print("-" * 90)
    
    for row in rows:
        client_id, count, first_log, last_log = row
        if last_log:
            last_time = datetime.fromisoformat(last_log)
            age = datetime.now() - last_time
            age_hours = age.total_seconds() / 3600
            status = "🟢 FRESH" if age_hours <= 6 else "🔴 STALE"
        else:
            age_hours = "N/A"
            status = "❌ NO LOGS"
        
        print(f"{client_id:<25} {count:<8} {first_log or 'N/A':<20} {last_log or 'N/A':<20} {age_hours:<12} {status}")
    
    # Check clients table to see registered clients
    print(f"\n📋 Registered Clients:")
    cursor.execute('SELECT client_id, client_name, last_seen FROM clients ORDER BY last_seen DESC')
    client_rows = cursor.fetchall()
    
    if client_rows:
        print(f"{'Client ID':<25} {'Name':<15} {'Last Seen':<20}")
        print("-" * 65)
        for client_row in client_rows:
            client_id, client_name, last_seen = client_row
            print(f"{client_id:<25} {client_name or 'N/A':<15} {last_seen or 'N/A':<20}")
    else:
        print("❌ NO CLIENTS REGISTERED")
    
    conn.close()

if __name__ == "__main__":
    check_all_logs()
