#!/usr/bin/env python3
"""Check when logs were last downloaded for opus-1"""
import sqlite3
from datetime import datetime

conn = sqlite3.connect('hq_database.db')
cur = conn.cursor()

print("=" * 60)
print("Last Log Download for opus-1")
print("=" * 60)

# Check commands table for get_logs commands
print("\n1. Last get_logs commands:")
cur.execute('''
    SELECT id, client_id, command_type, status, created_at, completed_at
    FROM commands
    WHERE command_type = 'get_logs'
    ORDER BY created_at DESC
    LIMIT 10
''')

for row in cur.fetchall():
    cmd_id, client_id, cmd_type, status, created, completed = row
    print(f"   {created} | {client_id[:16]} | {status:12} | {cmd_id[:8]}...")
    if completed:
        print(f"      Completed: {completed}")

# Check log_entries table for most recent entries
print("\n2. Most recent log entries in database:")
cur.execute('''
    SELECT client_id, MIN(timestamp) as first_insert, MAX(timestamp) as last_insert, COUNT(*) as total
    FROM log_entries
    GROUP BY client_id
''')

for row in cur.fetchall():
    client_id, first, last, total = row
    print(f"   {client_id}:")
    print(f"      First inserted: {first}")
    print(f"      Last inserted:  {last}")
    print(f"      Total entries:  {total:,}")

# Check the actual log timestamps (when events occurred, not when inserted)
print("\n3. Log event date range (actual firewall events):")
cur.execute('''
    SELECT client_id, MIN(log_timestamp) as oldest_event, MAX(log_timestamp) as newest_event
    FROM log_entries
    WHERE client_id = 'opus-1'
    GROUP BY client_id
''')

row = cur.fetchone()
if row:
    client_id, oldest, newest = row
    print(f"   {client_id}:")
    print(f"      Oldest event: {oldest}")
    print(f"      Newest event: {newest}")
    
    # Calculate age
    if newest:
        try:
            newest_dt = datetime.fromisoformat(newest.replace('Z', '+00:00'))
            now = datetime.now(newest_dt.tzinfo) if newest_dt.tzinfo else datetime.now()
            age = now - newest_dt
            hours = age.total_seconds() / 3600
            print(f"      Age: {hours:.1f} hours ({age.days} days)")
        except:
            pass

conn.close()

