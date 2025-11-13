#!/usr/bin/env python3
import sqlite3

conn = sqlite3.connect('hq_database.db')
cur = conn.cursor()

print("Checking log_entries data...\n")

# Get sample entries
cur.execute("""
    SELECT log_timestamp, source, log_type, action, protocol, 
           source_ip, dest_ip, dest_port, raw_message
    FROM log_entries 
    WHERE client_id = 'opus-1' 
    LIMIT 5
""")

rows = cur.fetchall()

for i, row in enumerate(rows, 1):
    print(f"Entry {i}:")
    print(f"  log_timestamp: {row[0]}")
    print(f"  source: {row[1]}")
    print(f"  log_type: {row[2]}")
    print(f"  action: {row[3]}")
    print(f"  protocol: {row[4]}")
    print(f"  source_ip: {row[5]}")
    print(f"  dest_ip: {row[6]}")
    print(f"  dest_port: {row[7]}")
    print(f"  raw_message: {row[8][:100] if row[8] else 'None'}...")
    print()

# Check if there are any entries with actual data
cur.execute("""
    SELECT COUNT(*) FROM log_entries 
    WHERE client_id = 'opus-1' AND action IS NOT NULL
""")
print(f"Entries with action field: {cur.fetchone()[0]}")

cur.execute("""
    SELECT COUNT(*) FROM log_entries 
    WHERE client_id = 'opus-1' AND source_ip IS NOT NULL
""")
print(f"Entries with source_ip field: {cur.fetchone()[0]}")

# Check the old logs table to see the original format
print("\n\nChecking old logs table format...\n")
cur.execute("""
    SELECT log_data FROM logs 
    WHERE client_id = 'opus-1' 
    LIMIT 1
""")
row = cur.fetchone()
if row:
    import json
    logs = json.loads(row[0])
    if logs and len(logs) > 0:
        print("Sample log entry from old format:")
        print(json.dumps(logs[0], indent=2))

conn.close()

