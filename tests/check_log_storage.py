#!/usr/bin/env python3

import sqlite3
import json

conn = sqlite3.connect('hq_database.db')
cur = conn.cursor()

print("📊 Log storage analysis:")
cur.execute('SELECT client_id, size_bytes, LENGTH(log_data) as data_length FROM logs WHERE client_id = "opus-1"')
rows = cur.fetchall()

for client_id, size_bytes, data_length in rows:
    print(f'  Client: {client_id}, Size: {size_bytes:,} bytes, Data length: {data_length:,} chars')

# Check the first log entry structure
cur.execute('SELECT log_data FROM logs WHERE client_id = "opus-1" LIMIT 1')
row = cur.fetchone()
if row:
    log_data = row[0]
    try:
        parsed = json.loads(log_data)
        if isinstance(parsed, list):
            print(f'  📝 Log contains {len(parsed):,} individual log entries')
            if len(parsed) > 0:
                print(f'  📄 Sample entry keys: {list(parsed[0].keys())}')
        else:
            print(f'  📝 Log is not a list, type: {type(parsed)}')
    except Exception as e:
        print(f'  ❌ Failed to parse log data: {e}')

conn.close()

print("\n🔍 The issue: Each database row contains a massive JSON array!")
print("💡 Solution: We need to either:")
print("   1. Store individual log entries as separate rows")
print("   2. Add pagination/chunking to the JSON parsing")
print("   3. Add sampling for analysis (take every Nth entry)")
