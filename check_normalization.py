#!/usr/bin/env python3

import sqlite3

conn = sqlite3.connect('hq_database.db')
cur = conn.cursor()

print("🔍 Checking client name normalization...")

# Check logs table
cur.execute('SELECT DISTINCT client_id FROM logs')
stored_client_ids = [row[0] for row in cur.fetchall()]
print(f'Client IDs in logs table: {stored_client_ids}')

for client_id in stored_client_ids:
    cur.execute('SELECT COUNT(*) FROM logs WHERE client_id = ?', (client_id,))
    count = cur.fetchone()[0]
    print(f'  {client_id}: {count} log entries')

# Check rulesets table
cur.execute('SELECT DISTINCT client_id FROM rulesets')
ruleset_client_ids = [row[0] for row in cur.fetchall()]
print(f'Client IDs in rulesets table: {ruleset_client_ids}')

for client_id in ruleset_client_ids:
    cur.execute('SELECT COUNT(*) FROM rulesets WHERE client_id = ?', (client_id,))
    count = cur.fetchone()[0]
    print(f'  {client_id}: {count} rulesets')

conn.close()

# Test LogQueryEngine
print("\n🧪 Testing LogQueryEngine...")
from hq.lqe import LogQueryEngine

lqe1 = LogQueryEngine.from_db('hq_database.db', 'opus-1', since_days=7)
print(f"LogQueryEngine('opus-1'): {len(lqe1.entries)} entries")

lqe2 = LogQueryEngine.from_db('hq_database.db', '8cbb62eecbb00579', since_days=7)
print(f"LogQueryEngine('8cbb62eecbb00579'): {len(lqe2.entries)} entries")

print("\n✅ Normalization check complete!")
if 'opus-1' in stored_client_ids:
    print("✅ SUCCESS: Logs are stored with normalized client name 'opus-1'!")
else:
    print("❌ ISSUE: Logs are not stored with normalized client name")
