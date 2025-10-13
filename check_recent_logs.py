#!/usr/bin/env python3
import sqlite3
from datetime import datetime, timedelta

conn = sqlite3.connect('hq_database.db')
cur = conn.cursor()

since = (datetime.now() - timedelta(minutes=10)).isoformat()

cur.execute('''
    SELECT COUNT(*), MAX(timestamp) 
    FROM log_entries 
    WHERE client_id = 'opus-1' AND timestamp >= ?
''', (since,))

row = cur.fetchone()
print(f"Log entries in last 10 min: {row[0]}")
print(f"Latest timestamp: {row[1]}")

conn.close()

