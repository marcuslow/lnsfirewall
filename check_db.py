#!/usr/bin/env python3
import sqlite3

conn = sqlite3.connect('hq_database.db')
cur = conn.cursor()

print("=== Recent Commands ===")
cur.execute('SELECT id, client_id, command_type, status, created_at FROM commands ORDER BY created_at DESC LIMIT 5')
for row in cur.fetchall():
    print(row)

print("\n=== Recent Logs ===")
cur.execute('SELECT client_id, timestamp, size_bytes, compressed FROM logs ORDER BY timestamp DESC LIMIT 5')
for row in cur.fetchall():
    print(row)

print("\n=== Clients ===")
cur.execute('SELECT client_id, client_name, last_seen FROM clients')
for row in cur.fetchall():
    print(row)

conn.close()
