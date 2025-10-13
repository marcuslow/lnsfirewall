#!/usr/bin/env python3
import sqlite3
import sys

command_id = sys.argv[1] if len(sys.argv) > 1 else "f1714731-103d-4614-aeb0-4e0454bb8362"

conn = sqlite3.connect('hq_database.db')
cur = conn.cursor()

cur.execute('''
    SELECT id, client_id, command_type, status, created_at, completed_at, response_data 
    FROM commands 
    WHERE id = ?
''', (command_id,))

row = cur.fetchone()

if row:
    print(f"Command ID: {row[0]}")
    print(f"Client: {row[1]}")
    print(f"Type: {row[2]}")
    print(f"Status: {row[3]}")
    print(f"Created: {row[4]}")
    print(f"Completed: {row[5]}")
    print(f"Response: {row[6][:500] if row[6] else 'None'}...")
else:
    print(f"Command {command_id} not found")

conn.close()

