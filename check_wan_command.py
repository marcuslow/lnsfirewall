#!/usr/bin/env python3
import sqlite3
import json

conn = sqlite3.connect('hq_database.db')
cur = conn.cursor()

print("=== WAN Performance Command Details ===")
cur.execute('SELECT id, client_id, command_type, status, response_data FROM commands WHERE command_type = "get_wan_performance" ORDER BY created_at DESC LIMIT 1')

for row in cur.fetchall():
    cmd_id, client_id, cmd_type, status, response_data = row
    print(f"Command ID: {cmd_id}")
    print(f"Client: {client_id}")
    print(f"Type: {cmd_type}")
    print(f"Status: {status}")
    
    if response_data:
        try:
            response = json.loads(response_data)
            print(f"Response: {json.dumps(response, indent=2)}")
        except json.JSONDecodeError:
            print(f"Raw response: {response_data}")
    else:
        print("No response data")

print("\n=== Recent Update Commands ===")
cur.execute('SELECT id, client_id, command_type, status, response_data FROM commands WHERE command_type = "update_client" ORDER BY created_at DESC LIMIT 3')

for row in cur.fetchall():
    cmd_id, client_id, cmd_type, status, response_data = row
    print(f"\nCommand ID: {cmd_id}")
    print(f"Client: {client_id}")
    print(f"Type: {cmd_type}")
    print(f"Status: {status}")
    
    if response_data:
        try:
            response = json.loads(response_data)
            print(f"Response: {json.dumps(response, indent=2)}")
        except json.JSONDecodeError:
            print(f"Raw response: {response_data}")

conn.close()
