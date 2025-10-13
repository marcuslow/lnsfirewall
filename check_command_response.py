#!/usr/bin/env python3
import sqlite3
import json

conn = sqlite3.connect('hq_database.db')
cur = conn.cursor()

print("=== Recent Command Responses ===")
cur.execute('SELECT id, client_id, command_type, status, response_data FROM commands WHERE command_type = "get_logs" ORDER BY created_at DESC LIMIT 3')

for row in cur.fetchall():
    cmd_id, client_id, cmd_type, status, response_data = row
    print(f"\nCommand ID: {cmd_id}")
    print(f"Client: {client_id}")
    print(f"Type: {cmd_type}")
    print(f"Status: {status}")
    
    if response_data:
        try:
            response = json.loads(response_data)
            print(f"Response keys: {list(response.keys()) if isinstance(response, dict) else 'Not a dict'}")
            
            if isinstance(response, dict):
                if 'logs' in response:
                    logs = response['logs']
                    if isinstance(logs, list):
                        print(f"Number of log entries: {len(logs)}")
                        if logs:
                            print(f"First log entry keys: {list(logs[0].keys()) if isinstance(logs[0], dict) else 'Not a dict'}")
                            if isinstance(logs[0], dict):
                                print(f"Sample log entry: {logs[0]}")
                    else:
                        print(f"Logs field type: {type(logs)}")
                        print(f"Logs content (first 200 chars): {str(logs)[:200]}")
                
                # Check for other relevant fields
                for key in ['count', 'size_bytes', 'compressed', 'statistics']:
                    if key in response:
                        print(f"{key}: {response[key]}")
        except Exception as e:
            print(f"Error parsing response: {e}")
            print(f"Raw response (first 200 chars): {response_data[:200]}")
    else:
        print("No response data")

conn.close()
