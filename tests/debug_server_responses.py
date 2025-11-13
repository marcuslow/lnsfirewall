#!/usr/bin/env python3
"""Debug what the server is actually receiving"""
import sqlite3
import json

def debug_server_responses():
    print("=" * 80)
    print("Debugging Server Response Data")
    print("=" * 80)
    
    conn = sqlite3.connect('hq_database.db')
    cursor = conn.cursor()
    
    # Get the most recent get_logs commands
    cursor.execute('''
        SELECT id, client_id, status, response_data, created_at
        FROM commands
        WHERE command_type = 'get_logs' AND status = 'completed'
        ORDER BY created_at DESC
        LIMIT 3
    ''')
    
    rows = cursor.fetchall()
    
    for i, row in enumerate(rows, 1):
        cmd_id, client_id, status, response_data, created_at = row
        print(f"\n📋 Command #{i}: {cmd_id[:8]}...")
        print(f"   Client: {client_id}")
        print(f"   Created: {created_at}")
        print(f"   Status: {status}")
        
        if response_data:
            try:
                data = json.loads(response_data)
                print(f"   Response keys: {list(data.keys())}")
                
                # Check the exact condition from the server code
                has_logs = isinstance(data, dict) and data.get("logs") is not None
                print(f"   Condition check: isinstance(data, dict)={isinstance(data, dict)}")
                print(f"   Condition check: data.get('logs') is not None={data.get('logs') is not None}")
                print(f"   Overall condition: {has_logs}")
                
                if 'logs' in data:
                    logs = data['logs']
                    print(f"   Logs type: {type(logs)}")
                    print(f"   Logs is None: {logs is None}")
                    print(f"   Logs length: {len(logs) if isinstance(logs, (str, list)) else 'N/A'}")
                    
                    if isinstance(logs, str):
                        print(f"   First 100 chars: {logs[:100]}...")
                
                # Check compression flag
                if 'compressed' in data:
                    print(f"   Compressed: {data['compressed']}")
                    
            except Exception as e:
                print(f"   ❌ Error parsing response: {e}")
        else:
            print(f"   ❌ No response data")
    
    conn.close()

if __name__ == "__main__":
    debug_server_responses()
