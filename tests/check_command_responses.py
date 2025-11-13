#!/usr/bin/env python3
"""Check command responses to see log data format"""
import sqlite3
import json

def check_responses():
    print("=" * 80)
    print("Checking Command Responses")
    print("=" * 80)
    
    conn = sqlite3.connect('hq_database.db')
    cursor = conn.cursor()
    
    # Check recent get_logs command responses
    cursor.execute('''
        SELECT id, client_id, command_type, status, response_data
        FROM commands
        WHERE command_type = 'get_logs' AND status = 'completed'
        ORDER BY created_at DESC
        LIMIT 3
    ''')
    
    rows = cursor.fetchall()
    
    if not rows:
        print("❌ NO COMPLETED get_logs COMMANDS FOUND")
        return
    
    for i, row in enumerate(rows, 1):
        cmd_id, client_id, cmd_type, status, response_data = row
        print(f"\n📋 Command #{i}: {cmd_id}")
        print(f"   Client: {client_id}")
        print(f"   Status: {status}")
        
        if response_data:
            try:
                data = json.loads(response_data)
                print(f"   Response keys: {list(data.keys())}")
                
                # Check if 'logs' key exists
                if 'logs' in data:
                    logs = data['logs']
                    print(f"   ✅ Has 'logs' key: {type(logs)} with {len(logs) if isinstance(logs, (list, dict)) else 'unknown'} items")
                    
                    # Show sample of logs
                    if isinstance(logs, list) and logs:
                        print(f"   Sample log entry: {str(logs[0])[:100]}...")
                    elif isinstance(logs, dict):
                        print(f"   Logs dict keys: {list(logs.keys())}")
                else:
                    print(f"   ❌ NO 'logs' key found")
                    
                # Check other relevant keys
                for key in ['compressed', 'size_bytes', 'total_entries']:
                    if key in data:
                        print(f"   {key}: {data[key]}")
                        
            except json.JSONDecodeError as e:
                print(f"   ❌ Invalid JSON: {e}")
                print(f"   Raw data: {response_data[:200]}...")
        else:
            print(f"   ❌ No response data")
    
    conn.close()

if __name__ == "__main__":
    check_responses()
