#!/usr/bin/env python3
"""Test the command status endpoint to verify progress is returned correctly"""

import requests
import json

# Get the most recent command from the database
import psycopg2
import psycopg2.extras

DB_CONFIG = {
    'host': 'localhost',
    'port': 5432,
    'database': 'lnsfirewall',
    'user': 'postgres',
    'password': 'lnsFirewall2024!',
}

print("=" * 70)
print("Testing Command Status Endpoint")
print("=" * 70)

# Get a recent command ID from database
conn = psycopg2.connect(**DB_CONFIG)
cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

cur.execute("""
    SELECT id, client_id, command_type, status, response_data
    FROM commands 
    ORDER BY created_at DESC 
    LIMIT 1
""")
cmd = cur.fetchone()

if not cmd:
    print("❌ No commands found in database")
    exit(1)

print(f"\nMost recent command:")
print(f"  ID: {cmd['id']}")
print(f"  Client: {cmd['client_id']}")
print(f"  Type: {cmd['command_type']}")
print(f"  Status: {cmd['status']}")
print(f"  Response data type: {type(cmd['response_data'])}")
if cmd['response_data']:
    if isinstance(cmd['response_data'], dict):
        print(f"  Response data keys: {list(cmd['response_data'].keys())}")
    else:
        print(f"  Response data: {str(cmd['response_data'])[:100]}")

# Test the endpoint
print(f"\n" + "=" * 70)
print("Testing /command/status endpoint")
print("=" * 70)

try:
    response = requests.get(
        "http://localhost:8000/command/status",
        params={"command_id": cmd['id']},
        timeout=5
    )
    
    print(f"\nStatus Code: {response.status_code}")
    
    if response.status_code == 200:
        data = response.json()
        print(f"\n✅ Response received:")
        print(json.dumps(data, indent=2, default=str))
        
        # Check if it has the expected structure
        print(f"\n" + "=" * 70)
        print("Validation:")
        print("=" * 70)
        
        required_keys = ['command_id', 'client_id', 'command_type', 'status', 'progress']
        for key in required_keys:
            if key in data:
                print(f"  ✅ Has '{key}' key")
            else:
                print(f"  ❌ Missing '{key}' key")
        
        # Check progress structure
        if 'progress' in data and data['progress']:
            print(f"\n  Progress data:")
            progress = data['progress']
            if isinstance(progress, dict):
                for key, val in progress.items():
                    print(f"    {key}: {val}")
            else:
                print(f"    Type: {type(progress)}")
                print(f"    Value: {str(progress)[:100]}")
    else:
        print(f"❌ Error: {response.status_code}")
        print(f"Response: {response.text}")
        
except Exception as e:
    print(f"❌ Error calling endpoint: {e}")
    import traceback
    traceback.print_exc()

cur.close()
conn.close()

