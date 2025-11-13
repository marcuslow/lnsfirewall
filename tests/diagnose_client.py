#!/usr/bin/env python3
"""Send a diagnostic command to check client health"""
import requests
import json
import time

HQ_URL = "http://localhost:8000"

# Get client ID
resp = requests.get(f"{HQ_URL}/clients")
clients = resp.json().get('clients', {})

if not clients:
    print("❌ No clients connected!")
    exit(1)

client_id = list(clients.keys())[0]
client_name = clients[client_id].get('client_name', 'unknown')

print(f"📋 Sending diagnostic command to {client_name}...")

# Send get_status command (lightweight)
resp = requests.post(f"{HQ_URL}/command", json={
    "client_id": client_id,
    "command_type": "get_status",
    "params": {}
})

if resp.status_code != 200:
    print(f"❌ Failed to send command: {resp.status_code}")
    exit(1)

command_id = resp.json().get('command_id')
print(f"✅ Command sent: {command_id}")

# Wait for response
print("⏳ Waiting for response...")
for i in range(30):
    time.sleep(1)
    resp = requests.get(f"{HQ_URL}/command/status", params={"command_id": command_id})
    
    if resp.status_code == 200:
        data = resp.json()
        status = data.get('status')
        
        if status == 'completed':
            print(f"✅ Client responded successfully!")
            progress = data.get('progress', {})
            print(f"\nClient Status:")
            print(json.dumps(progress, indent=2))
            exit(0)
        elif status == 'failed':
            print(f"❌ Command failed: {data.get('progress')}")
            exit(1)
        else:
            print(f"   Status: {status} ({i+1}s)")
    else:
        print(f"   Waiting... ({i+1}s)")

print("⏰ Timeout - client did not respond")
print("\n💡 This suggests the client is having issues processing commands")
print("   Check pfSense client logs: tail -100 /var/log/pfsense_client.log")

