#!/usr/bin/env python3
"""Test with a smaller log request (1 day instead of 7)"""
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

print(f"📋 Requesting 1 day of logs from {client_name}...")

# Send get_logs command with 1 day
resp = requests.post(f"{HQ_URL}/command", json={
    "client_id": client_id,
    "command_type": "get_logs",
    "params": {"days": 1}
})

if resp.status_code != 200:
    print(f"❌ Failed to send command: {resp.status_code}")
    exit(1)

command_id = resp.json().get('command_id')
print(f"✅ Command sent: {command_id}")

# Wait for response with progress monitoring
print("⏳ Waiting for logs...")
last_progress = None

for i in range(120):  # 2 minutes max
    time.sleep(1)
    resp = requests.get(f"{HQ_URL}/command/status", params={"command_id": command_id})
    
    if resp.status_code == 200:
        data = resp.json()
        status = data.get('status')
        progress = data.get('progress', {})
        
        # Show progress if changed
        current_progress = progress.get('progress_pct', 0)
        stage = progress.get('stage', 'unknown')
        current_file = progress.get('current_file', '')
        
        if current_progress != last_progress:
            print(f"   {stage}: {current_file} ({current_progress}%)")
            last_progress = current_progress
        
        if status == 'completed':
            print(f"\n✅ Logs received successfully!")
            
            # Check if temp files were created
            import os
            temp_dir = f"temp/{client_name}"
            if os.path.exists(temp_dir):
                files = os.listdir(temp_dir)
                print(f"\n📁 Temp files created:")
                for f in sorted(files):
                    size = os.path.getsize(os.path.join(temp_dir, f))
                    print(f"   {f}: {size:,} bytes")
            else:
                print(f"\n⚠️  No temp files found in {temp_dir}")
            
            exit(0)
        elif status == 'failed':
            print(f"\n❌ Command failed: {progress}")
            exit(1)
        elif i % 10 == 0 and i > 0:
            print(f"   Still waiting... ({i}s, status: {status})")

print("\n⏰ Timeout - logs not received")
print(f"\n💡 Check command status:")
print(f"   python check_command.py {command_id}")

