#!/usr/bin/env python3
"""Check if client is connected and view recent activity"""
import requests
import json
from datetime import datetime

HQ_URL = "http://localhost:8000"

# Get clients
resp = requests.get(f"{HQ_URL}/clients")
clients = resp.json().get('clients', {})

print("=" * 60)
print("Connected Clients")
print("=" * 60)

if not clients:
    print("❌ No clients connected!")
else:
    for client_id, info in clients.items():
        client_name = info.get('client_name', 'unknown')
        last_seen = info.get('last_seen', 'never')
        connected_at = info.get('connected_at', 'unknown')
        
        print(f"\n✅ Client: {client_name}")
        print(f"   ID: {client_id}")
        print(f"   Connected: {connected_at}")
        print(f"   Last seen: {last_seen}")
        
        # Check if recently seen (within last 30 seconds)
        try:
            last_seen_dt = datetime.fromisoformat(last_seen)
            now = datetime.now()
            seconds_ago = (now - last_seen_dt).total_seconds()
            
            if seconds_ago < 30:
                print(f"   Status: 🟢 ACTIVE ({seconds_ago:.0f}s ago)")
            elif seconds_ago < 300:
                print(f"   Status: 🟡 IDLE ({seconds_ago:.0f}s ago)")
            else:
                print(f"   Status: 🔴 STALE ({seconds_ago:.0f}s ago)")
        except:
            print(f"   Status: ❓ UNKNOWN")

print("\n" + "=" * 60)

