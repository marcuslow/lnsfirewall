#!/usr/bin/env python3
"""
Send a restart command to the client via the HQ server.
This uses the existing update mechanism to send a restart command.
"""
import requests
import time

HQ_URL = "http://localhost:8000"

def check_clients():
    """Check connected clients"""
    r = requests.get(f"{HQ_URL}/clients")
    clients = r.json().get('clients', {})
    print(f"Connected clients: {len(clients)}")
    for k, v in clients.items():
        print(f"  {v.get('client_name')}: {k}")
    return clients

def send_restart_command(client_id):
    """Send restart command to client"""
    print(f"\nSending restart command to {client_id}...")
    r = requests.post(f"{HQ_URL}/command", json={
        "client_id": client_id,
        "command_type": "restart_client",
        "params": {}
    })
    if r.status_code == 200:
        command_id = r.json().get("command_id")
        print(f"✅ Restart command sent: {command_id}")
        return command_id
    else:
        print(f"❌ Failed to send restart command: {r.status_code}")
        return None

if __name__ == "__main__":
    print("Checking for connected clients...")
    clients = check_clients()
    
    if not clients:
        print("\n❌ No clients connected!")
        print("\nYou need to manually restart the client on the pfSense box:")
        print("  SSH to pfSense and run:")
        print("  pkill -f pfsense_client.py")
        print("  python /root/pfsense_client.py &")
    else:
        print("\n✅ Client is connected, no restart needed")

