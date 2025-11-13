#!/usr/bin/env python3
"""
Test sending a command to the WebSocket client
"""

import requests
import json

def send_command():
    """Send a test command to the WebSocket client"""
    
    hq_url = "http://localhost:8000"
    
    # Send a ping command
    command_data = {
        "client_id": "test-websocket-client",
        "command_type": "ping",
        "params": {"message": "Hello from HQ!"}
    }
    
    print(f"🚀 Sending command to WebSocket client...")
    print(f"📋 Command: {json.dumps(command_data, indent=2)}")
    
    try:
        response = requests.post(
            f"{hq_url}/command",
            json=command_data,
            timeout=10
        )
        
        if response.status_code == 200:
            result = response.json()
            print(f"✅ Command sent successfully!")
            print(f"📨 Response: {json.dumps(result, indent=2)}")
            
            if result.get("delivery") == "sent_via_websocket":
                print("🎯 Command was delivered via WebSocket (real-time)!")
            else:
                print("📬 Command was queued for HTTP polling")
        else:
            print(f"❌ Failed to send command: {response.status_code} - {response.text}")
            
    except Exception as e:
        print(f"❌ Error sending command: {e}")

if __name__ == "__main__":
    send_command()
