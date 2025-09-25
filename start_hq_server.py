#!/usr/bin/env python3
"""
Cross-platform HQ Server Starter
Works on Windows and Linux without emoji issues
"""

import subprocess
import sys
import os
import time
import threading

def start_ngrok():
    """Start ngrok tunnel"""
    print("Starting ngrok tunnel...")
    try:
        # Start ngrok in background
        ngrok_cmd = ["ngrok", "http", "8000", "--domain=lnsfirewall.ngrok.app"]
        ngrok_process = subprocess.Popen(ngrok_cmd, 
                                       stdout=subprocess.PIPE, 
                                       stderr=subprocess.PIPE)
        
        # Give ngrok time to start
        time.sleep(3)
        
        print("Ngrok tunnel started at: https://lnsfirewall.ngrok.app")
        print("WebSocket endpoint: wss://lnsfirewall.ngrok.app/ws")
        return ngrok_process
        
    except FileNotFoundError:
        print("ERROR: ngrok not found. Please install ngrok first.")
        return None
    except Exception as e:
        print(f"ERROR starting ngrok: {e}")
        return None

def start_hq_server():
    """Start the HQ server"""
    print("Starting HQ server on localhost:8000...")
    try:
        # Change to the hq directory
        os.chdir("hq")
        
        # Start the server
        server_cmd = [sys.executable, "http_server.py"]
        server_process = subprocess.Popen(server_cmd)
        
        print("HQ server started successfully")
        return server_process
        
    except Exception as e:
        print(f"ERROR starting HQ server: {e}")
        return None

def main():
    """Main function"""
    print("=" * 50)
    print("pfSense Firewall Management HQ Server")
    print("=" * 50)
    print(f"Time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    # Start ngrok tunnel
    ngrok_process = start_ngrok()
    if not ngrok_process:
        print("Failed to start ngrok. Exiting.")
        return 1
    
    # Start HQ server
    server_process = start_hq_server()
    if not server_process:
        print("Failed to start HQ server. Exiting.")
        if ngrok_process:
            ngrok_process.terminate()
        return 1
    
    print()
    print("=" * 50)
    print("SERVER READY!")
    print("=" * 50)
    print()
    print("HQ Server: http://localhost:8000")
    print("Public URL: https://lnsfirewall.ngrok.app")
    print("WebSocket: wss://lnsfirewall.ngrok.app/ws")
    print()
    print("Endpoints:")
    print("  GET  /status          - Server status")
    print("  GET  /clients         - List clients")
    print("  POST /command         - Send command")
    print("  WS   /ws              - WebSocket connection")
    print()
    print("Press Ctrl+C to stop both servers")
    print()
    
    try:
        # Wait for server process
        server_process.wait()
    except KeyboardInterrupt:
        print("\nShutting down servers...")
        
        # Terminate processes
        if server_process:
            server_process.terminate()
        if ngrok_process:
            ngrok_process.terminate()
        
        print("Servers stopped.")
        return 0

if __name__ == "__main__":
    sys.exit(main())
