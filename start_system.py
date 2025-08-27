#!/usr/bin/env python3
"""
Quick Start Script for pfSense Firewall Management System
Starts both the HQ server and AI Command Center
"""

import asyncio
import subprocess
import sys
import os
import time
import signal
from pathlib import Path

def check_dependencies():
    """Check if required dependencies are installed"""
    try:
        import websockets
        import openai
        import aiosqlite
        import yaml
        print("✅ All dependencies are installed")
        return True
    except ImportError as e:
        print(f"❌ Missing dependency: {e}")
        print("Please run: pip install -r requirements.txt")
        return False

def check_config():
    """Check if configuration is set up"""
    env_file = Path(".env")
    if not env_file.exists():
        print("❌ .env file not found")
        print("Please copy config/.env.example to .env and configure it")
        return False

    # Check for OpenAI API key
    with open(env_file) as f:
        content = f.read()
        if "your_openai_api_key_here" in content:
            print("❌ OpenAI API key not configured in .env")
            print("Please set OPENAI_API_KEY in .env file")
            return False

    print("✅ Configuration looks good")
    return True

def start_hq_server():
    """Start the HQ server"""
    print("🚀 Starting HQ Server...")
    return subprocess.Popen([
        sys.executable, "hq/server.py",
        "--host", "0.0.0.0",
        "--port", "8000"
    ])

def start_ai_center():
    """Start the AI Command Center"""
    print("🤖 Starting AI Command Center...")

    # Get OpenAI API key from .env
    openai_key = None
    if os.path.exists(".env"):
        with open(".env") as f:
            for line in f:
                if line.startswith("OPENAI_API_KEY="):
                    openai_key = line.split("=", 1)[1].strip()
                    break

    if not openai_key:
        print("❌ OpenAI API key not found in .env")
        return None

    return subprocess.Popen([
        sys.executable, "hq/ai_command_center.py",
        "--openai-key", openai_key
    ])

def main():
    """Main function"""
    print("🔥 pfSense Firewall Management System - Quick Start")
    print("=" * 60)

    # Check dependencies
    if not check_dependencies():
        sys.exit(1)

    # Check configuration
    if not check_config():
        sys.exit(1)

    # Start services
    processes = []

    try:
        # Start HQ server
        hq_process = start_hq_server()
        processes.append(hq_process)

        # Wait a moment for server to start
        time.sleep(3)

        # Start AI Command Center
        ai_process = start_ai_center()
        if ai_process:
            processes.append(ai_process)

        print("\n🎉 System started successfully!")
        print("\nServices running:")
        print("- HQ Server: http://localhost:8000")
        print("- AI Command Center: Interactive terminal")
        print("\nPress Ctrl+C to stop all services")

        # Wait for processes
        while True:
            time.sleep(1)
            # Check if any process has died
            for proc in processes:
                if proc.poll() is not None:
                    print(f"❌ Process {proc.pid} has stopped")
                    break

    except KeyboardInterrupt:
        print("\n🛑 Stopping services...")

        # Terminate all processes
        for proc in processes:
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()

        print("✅ All services stopped")

if __name__ == "__main__":
    main()