#!/usr/bin/env python3
"""
Test WebSocket client for Windows
"""

import asyncio
import json
import logging
import os
import sys
import time
import yaml
from datetime import datetime
from pathlib import Path

try:
    import websockets
    WEBSOCKETS_AVAILABLE = True
except ImportError:
    WEBSOCKETS_AVAILABLE = False

# Configure logging for Windows
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class TestWebSocketClient:
    def __init__(self):
        self.client_id = "test-websocket-client"
        self.client_name = "test-client"
        self.hq_url = "http://localhost:8000"
        self.websocket = None
        self.running = True

    def get_websocket_url(self) -> str:
        """Convert HTTP URL to WebSocket URL"""
        ws_url = self.hq_url.replace('http://', 'ws://').replace('https://', 'wss://')
        return f"{ws_url.rstrip('/')}/ws"

    async def connect_websocket(self) -> bool:
        """Attempt to connect via WebSocket"""
        if not WEBSOCKETS_AVAILABLE:
            logger.error("WebSocket not available")
            return False
        
        try:
            ws_url = self.get_websocket_url()
            logger.info(f"Attempting WebSocket connection to {ws_url}")
            
            self.websocket = await websockets.connect(
                ws_url,
                ping_interval=30,
                ping_timeout=10
            )
            
            # Send registration message
            registration = {
                "type": "register",
                "client_id": self.client_id,
                "client_name": self.client_name,
                "hostname": "test-hostname"
            }
            
            await self.websocket.send(json.dumps(registration))
            logger.info("Sent registration message")
            
            # Wait for registration confirmation
            response = await asyncio.wait_for(self.websocket.recv(), timeout=10)
            message = json.loads(response)
            
            if message.get("type") == "registered":
                logger.info(f"✅ WebSocket registered as {message.get('client_name')} ({message.get('client_id')})")
                return True
            else:
                logger.error(f"❌ WebSocket registration failed: {message}")
                return False
                
        except Exception as e:
            logger.error(f"❌ WebSocket connection failed: {e}")
            self.websocket = None
            return False

    async def websocket_loop(self):
        """WebSocket message handling loop"""
        logger.info("Starting WebSocket message loop")
        
        last_heartbeat = time.time()
        
        try:
            while self.running and self.websocket:
                try:
                    # Send heartbeat every 30 seconds
                    if time.time() - last_heartbeat > 30:
                        await self.websocket.send(json.dumps({
                            "type": "heartbeat",
                            "client_id": self.client_id,
                            "timestamp": datetime.now().isoformat()
                        }))
                        logger.info("Sent heartbeat")
                        last_heartbeat = time.time()
                    
                    # Wait for messages with timeout
                    try:
                        message_text = await asyncio.wait_for(self.websocket.recv(), timeout=1.0)
                        message = json.loads(message_text)
                        
                        logger.info(f"📨 Received message: {message}")
                        
                        if message.get("type") == "command":
                            command = message.get("command")
                            if command:
                                logger.info(f"🎯 Received command: {command.get('type')}")
                                
                                # Send mock response
                                response_data = {
                                    "status": "success",
                                    "message": f"Executed {command.get('type')}",
                                    "timestamp": datetime.now().isoformat()
                                }
                                
                                await self.websocket.send(json.dumps({
                                    "type": "response",
                                    "command_id": command.get("id"),
                                    "data": response_data
                                }))
                                logger.info(f"📤 Sent response for command {command.get('id')}")
                        
                        elif message.get("type") == "heartbeat_ack":
                            logger.debug("💓 Received heartbeat acknowledgment")
                        
                        elif message.get("type") == "error":
                            logger.error(f"❌ Server error: {message.get('message')}")
                    
                    except asyncio.TimeoutError:
                        # Normal timeout, continue loop
                        continue
                
                except websockets.exceptions.ConnectionClosed:
                    logger.warning("🔌 WebSocket connection closed by server")
                    break
                except Exception as e:
                    logger.error(f"❌ Error in WebSocket loop: {e}")
                    break
        
        finally:
            self.websocket = None
            logger.info("WebSocket loop ended")

    async def run(self):
        """Main test loop"""
        logger.info("🚀 Starting WebSocket test client")
        
        try:
            if await self.connect_websocket():
                logger.info("✅ WebSocket connected successfully!")
                await self.websocket_loop()
            else:
                logger.error("❌ Failed to connect via WebSocket")
        
        except KeyboardInterrupt:
            logger.info("🛑 Received interrupt signal, shutting down...")
        except Exception as e:
            logger.error(f"❌ Unexpected error: {e}")
        finally:
            self.running = False
            if self.websocket:
                try:
                    await self.websocket.close()
                except:
                    pass
            logger.info("🏁 Test client stopped")

async def main():
    client = TestWebSocketClient()
    await client.run()

if __name__ == "__main__":
    asyncio.run(main())
