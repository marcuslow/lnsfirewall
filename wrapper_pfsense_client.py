#!/usr/bin/env python3
"""
Windows Wrapper pfSense Client for Testing
Simulates a pfSense client on Windows to test rule push workflow
"""

import asyncio
import json
import logging
import os
import shutil
import subprocess
import time
import websockets
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Dict, Any, Optional
import requests
import sys

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class WindowsPfSenseWrapper:
    """Windows wrapper that simulates pfSense client behavior"""
    
    def __init__(self, client_id: str = "test-wrapper", hq_url: str = "ws://localhost:8000"):
        self.client_id = client_id
        self.client_name = client_id
        self.hq_url = hq_url
        self.websocket = None
        self.running = False
        
        # Create simulation directories
        self.sim_dir = os.path.join(os.getcwd(), "pfsense_simulation")
        self.config_dir = os.path.join(self.sim_dir, "cf", "conf")
        self.backup_dir = os.path.join(self.sim_dir, "backups")
        
        # Ensure directories exist
        os.makedirs(self.config_dir, exist_ok=True)
        os.makedirs(self.backup_dir, exist_ok=True)
        
        # Create initial config file if it doesn't exist
        self.config_file = os.path.join(self.config_dir, "config.xml")
        self.create_initial_config()
        
        logger.info(f"Wrapper client initialized: {self.client_id}")
        logger.info(f"Simulation directory: {self.sim_dir}")
    
    def create_initial_config(self):
        """Create an initial pfSense-like config file"""
        if not os.path.exists(self.config_file):
            initial_config = '''<?xml version="1.0"?>
<pfsense>
    <version>2.7.0</version>
    <system>
        <hostname>test-wrapper</hostname>
        <domain>local</domain>
    </system>
    <interfaces>
        <wan>
            <enable/>
            <if>em0</if>
            <ipaddr>dhcp</ipaddr>
        </wan>
        <lan>
            <enable/>
            <if>em1</if>
            <ipaddr>192.168.1.1</ipaddr>
            <subnet>24</subnet>
        </lan>
    </interfaces>
    <filter>
        <rule>
            <type>block</type>
            <interface>wan</interface>
            <ipprotocol>inet</ipprotocol>
            <statetype>keep state</statetype>
            <direction>in</direction>
            <floating>yes</floating>
            <quick>yes</quick>
            <source>
                <any/>
            </source>
            <destination>
                <any/>
            </destination>
            <descr>Default block rule</descr>
        </rule>
        <rule>
            <type>pass</type>
            <interface>lan</interface>
            <ipprotocol>inet</ipprotocol>
            <statetype>keep state</statetype>
            <direction>in</direction>
            <source>
                <network>lan</network>
            </source>
            <destination>
                <any/>
            </destination>
            <descr>Default LAN to any rule</descr>
        </rule>
    </filter>
</pfsense>'''
            
            with open(self.config_file, 'w') as f:
                f.write(initial_config)
            logger.info(f"Created initial config file: {self.config_file}")
    
    async def connect_websocket(self):
        """Connect to HQ server via WebSocket"""
        try:
            ws_url = self.hq_url.replace("http://", "ws://").replace("https://", "wss://")
            if not ws_url.endswith("/ws"):
                ws_url += "/ws"
            
            logger.info(f"Connecting to WebSocket: {ws_url}")
            self.websocket = await websockets.connect(ws_url)
            
            # Send registration message
            registration = {
                "type": "register",
                "client_id": self.client_id,
                "client_name": self.client_name,
                "hostname": f"{self.client_name}-windows-wrapper",
                "system_health": {
                    "cpu_usage": 15.2,
                    "memory_usage": 45.8,
                    "disk_usage": 23.1,
                    "uptime": "2 days, 3 hours",
                    "platform": "Windows Simulation"
                }
            }
            
            await self.websocket.send(json.dumps(registration))
            logger.info("Registration message sent")
            
            # Wait for registration confirmation
            response = await self.websocket.recv()
            data = json.loads(response)
            
            if data.get("type") == "registered":
                logger.info(f"✅ Successfully registered as: {data.get('client_name')}")
                return True
            else:
                logger.error(f"Registration failed: {data}")
                return False
                
        except Exception as e:
            logger.error(f"WebSocket connection failed: {e}")
            return False
    
    async def handle_command(self, command: Dict[str, Any]) -> Dict[str, Any]:
        """Handle commands from HQ server"""
        command_type = command.get("type")
        command_id = command.get("id")
        params = command.get("params", {})
        
        logger.info(f"Handling command: {command_type} (ID: {command_id})")
        
        try:
            if command_type == "get_rules":
                return await self.get_firewall_rules()
            elif command_type == "set_rules":
                return await self.set_firewall_rules(params)
            elif command_type == "get_system_health":
                return await self.get_system_health()
            elif command_type == "ping":
                return {"status": "success", "message": "pong", "timestamp": datetime.now().isoformat()}
            else:
                return {"status": "error", "message": f"Unknown command type: {command_type}"}
                
        except Exception as e:
            logger.error(f"Error handling command {command_type}: {e}")
            return {"status": "error", "message": str(e)}
    
    async def get_firewall_rules(self) -> Dict[str, Any]:
        """Get current firewall rules (simulated)"""
        try:
            logger.info("Getting firewall rules...")
            
            if not os.path.exists(self.config_file):
                return {'status': 'error', 'message': 'Config file not found'}
            
            with open(self.config_file, 'r') as f:
                config_content = f.read()
            
            logger.info(f"Config file read, size: {len(config_content)} bytes")
            
            # Extract filter section
            try:
                root = ET.fromstring(config_content)
                filter_elem = root.find('filter')
                
                if filter_elem is not None:
                    # Convert filter element back to XML string
                    rules_xml = ET.tostring(filter_elem, encoding='unicode')
                    # Remove the outer <filter> tags to get just the inner content
                    rules_xml = rules_xml.replace('<filter>', '').replace('</filter>', '').strip()
                    
                    rule_count = len(filter_elem.findall('rule'))
                    
                    logger.info(f"Extracted {rule_count} rules from config")
                    
                    return {
                        'status': 'success',
                        'rules_xml': rules_xml,
                        'rule_count': rule_count,
                        'timestamp': datetime.now().isoformat(),
                        'config_size': len(config_content)
                    }
                else:
                    return {'status': 'error', 'message': 'No filter section found in config'}
                    
            except ET.ParseError as e:
                logger.error(f"XML parsing error: {e}")
                return {'status': 'error', 'message': f'Config XML parsing failed: {e}'}
                
        except Exception as e:
            logger.error(f"Error getting firewall rules: {e}")
            return {'status': 'error', 'message': str(e)}
    
    async def set_firewall_rules(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Set new firewall rules (simulated)"""
        try:
            new_rules = params.get('rules_xml', '')
            if not new_rules:
                return {'status': 'error', 'message': 'No rules provided'}
            
            logger.info(f"Setting new firewall rules, size: {len(new_rules)} chars")
            
            # Create backup
            timestamp = int(time.time())
            backup_file = os.path.join(self.backup_dir, f"config.xml.backup.{timestamp}")
            
            if os.path.exists(self.config_file):
                shutil.copy2(self.config_file, backup_file)
                logger.info(f"Backed up config to {backup_file}")
            
            # Read current config
            with open(self.config_file, 'r') as f:
                config_content = f.read()
            
            # Replace filter section
            import re
            new_config = re.sub(
                r'<filter>.*?</filter>',
                f'<filter>{new_rules}</filter>',
                config_content,
                flags=re.DOTALL
            )
            
            # Write new config
            with open(self.config_file, 'w') as f:
                f.write(new_config)
            
            logger.info("New config written successfully")
            
            # Simulate firewall reload (Windows equivalent)
            reload_success = await self.simulate_firewall_reload()
            
            if reload_success:
                logger.info("✅ Firewall rules updated successfully")
                return {
                    'status': 'success',
                    'message': 'Firewall rules updated successfully (simulated)',
                    'backup_file': backup_file,
                    'timestamp': datetime.now().isoformat(),
                    'rules_applied': new_rules.count('<rule'),
                    'platform': 'Windows Simulation'
                }
            else:
                # Restore backup
                shutil.copy2(backup_file, self.config_file)
                logger.warning("Firewall reload failed, backup restored")
                return {
                    'status': 'error',
                    'message': 'Simulated firewall reload failed, backup restored',
                    'restored_backup': True
                }
                
        except Exception as e:
            logger.error(f"Error setting firewall rules: {e}")
            return {'status': 'error', 'message': str(e)}
    
    async def simulate_firewall_reload(self) -> bool:
        """Simulate pfSense firewall reload"""
        try:
            logger.info("Simulating firewall reload...")
            
            # Validate XML structure
            with open(self.config_file, 'r') as f:
                config_content = f.read()
            
            # Try to parse the XML to ensure it's valid
            try:
                ET.fromstring(config_content)
                logger.info("✅ XML validation passed")
            except ET.ParseError as e:
                logger.error(f"❌ XML validation failed: {e}")
                return False
            
            # Simulate processing time
            await asyncio.sleep(1)
            
            # Simulate success (you could add failure scenarios here for testing)
            logger.info("✅ Simulated firewall reload completed successfully")
            return True
            
        except Exception as e:
            logger.error(f"Simulated firewall reload failed: {e}")
            return False
    
    async def get_system_health(self) -> Dict[str, Any]:
        """Get system health (simulated)"""
        return {
            'status': 'success',
            'health': {
                'cpu_usage': 12.5,
                'memory_usage': 48.2,
                'disk_usage': 25.7,
                'uptime': '2 days, 4 hours',
                'platform': 'Windows Simulation',
                'config_file_size': os.path.getsize(self.config_file) if os.path.exists(self.config_file) else 0,
                'backup_count': len([f for f in os.listdir(self.backup_dir) if f.startswith('config.xml.backup')])
            },
            'timestamp': datetime.now().isoformat()
        }
    
    async def run(self):
        """Main client loop"""
        self.running = True
        logger.info(f"Starting wrapper pfSense client: {self.client_id}")
        
        while self.running:
            try:
                # Connect to WebSocket
                if not await self.connect_websocket():
                    logger.error("Failed to connect, retrying in 5 seconds...")
                    await asyncio.sleep(5)
                    continue
                
                logger.info("✅ Connected and registered, listening for commands...")
                
                # Listen for commands
                async for message in self.websocket:
                    try:
                        data = json.loads(message)
                        
                        if data.get("type") == "command":
                            command = data.get("command")
                            if command:
                                logger.info(f"📨 Received command: {command.get('type')}")
                                response = await self.handle_command(command)
                                
                                # Send response back
                                await self.websocket.send(json.dumps({
                                    "type": "response",
                                    "command_id": command.get("id"),
                                    "data": response
                                }))
                                logger.info(f"📤 Response sent for command {command.get('id')}")
                        
                    except json.JSONDecodeError:
                        logger.error("Received invalid JSON message")
                    except Exception as e:
                        logger.error(f"Error processing message: {e}")
                        
            except websockets.exceptions.ConnectionClosed:
                logger.warning("WebSocket connection closed, reconnecting...")
                await asyncio.sleep(2)
            except Exception as e:
                logger.error(f"Unexpected error: {e}")
                await asyncio.sleep(5)
    
    def stop(self):
        """Stop the client"""
        self.running = False
        logger.info("Stopping wrapper client...")

async def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Windows pfSense Wrapper Client")
    parser.add_argument("--client-id", default="test-wrapper", help="Client ID")
    parser.add_argument("--hq-url", default="ws://localhost:8000", help="HQ server URL")
    
    args = parser.parse_args()
    
    client = WindowsPfSenseWrapper(args.client_id, args.hq_url)
    
    try:
        await client.run()
    except KeyboardInterrupt:
        logger.info("Received interrupt signal")
    finally:
        client.stop()

if __name__ == "__main__":
    asyncio.run(main())
