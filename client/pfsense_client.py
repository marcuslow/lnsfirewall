#!/usr/bin/env python3
"""
pfSense Firewall Client Script
Connects to HQ server and executes firewall management commands
"""

import asyncio
import json
import logging
import os
import sys
import time
import subprocess
import yaml
# import requests  # Removed - WebSocket only mode
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any
import hashlib
import gzip
import shutil
from glob import glob
import base64

try:
    import websockets
    WEBSOCKETS_AVAILABLE = True
except ImportError:
    WEBSOCKETS_AVAILABLE = False
    logger.warning("websockets not available, will use HTTP polling only")

try:
    import psutil
except ImportError:
    import psutil_stub as psutil


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/pfsense_client.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class PfSenseClient:
    def __init__(self, config_path: str = '/usr/local/etc/pfsense_client.yaml'):
        self.config_path = config_path
        self.config = self.load_config()
        self.client_id = self.config.get('client_id', self.generate_client_id())
        self.client_name = self.config.get('client_name', self.get_pfsense_hostname() or f"firewall-{self.client_id[:8]}")
        self.hq_url = self.config.get('hq_url', 'http://localhost:8000')
        self.reconnect_interval = self.config.get('reconnect_interval', 20)  # Used when server is offline/unreachable
        # Removed HTTP polling settings - WebSocket only mode
        self.registered = False
        self.running = True
        self.websocket = None
        self.connection_mode = None  # 'websocket' or 'http'

    def load_config(self) -> Dict[str, Any]:
        """Load configuration from YAML file"""
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r') as f:
                    return yaml.safe_load(f) or {}
            else:
                logger.warning(f"Config file not found: {self.config_path}")
                return {}
        except Exception as e:
            logger.error(f"Error loading config: {e}")
            return {}

    def generate_client_id(self) -> str:
        """Generate unique client ID based on system info"""
        try:
            # Try to get pfSense hostname from config
            hostname = self.get_pfsense_hostname()
            if not hostname:
                hostname = os.uname().nodename

            # Create unique ID
            system_info = f"{hostname}-{psutil.boot_time()}"
            return hashlib.md5(system_info.encode()).hexdigest()[:16]
        except Exception as e:
            logger.error(f"Error generating client ID: {e}")
            return "unknown-client"

    def get_pfsense_hostname(self) -> Optional[str]:
        """Get hostname from pfSense config"""
        try:
            config_file = '/cf/conf/config.xml'
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    content = f.read()
                    # Simple XML parsing for hostname
                    import re
                    match = re.search(r'<hostname>(.*?)</hostname>', content)
                    if match:
                        return match.group(1)
        except Exception as e:
            logger.error(f"Error reading pfSense config: {e}")
        return None

    # HTTP methods removed - WebSocket only mode

    # send_response removed - handled directly in websocket_loop

    async def send_message(self, message: Dict[str, Any]):
        """Send message to HQ server via WebSocket"""
        try:
            if self.websocket:
                message_json = json.dumps(message)
                message_size = len(message_json)
                logger.debug(f"Sending WebSocket message, size: {message_size} bytes, type: {message.get('type')}")
                await self.websocket.send(message_json)
                logger.debug(f"WebSocket message sent successfully")
            else:
                logger.error("Cannot send message: WebSocket not connected")
        except Exception as e:
            logger.error(f"Error sending WebSocket message: {e}")
            # Mark connection as broken
            self.websocket = None
            self.registered = False

    def get_websocket_url(self) -> str:
        """Convert HTTP URL to WebSocket URL"""
        ws_url = self.hq_url.replace('http://', 'ws://').replace('https://', 'wss://')
        return f"{ws_url.rstrip('/')}/ws"

    async def connect_websocket(self) -> bool:
        """Attempt to connect via WebSocket"""
        if not WEBSOCKETS_AVAILABLE:
            logger.info("WebSocket not available, falling back to HTTP")
            return False

        try:
            ws_url = self.get_websocket_url()
            logger.info(f"Attempting WebSocket connection to {ws_url}")

            self.websocket = await websockets.connect(
                ws_url,
                ping_interval=30,
                ping_timeout=10
            )

            # Send registration message with system health
            system_health = await self.get_system_status()
            registration = {
                "type": "register",
                "client_id": self.client_id,
                "client_name": self.client_name,
                "hostname": self.get_pfsense_hostname() or 'unknown',
                "system_health": system_health
            }

            await self.websocket.send(json.dumps(registration))

            # Wait for registration confirmation
            response = await asyncio.wait_for(self.websocket.recv(), timeout=10)
            message = json.loads(response)

            if message.get("type") == "registered":
                logger.info(f"WebSocket registered as {message.get('client_name')} ({message.get('client_id')})")
                self.registered = True
                self.connection_mode = 'websocket'
                return True
            else:
                logger.error(f"WebSocket registration failed: {message}")
                return False

        except Exception as e:
            logger.warning(f"WebSocket connection failed: {e}")
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
                        await self.send_message({
                            "type": "heartbeat",
                            "client_id": self.client_id,
                            "timestamp": datetime.now().isoformat()
                        })
                        last_heartbeat = time.time()

                    # Wait for messages with timeout
                    try:
                        message_text = await asyncio.wait_for(self.websocket.recv(), timeout=1.0)
                        message = json.loads(message_text)

                        if message.get("type") == "command":
                            command = message.get("command")
                            if command:
                                logger.info(f"Received WebSocket command: {command.get('type')}")
                                response = await self.handle_command(command)

                                # Send response back
                                logger.info(f"Sending response for command {command.get('id')}, response size: {len(str(response))} chars")
                                try:
                                    await self.send_message({
                                        "type": "response",
                                        "command_id": command.get("id"),
                                        "data": response
                                    })
                                    logger.info(f"Response sent successfully for command {command.get('id')}")
                                except Exception as e:
                                    logger.error(f"Failed to send response for command {command.get('id')}: {e}")

                        elif message.get("type") == "heartbeat_ack":
                            logger.debug("Received heartbeat acknowledgment")

                        elif message.get("type") == "error":
                            logger.error(f"Server error: {message.get('message')}")

                    except asyncio.TimeoutError:
                        # Normal timeout, continue loop
                        continue

                except websockets.exceptions.ConnectionClosed:
                    logger.warning("WebSocket connection closed by server")
                    break
                except Exception as e:
                    logger.error(f"Error in WebSocket loop: {e}")
                    break

        finally:
            self.websocket = None
            self.registered = False
            logger.info("WebSocket loop ended")

    async def handle_command(self, command: Dict[str, Any]) -> Dict[str, Any]:
        """Handle incoming command from HQ"""
        cmd_type = command.get('type')
        cmd_id = command.get('id', 'unknown')

        logger.info(f"Received command: {cmd_type} (ID: {cmd_id})")

        try:
            if cmd_type == 'get_logs':
                return await self.get_firewall_logs(command.get('params', {}), cmd_id)
            elif cmd_type == 'get_status':
                return await self.get_system_status()
            elif cmd_type == 'get_rules':
                return await self.get_firewall_rules()
            elif cmd_type == 'set_rules':
                return await self.set_firewall_rules(command.get('params', {}))
            elif cmd_type == 'restart_firewall':
                return await self.restart_firewall()
            elif cmd_type == 'update_client':
                return await self.update_client_files(command.get('params', {}))
            elif cmd_type == 'ping':
                return {'status': 'success', 'message': 'pong', 'timestamp': datetime.now().isoformat()}
            else:
                return {'status': 'error', 'message': f'Unknown command type: {cmd_type}'}
        except Exception as e:
            logger.error(f"Error handling command {cmd_type}: {e}")
            return {'status': 'error', 'message': str(e)}

    async def get_firewall_logs(self, params: Dict[str, Any], command_id: Optional[str] = None) -> Dict[str, Any]:
        """Collect firewall logs from specified date range and stream progress back to HQ"""
        try:
            days = params.get('days', 90)
            max_days = min(days, 90)  # Limit to 90 days max

            start_date = datetime.now() - timedelta(days=max_days)

            # pfSense rotated logs (e.g., filter.log, filter.log.0.gz, filter.log.1, etc.)
            # Build dynamically to include rotated files present on the system.
            log_files = []
            # Filter logs (including rotated variants)
            log_files.extend(sorted(glob('/var/log/filter.log*')))
            # pfBlockerNG logs (including rotated variants)
            log_files.extend(sorted(glob('/var/log/pfblockerng/ip_block.log*')))

            # Only keep files that exist and are readable
            log_files = [f for f in log_files if os.path.exists(f)]
            # Sort by modification time ascending so earlier logs are processed first
            try:
                log_files.sort(key=lambda p: os.path.getmtime(p))
            except Exception:
                pass

            logs_data = []
            total_size = 0

            total_files = len(log_files)
            for idx, log_file in enumerate(log_files, start=1):
                if os.path.exists(log_file):
                    file_logs = self.parse_log_file(log_file, start_date)
                    logs_data.extend(file_logs)
                    total_size += os.path.getsize(log_file)

                # Send progress update to HQ via WebSocket (if available)
                if command_id and self.websocket:
                    progress_pct = int((idx / total_files) * 100) if total_files else 100
                    try:
                        await self.send_message({
                            "type": "progress",
                            "command_id": command_id,
                            "data": {
                                "status": "in_progress",
                                "stage": "parsing_logs",
                                "current_file": os.path.basename(log_file),
                                "files_done": idx,
                                "files_total": total_files,
                                "progress_pct": progress_pct,
                                "timestamp": datetime.now().isoformat()
                            }
                        })
                    except Exception as e:
                        logger.debug(f"Failed to send progress update: {e}")

            # Sort by timestamp
            logs_data.sort(key=lambda x: x.get('timestamp', ''))

            # Generate statistics
            log_stats = self.generate_log_statistics(logs_data)

            # Compress if large
            if len(logs_data) > 10000:
                compressed_logs = self.compress_logs(logs_data)
                return {
                    'status': 'success',
                    'logs': compressed_logs,
                    'compressed': True,
                    'count': len(logs_data),
                    'size_bytes': total_size,
                    'date_range': f"{start_date.isoformat()} to {datetime.now().isoformat()}",
                    'statistics': log_stats,
                    'files_processed': [f for f in log_files if os.path.exists(f)]
                }

            return {
                'status': 'success',
                'logs': logs_data,
                'compressed': False,
                'count': len(logs_data),
                'size_bytes': total_size,
                'date_range': f"{start_date.isoformat()} to {datetime.now().isoformat()}",
                'statistics': log_stats,
                'files_processed': [f for f in log_files if os.path.exists(f)]
            }

        except Exception as e:
            logger.error(f"Error collecting logs: {e}")
            return {'status': 'error', 'message': str(e)}

    def parse_log_file(self, log_file: str, start_date: datetime) -> List[Dict[str, Any]]:
        """Parse pfSense log file and extract entries after start_date"""
        logs = []
        try:
            if not os.path.exists(log_file):
                logger.debug(f"Log file does not exist: {log_file}")
                return logs

            with open(log_file, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue

                    parsed_entry = self.parse_pfsense_log_line(line, log_file, line_num)
                    if parsed_entry and parsed_entry.get('timestamp_obj'):
                        if parsed_entry['timestamp_obj'] >= start_date:
                            # Remove the datetime object before storing
                            del parsed_entry['timestamp_obj']
                            logs.append(parsed_entry)
                    elif parsed_entry:
                        # Include lines that couldn't be parsed with timestamp
                        logs.append(parsed_entry)

        except Exception as e:
            logger.error(f"Error parsing log file {log_file}: {e}")

        return logs

    def generate_log_statistics(self, logs_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate statistics from parsed log data"""
        stats = {
            'total_entries': len(logs_data),
            'by_log_type': {},
            'by_source': {},
            'by_action': {},
            'by_protocol': {},
            'top_source_ips': {},
            'top_dest_ips': {},
            'blocked_connections': 0,
            'allowed_connections': 0
        }

        for entry in logs_data:
            # Count by log type
            log_type = entry.get('log_type', 'unknown')
            stats['by_log_type'][log_type] = stats['by_log_type'].get(log_type, 0) + 1

            # Count by source file
            source = entry.get('source', 'unknown')
            stats['by_source'][source] = stats['by_source'].get(source, 0) + 1

            # Count by action
            action = entry.get('action', 'unknown')
            if action != 'unknown':
                stats['by_action'][action] = stats['by_action'].get(action, 0) + 1

                # Count blocked vs allowed
                if action in ['block', 'blocked']:
                    stats['blocked_connections'] += 1
                elif action in ['pass', 'allow', 'allowed']:
                    stats['allowed_connections'] += 1

            # Count by protocol
            protocol = entry.get('protocol', 'unknown')
            if protocol != 'unknown':
                stats['by_protocol'][protocol] = stats['by_protocol'].get(protocol, 0) + 1

            # Track top IPs
            source_ip = entry.get('source_ip')
            if source_ip:
                stats['top_source_ips'][source_ip] = stats['top_source_ips'].get(source_ip, 0) + 1

            dest_ip = entry.get('dest_ip')
            if dest_ip:
                stats['top_dest_ips'][dest_ip] = stats['top_dest_ips'].get(dest_ip, 0) + 1

        # Sort top IPs by frequency (keep top 10)
        stats['top_source_ips'] = dict(sorted(stats['top_source_ips'].items(),
                                            key=lambda x: x[1], reverse=True)[:10])
        stats['top_dest_ips'] = dict(sorted(stats['top_dest_ips'].items(),
                                          key=lambda x: x[1], reverse=True)[:10])

        return stats

    def parse_pfsense_log_line(self, line: str, log_file: str, line_num: int) -> Optional[Dict[str, Any]]:
        """Parse individual pfSense log line based on log type"""
        try:
            log_type = self.detect_log_type(log_file, line)

            if log_type == 'filter':
                return self.parse_filter_log_line(line, log_file)
            elif log_type == 'pfblockerng':
                return self.parse_pfblockerng_log_line(line, log_file)
            else:
                return self.parse_generic_log_line(line, log_file)

        except Exception as e:
            logger.debug(f"Error parsing line {line_num} in {log_file}: {e}")
            return {
                'timestamp': datetime.now().isoformat(),
                'timestamp_obj': datetime.now(),
                'source': os.path.basename(log_file),
                'log_type': 'unparsed',
                'raw_message': line,
                'error': str(e)
            }

    def detect_log_type(self, log_file: str, line: str) -> str:
        """Detect the type of log based on file path and content"""
        if 'pfblockerng' in log_file:
            return 'pfblockerng'
        elif 'filter' in log_file and 'filterlog[' in line:
            return 'filter'
        else:
            return 'generic'

    def parse_filter_log_line(self, line: str, log_file: str) -> Dict[str, Any]:
        """Parse pfSense filter log line"""
        # Example: Aug 21 17:13:00 pfSense filterlog[80936]: 4,,,1000000103,vtnet0,match,block,in,4,0x0,,124,19963,0,none,1,icmp,60,211.24.58.7,103.26.150.122,request,2233,1729740

        parts = line.split(' ', 5)
        if len(parts) >= 6:
            try:
                # Parse timestamp
                log_date_str = f"{parts[0]} {parts[1]} {parts[2]}"
                log_date = datetime.strptime(log_date_str, "%b %d %H:%M:%S")
                log_date = log_date.replace(year=datetime.now().year)

                # Extract filterlog data
                if 'filterlog[' in line and ']:' in line:
                    filterlog_data = line.split(']: ', 1)[1] if ']: ' in line else ''
                    filter_fields = filterlog_data.split(',') if filterlog_data else []

                    parsed_data = {
                        'timestamp': log_date.isoformat(),
                        'timestamp_obj': log_date,
                        'source': os.path.basename(log_file),
                        'log_type': 'filter',
                        'hostname': parts[3] if len(parts) > 3 else 'unknown',
                        'raw_message': line
                    }

                    # Parse filter fields if available
                    if len(filter_fields) >= 8:
                        parsed_data.update({
                            'rule_number': filter_fields[0] if filter_fields[0] else None,
                            'interface': filter_fields[4] if len(filter_fields) > 4 else None,
                            'action': filter_fields[6] if len(filter_fields) > 6 else None,
                            'direction': filter_fields[7] if len(filter_fields) > 7 else None,
                            'protocol': filter_fields[16] if len(filter_fields) > 16 else None,
                            'source_ip': filter_fields[18] if len(filter_fields) > 18 else None,
                            'dest_ip': filter_fields[19] if len(filter_fields) > 19 else None
                        })

                    return parsed_data

            except ValueError as e:
                logger.debug(f"Date parsing failed for filter log: {e}")

        return self.parse_generic_log_line(line, log_file)

    def parse_pfblockerng_log_line(self, line: str, log_file: str) -> Dict[str, Any]:
        """Parse pfBlockerNG log line"""
        # Example: Aug 20 02:39:20,1770009964,vtnet0,WAN,block,4,6,TCP-S,176.65.149.67,103.26.150.122,40177,1443,in,Unk,pfB_PRI1_v4,176.65.148.0/22,ET_Block_v4,hosted-by.pfcloud.io,wan,null,+

        try:
            # Split by comma for pfBlockerNG format
            if ',' in line:
                fields = line.split(',')
                if len(fields) >= 10:
                    # First field should be timestamp
                    timestamp_str = fields[0]
                    log_date = datetime.strptime(timestamp_str, "%b %d %H:%M:%S")
                    log_date = log_date.replace(year=datetime.now().year)

                    return {
                        'timestamp': log_date.isoformat(),
                        'timestamp_obj': log_date,
                        'source': os.path.basename(log_file),
                        'log_type': 'pfblockerng',
                        'interface': fields[2] if len(fields) > 2 else None,
                        'action': fields[4] if len(fields) > 4 else None,
                        'protocol': fields[7] if len(fields) > 7 else None,
                        'source_ip': fields[8] if len(fields) > 8 else None,
                        'dest_ip': fields[9] if len(fields) > 9 else None,
                        'source_port': fields[10] if len(fields) > 10 else None,
                        'dest_port': fields[11] if len(fields) > 11 else None,
                        'block_list': fields[14] if len(fields) > 14 else None,
                        'block_reason': fields[16] if len(fields) > 16 else None,
                        'raw_message': line
                    }
        except ValueError as e:
            logger.debug(f"Date parsing failed for pfBlockerNG log: {e}")

        return self.parse_generic_log_line(line, log_file)

    def parse_generic_log_line(self, line: str, log_file: str) -> Dict[str, Any]:
        """Parse generic log line with basic timestamp extraction"""
        parts = line.split(' ', 5)
        if len(parts) >= 3:
            try:
                # Try to parse standard syslog timestamp
                log_date_str = f"{parts[0]} {parts[1]} {parts[2]}"
                log_date = datetime.strptime(log_date_str, "%b %d %H:%M:%S")
                log_date = log_date.replace(year=datetime.now().year)

                return {
                    'timestamp': log_date.isoformat(),
                    'timestamp_obj': log_date,
                    'source': os.path.basename(log_file),
                    'log_type': 'generic',
                    'hostname': parts[3] if len(parts) > 3 else 'unknown',
                    'raw_message': line
                }
            except ValueError:
                pass

        # Fallback for unparseable lines
        return {
            'timestamp': datetime.now().isoformat(),
            'timestamp_obj': datetime.now(),
            'source': os.path.basename(log_file),
            'log_type': 'unparsed',
            'raw_message': line
        }

    def compress_logs(self, logs: List[Dict[str, Any]]) -> str:
        """Compress logs data using gzip"""
        try:
            import base64
            logs_json = json.dumps(logs)
            compressed = gzip.compress(logs_json.encode('utf-8'))
            return base64.b64encode(compressed).decode('utf-8')
        except Exception as e:
            logger.error(f"Error compressing logs: {e}")
            return ""

    async def get_system_status(self) -> Dict[str, Any]:
        """Get system status information"""
        try:
            # System uptime
            boot_time = datetime.fromtimestamp(psutil.boot_time())
            uptime = datetime.now() - boot_time

            # Memory info
            memory = psutil.virtual_memory()

            # Disk usage
            disk_usage = psutil.disk_usage('/')

            # CPU info
            cpu_percent = psutil.cpu_percent(interval=1)

            # Network interfaces
            network_stats = {}
            for interface, stats in psutil.net_io_counters(pernic=True).items():
                network_stats[interface] = {
                    'bytes_sent': stats.bytes_sent,
                    'bytes_recv': stats.bytes_recv,
                    'packets_sent': stats.packets_sent,
                    'packets_recv': stats.packets_recv
                }

            return {
                'status': 'success',
                'hostname': self.get_pfsense_hostname() or 'unknown',
                'client_id': self.client_id,
                'client_name': self.client_name,
                'uptime': {
                    'boot_time': boot_time.isoformat(),
                    'uptime_seconds': int(uptime.total_seconds()),
                    'uptime_human': str(uptime)
                },
                'memory': {
                    'total': memory.total,
                    'available': memory.available,
                    'percent': memory.percent,
                    'used': memory.used
                },
                'disk': {
                    'total': disk_usage.total,
                    'used': disk_usage.used,
                    'free': disk_usage.free,
                    'percent': (disk_usage.used / disk_usage.total) * 100
                },
                'cpu': {
                    'percent': cpu_percent,
                    'count': psutil.cpu_count()
                },
                'network': network_stats,
                'timestamp': datetime.now().isoformat()
            }

        except Exception as e:
            logger.error(f"Error getting system status: {e}")
            return {'status': 'error', 'message': str(e)}

    async def get_firewall_rules(self) -> Dict[str, Any]:
        """Get current firewall rules"""
        try:
            logger.info("Starting to get firewall rules...")
            rules_file = '/cf/conf/config.xml'
            if not os.path.exists(rules_file):
                return {'status': 'error', 'message': 'pfSense config file not found'}

            logger.info("Reading config file...")
            with open(rules_file, 'r') as f:
                config_content = f.read()

            logger.info(f"Config file read successfully, size: {len(config_content)} bytes")

            # Extract rules section with more robust parsing
            import re
            logger.info("Extracting filter section...")

            # Find the start and end of the filter section
            filter_start = config_content.find('<filter>')
            filter_end = config_content.find('</filter>')

            if filter_start != -1 and filter_end != -1:
                # Extract content between <filter> and </filter>
                rules_xml = config_content[filter_start + 8:filter_end]  # +8 to skip '<filter>'
                logger.info(f"Filter section extracted, size: {len(rules_xml)} bytes")

                # Limit the size to prevent WebSocket issues (max 50KB)
                if len(rules_xml) > 50000:
                    rules_xml = rules_xml[:50000] + "\n<!-- TRUNCATED - Rules too large -->"
                    logger.warning("Rules truncated due to size limit")
            else:
                rules_xml = ""
                logger.warning("No filter section found in config")

            result = {
                'status': 'success',
                'rules_xml': rules_xml,
                'config_size': len(config_content),
                'rules_size': len(rules_xml),
                'timestamp': datetime.now().isoformat()
            }

            logger.info("Firewall rules extracted successfully")
            return result

        except Exception as e:
            logger.error(f"Error getting firewall rules: {e}")
            return {'status': 'error', 'message': str(e)}

    async def set_firewall_rules(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Set new firewall rules"""
        try:
            new_rules = params.get('rules_xml', '')
            if not new_rules:
                return {'status': 'error', 'message': 'No rules provided'}

            # Backup current config
            config_file = '/cf/conf/config.xml'
            backup_file = f'/cf/conf/config.xml.backup.{int(time.time())}'

            if os.path.exists(config_file):
                shutil.copy2(config_file, backup_file)
                logger.info(f"Backed up config to {backup_file}")

            # Read current config
            with open(config_file, 'r') as f:
                config_content = f.read()

            # Replace rules section
            import re
            new_config = re.sub(
                r'<filter>.*?</filter>',
                f'<filter>{new_rules}</filter>',
                config_content,
                flags=re.DOTALL
            )

            # Write new config
            with open(config_file, 'w') as f:
                f.write(new_config)

            # Reload firewall rules
            result = subprocess.run(['/etc/rc.filter_configure'],
                                  capture_output=True, text=True)

            if result.returncode == 0:
                return {
                    'status': 'success',
                    'message': 'Firewall rules updated successfully',
                    'backup_file': backup_file,
                    'timestamp': datetime.now().isoformat()
                }
            else:
                # Restore backup if reload failed
                shutil.copy2(backup_file, config_file)
                return {
                    'status': 'error',
                    'message': f'Failed to reload rules: {result.stderr}',
                    'restored_backup': True
                }

        except Exception as e:
            logger.error(f"Error setting firewall rules: {e}")
            return {'status': 'error', 'message': str(e)}

    async def restart_firewall(self) -> Dict[str, Any]:
        """Restart the firewall service"""
        try:
            logger.warning("Restarting firewall - this may cause temporary connectivity loss")

            # Execute pfSense firewall restart
            result = subprocess.run(['/etc/rc.restart_webgui'],
                                  capture_output=True, text=True)

            if result.returncode == 0:
                return {
                    'status': 'success',
                    'message': 'Firewall restarted successfully',
                    'timestamp': datetime.now().isoformat()
                }
            else:
                return {
                    'status': 'error',
                    'message': f'Failed to restart firewall: {result.stderr}'
                }

        except Exception as e:
            logger.error(f"Error restarting firewall: {e}")
            return {'status': 'error', 'message': str(e)}

    # HTTP polling methods removed - WebSocket only mode

    async def update_client_files(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Update local client .py files from HQ payload and optionally restart."""
        try:
            files = params.get('files', [])
            if not files:
                return {"status": "error", "message": "No files provided"}

            updated = []
            for f in files:
                name = f.get('name') or os.path.basename(f.get('path', ''))
                target = f.get('target') or ("/usr/local/bin/" + name)
                content_b64 = f.get('content_b64')
                mode = f.get('mode', '0644')
                if not content_b64:
                    continue
                data = base64.b64decode(content_b64)
                # Ensure dir exists
                os.makedirs(os.path.dirname(target), exist_ok=True)
                # Write atomically
                tmp_path = target + ".tmp"
                with open(tmp_path, 'wb') as out:
                    out.write(data)
                os.replace(tmp_path, target)
                # Permissions
                try:
                    perm = int(mode, 8)
                    os.chmod(target, perm)
                except Exception:
                    pass
                updated.append(target)

            # Restart if requested
            restart = params.get('restart', True)
            restarted = False
            if restart:
                # Prefer restart script if present
                if os.path.exists('/usr/local/bin/restart_client.sh'):
                    try:
                        subprocess.Popen(['sh', '-c', '/usr/local/bin/restart_client.sh >/dev/null 2>&1 &'])
                        restarted = True
                    except Exception as e:
                        logger.error(f"Failed to invoke restart script: {e}")
                else:
                    # Fallback: re-exec self as daemon
                    try:
                        py = shutil.which('python3') or shutil.which('python') or sys.executable
                        subprocess.Popen(['sh', '-c', f'nohup {py} /usr/local/bin/pfsense_client.py --daemon >/dev/null 2>&1 &'])
                        # Exit current process after spawning new one
                        restarted = True
                    except Exception as e:
                        logger.error(f"Failed to re-exec client: {e}")

            return {
                "status": "success",
                "updated_files": updated,
                "restarted": restarted,
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            logger.error(f"Update failed: {e}")
            return {"status": "error", "message": str(e)}

    async def run(self):
        """Main client loop - WebSocket only"""
        logger.info(f"Starting pfSense client {self.client_id} (WebSocket mode)")

        if not WEBSOCKETS_AVAILABLE:
            logger.error("❌ WebSocket library not available! Install with: pip install websockets")
            return

        try:
            while self.running:
                logger.info("Attempting WebSocket connection...")
                if await self.connect_websocket():
                    logger.info("✅ Connected via WebSocket")
                    self.connection_mode = 'websocket'
                    await self.websocket_loop()

                    # If we get here, WebSocket disconnected
                    if self.running:
                        logger.warning(f"WebSocket disconnected, retrying in {self.reconnect_interval} seconds...")
                        await asyncio.sleep(self.reconnect_interval)
                else:
                    logger.error(f"❌ WebSocket connection failed, retrying in {self.reconnect_interval} seconds...")
                    await asyncio.sleep(self.reconnect_interval)

        except KeyboardInterrupt:
            logger.info("Received interrupt signal, shutting down...")
        except Exception as e:
            logger.error(f"Unexpected error in main loop: {e}")
        finally:
            self.running = False
            if self.websocket:
                try:
                    await self.websocket.close()
                except:
                    pass
            logger.info("pfSense client stopped")

def main():
    """Main entry point"""
    import argparse

    parser = argparse.ArgumentParser(description='pfSense Firewall Client')
    parser.add_argument('--config', '-c', default='/usr/local/etc/pfsense_client.yaml',
                       help='Configuration file path')
    parser.add_argument('--daemon', '-d', action='store_true',
                       help='Run as daemon')

    args = parser.parse_args()

    if args.daemon:
        # Simple daemonization that preserves logging
        import os
        import sys

        # Fork to background
        if os.fork() > 0:
            sys.exit(0)  # Parent exits

        # Child continues as daemon
        os.setsid()  # Create new session
        os.chdir('/')  # Change to root directory

        # Redirect stdin/stdout/stderr but keep logging intact
        sys.stdin = open('/dev/null', 'r')
        sys.stdout = open('/dev/null', 'w')
        sys.stderr = open('/dev/null', 'w')

        client = PfSenseClient(args.config)
        asyncio.run(client.run())
    else:
        client = PfSenseClient(args.config)
        asyncio.run(client.run())

if __name__ == '__main__':
    main()