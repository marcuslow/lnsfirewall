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
import psutil
import yaml
import requests
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any
import hashlib
import gzip
import shutil
from glob import glob

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
        self.reconnect_interval = self.config.get('reconnect_interval', 10)  # Used when server is offline/unreachable
        self.idle_poll_interval = self.config.get('idle_poll_interval', 1)   # Used when server is online and client idle
        self.registered = False
        self.running = True

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

    def post(self, path: str, payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        url = self.hq_url.rstrip('/') + path
        try:
            resp = requests.post(url, json=payload, timeout=30)
            if resp.status_code == 200:
                return resp.json()
            else:
                logger.error(f"HTTP {resp.status_code} for {url}: {resp.text}")
        except Exception as e:
            logger.error(f"HTTP POST error to {url}: {e}")
        return None

    def get(self, path: str) -> Optional[Dict[str, Any]]:
        url = self.hq_url.rstrip('/') + path
        try:
            resp = requests.get(url, timeout=30)
            if resp.status_code == 200:
                return resp.json()
            else:
                logger.error(f"HTTP {resp.status_code} for {url}: {resp.text}")
        except Exception as e:
            logger.error(f"HTTP GET error to {url}: {e}")
        return None

    def register(self) -> bool:
        payload = {
            'client_id': self.client_id,
            'client_name': self.client_name,
            'hostname': self.get_pfsense_hostname() or 'unknown'
        }
        res = self.post('/register', payload)
        if res and res.get('registered'):
            logger.info(f"Registered with HQ as {self.client_name} ({self.client_id})")
            self.registered = True
            return True
        self.registered = False
        return False

    def heartbeat(self):
        self.post('/heartbeat', {'client_id': self.client_id})

    def poll_commands(self) -> List[Dict[str, Any]]:
        res = self.post('/poll', {'client_id': self.client_id})
        if res and isinstance(res.get('commands'), list):
            return res['commands']
        return []

    def send_response(self, command_id: Optional[str], data: Dict[str, Any]):
        payload = {
            'client_id': self.client_id,
            'command_id': command_id,
            'data': data
        }
        self.post('/response', payload)

    async def send_message(self, message: Dict[str, Any]):
        """Send message to HQ server"""
        try:
            if self.websocket:
                await self.websocket.send(json.dumps(message))
        except Exception as e:
            logger.error(f"Error sending message: {e}")

    async def handle_command(self, command: Dict[str, Any]) -> Dict[str, Any]:
        """Handle incoming command from HQ"""
        cmd_type = command.get('type')
        cmd_id = command.get('id', 'unknown')

        logger.info(f"Received command: {cmd_type} (ID: {cmd_id})")

        try:
            if cmd_type == 'get_logs':
                return await self.get_firewall_logs(command.get('params', {}))
            elif cmd_type == 'get_status':
                return await self.get_system_status()
            elif cmd_type == 'get_rules':
                return await self.get_firewall_rules()
            elif cmd_type == 'set_rules':
                return await self.set_firewall_rules(command.get('params', {}))
            elif cmd_type == 'restart_firewall':
                return await self.restart_firewall()
            elif cmd_type == 'ping':
                return {'status': 'success', 'message': 'pong', 'timestamp': datetime.now().isoformat()}
            else:
                return {'status': 'error', 'message': f'Unknown command type: {cmd_type}'}
        except Exception as e:
            logger.error(f"Error handling command {cmd_type}: {e}")
            return {'status': 'error', 'message': str(e)}

    async def get_firewall_logs(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Collect firewall logs from specified date range"""
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

            for log_file in log_files:
                if os.path.exists(log_file):
                    file_logs = self.parse_log_file(log_file, start_date)
                    logs_data.extend(file_logs)
                    total_size += os.path.getsize(log_file)

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
            rules_file = '/cf/conf/config.xml'
            if not os.path.exists(rules_file):
                return {'status': 'error', 'message': 'pfSense config file not found'}

            with open(rules_file, 'r') as f:
                config_content = f.read()

            # Extract rules section (simplified XML parsing)
            import re
            rules_match = re.search(r'<filter>(.*?)</filter>', config_content, re.DOTALL)
            if rules_match:
                rules_xml = rules_match.group(1)
            else:
                rules_xml = ""

            return {
                'status': 'success',
                'rules_xml': rules_xml,
                'config_size': len(config_content),
                'timestamp': datetime.now().isoformat()
            }

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

    async def poll_loop(self):
        """HTTP polling loop for commands"""
        logger.info("Starting HTTP polling loop")

        last_heartbeat = time.time()
        busy = False  # whether we are currently executing commands

        while self.running:
            try:
                # Attempt to (re)register every reconnect_interval until success
                if not self.registered:
                    ok = self.register()
                    if not ok:
                        logger.warning("HQ offline/unreachable; retrying registration soon")
                        await asyncio.sleep(self.reconnect_interval)
                        continue

                # Heartbeat every 30s
                if time.time() - last_heartbeat > 30:
                    self.heartbeat()
                    last_heartbeat = time.time()

                # Poll for commands
                commands = self.poll_commands() or []
                if commands:
                    busy = True
                    for cmd in commands:
                        response = await self.handle_command(cmd)
                        self.send_response(cmd.get('id'), response)
                    # After executing, immediately poll again quickly
                    await asyncio.sleep(self.idle_poll_interval)
                    busy = False
                else:
                    # No commands; when online and idle, poll faster (1s)
                    await asyncio.sleep(self.idle_poll_interval)
            except Exception as e:
                logger.error(f"Error in poll loop: {e}")
                # Reset registration state on error and back off to reconnect_interval
                self.registered = False
                await asyncio.sleep(self.reconnect_interval)

    async def send_heartbeat(self):
        """Send periodic heartbeat to HQ"""
        while self.running and self.websocket:
            try:
                await asyncio.sleep(30)  # Send heartbeat every 30 seconds
                if self.websocket:
                    heartbeat = {
                        'type': 'heartbeat',
                        'client_id': self.client_id,
                        'timestamp': datetime.now().isoformat()
                    }
                    await self.send_message(heartbeat)
            except Exception as e:
                logger.error(f"Error sending heartbeat: {e}")
                break

    async def run(self):
        """Main client loop (HTTP polling)"""
        logger.info(f"Starting pfSense client {self.client_id} (HTTP mode)")
        try:
            await self.poll_loop()
        except KeyboardInterrupt:
            logger.info("Received interrupt signal, shutting down...")
        except Exception as e:
            logger.error(f"Unexpected error in main loop: {e}")
        finally:
            self.running = False
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
        # Simple daemonization
        import daemon
        with daemon.DaemonContext():
            client = PfSenseClient(args.config)
            asyncio.run(client.run())
    else:
        client = PfSenseClient(args.config)
        asyncio.run(client.run())

if __name__ == '__main__':
    main()