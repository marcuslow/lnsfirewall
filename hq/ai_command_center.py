#!/usr/bin/env python3
"""
AI Command Center for Firewall Management System
Provides AI-powered interface for managing pfSense firewalls through OpenAI
"""

import asyncio
import json
import logging
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import openai
import aiosqlite
import gzip
import base64
from dotenv import load_dotenv
import requests
import re

# Local RQE (Rules Query Engine)
try:
    from rqe import RulesQueryEngine
except Exception:
    RulesQueryEngine = None  # Will handle gracefully at call site

# Local LQE (Logs Query Engine)
try:
    from lqe import LogQueryEngine
except Exception:
    LogQueryEngine = None

# Configure logging (will be reconfigured in main() based on verbose flag)
logging.basicConfig(
    level=logging.WARNING,  # Default to WARNING to hide debug info
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)
# Resolve a single, absolute DB path shared with the server
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # repo root
DEFAULT_DB_PATH = os.getenv('HQ_DB_PATH', os.path.join(BASE_DIR, 'hq_database.db'))


class AICommandCenter:
    def __init__(self, hq_url: str, openai_api_key: str, db_path: str = DEFAULT_DB_PATH, verbose: bool = False):
        self.hq_url = hq_url.rstrip('/')
        self.db_path = db_path or DEFAULT_DB_PATH
        self.openai_client = openai.OpenAI(api_key=openai_api_key)
        self.verbose = verbose
        self.conversation_history = []
        # Remember last requested logs window per client for better defaults
        self.last_logs_request_days: Dict[str, int] = {}

        # Define function tools for OpenAI
        self.function_tools = [
            {
                "type": "function",
                "function": {
                    "name": "get_client_status",
                    "description": "Get status information for all connected firewall clients or a specific client",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "client_id": {
                                "type": "string",
                                "description": "Optional specific client ID or name to get status for"
                            }
                        }
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "request_client_logs",
                    "description": "Request log collection from one or more clients (no logs content returned to AI)",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "client_id": {
                                "type": "string",
                                "description": "Client ID/name, comma-separated list, or 'all'"
                            },
                            "days": {
                                "type": "integer",
                                "description": "Number of days of logs to collect (default: 7, max: 90)",
                                "default": 7
                            }
                        },
                        "required": ["client_id"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "get_command_status",
                    "description": "Get the current status/progress of a previously enqueued command by command_id",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "command_id": {"type": "string", "description": "Command ID returned by a previous request"}
                        },
                        "required": ["command_id"]
                    }
                }
            },

            {
                "type": "function",
                "function": {
                    "name": "get_firewall_rules",
                    "description": "Get firewall rules from a client (uses cache if recent, fetches fresh if needed). Use this for initial rule retrieval.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "client_id": {
                                "type": "string",
                                "description": "Client ID or name to get rules from"
                            }
                        },
                        "required": ["client_id"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "get_rules_status",
                    "description": "Get the status and metadata of the latest ingested ruleset for a client",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "client_id": {
                                "type": "string",
                                "description": "Client ID or name to check rules status for"
                            }
                        },
                        "required": ["client_id"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "query_cached_rules",
                    "description": "Query and analyze cached firewall rules without fetching fresh data. Use this to search/analyze rules that were already retrieved.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "client_id": {
                                "type": "string",
                                "description": "Client ID or name to query cached rules for"
                            },
                            "query": {
                                "type": "string",
                                "description": "What to search for in the rules (e.g., 'port forwarding', 'SSH access', 'port 80')"
                            }
                        },
                        "required": ["client_id", "query"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "push_rules",
                    "description": "Push a specific ruleset to a client (enforces 6-hour freshness check)",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "client_id": {
                                "type": "string",
                                "description": "Client ID or name to push rules to"
                            },
                            "ruleset_id": {
                                "type": "string",
                                "description": "Ruleset ID to push (must be the latest for the client)"
                            }
                            },
                            "required": ["client_id", "ruleset_id"]
                        }
                    }
                },
                {
                    "type": "function",
                    "function": {
                        "name": "query_logs",
                        "description": "Query and summarize locally stored firewall logs without sending raw logs to AI.",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "client_id": {"type": "string", "description": "Client ID or name to query logs for"},
                                "query": {"type": "string", "description": "What to look for (e.g., 'summary', 'blocked', 'port 22', 'ssh', 'ip 1.2.3.4')"},
                                "days": {"type": "integer", "description": "Lookback window in days (default: 7)", "default": 7},
                                "top_n": {"type": "integer", "description": "How many top items to return in summaries (default: 10)", "default": 10}
                            },
                            "required": ["client_id", "query"]
                        }
                    }
                },
                {
                    "type": "function",
                    "function": {
                        "name": "get_system_health",
                        "description": "Get comprehensive system health information for a firewall client including uptime, CPU, memory, disk usage, and network stats",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "client_id": {
                                    "type": "string",
                                    "description": "Client ID or client name to get health info for"
                                }
                            },
                            "required": ["client_id"]
                        }
                    }
                },
                {
                    "type": "function",
                    "function": {
                        "name": "perform_risk_assessment",
                        "description": "Perform a comprehensive security risk assessment on a client: checks health, ensures recent logs, analyzes for threats (blocked events, brute-force, anomalies), and provides a structured report.",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "client_id": {"type": "string", "description": "Client ID or name"},
                                "days": {"type": "integer", "description": "Log lookback days (default: 7)", "default": 7},
                                "force_refresh": {"type": "boolean", "description": "Force fresh log request (default: False)", "default": False}
                            },
                            "required": ["client_id"]
                        }
                    }
                },
                {
                    "type": "function",
                    "function": {
                        "name": "get_logs_status",
                        "description": "Check log recency and status for a client to determine if fresh logs are needed",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "client_id": {"type": "string", "description": "Client ID or name"}
                            },
                            "required": ["client_id"]
                        }
                    }
                }
        ]
    def _truncate_string(self, s: str, max_len: int = 4000) -> str:
        if not isinstance(s, str):
            return s
        if len(s) <= max_len:
            return s
        head = s[:2000]
        tail = s[-500:]
        return f"[TRUNCATED {len(s)} chars] " + head + " ... " + tail

    def _sanitize_tool_result(self, result: Any) -> Any:
        try:
            if isinstance(result, dict):
                # Copy and truncate potentially large fields
                res = dict(result)
                big_fields = [
                    'rules_xml', 'config_xml', 'log_data', 'content', 'data'
                ]
                for f in big_fields:
                    if f in res and isinstance(res[f], str):
                        res[f] = self._truncate_string(res[f], 4000)
                # Never include raw log entries in AI context; summarize instead
                if 'logs' in res and isinstance(res['logs'], list):
                    summarized_logs = []
                    total_entries = 0
                    for item in res['logs']:
                        try:
                            entries = item.get('entries', []) if isinstance(item, dict) else []
                            total_entries += len(entries) if isinstance(entries, list) else 0
                            summarized_logs.append({
                                k: v for k, v in item.items() if k in ('client_id', 'timestamp', 'size_bytes')
                            } | {'entry_count': len(entries) if isinstance(entries, list) else 0})
                        except Exception:
                            continue
                    res['logs_summary'] = summarized_logs
                    res.pop('logs', None)
                    # Include totals if present
                    if 'total_entries' in res:
                        res['total_entries'] = total_entries
                # As a safeguard, cap overall JSON size
                payload = json.dumps(res)
                if len(payload) > 6000:
                    # Keep only keys and sizes
                    summary = {k: (len(v) if isinstance(v, str) else v) for k, v in res.items()}
                    return {
                        'success': res.get('success', True),
                        'note': 'Payload truncated for AI context limits',
                        'summary': summary
                    }
                return res
            return result
        except Exception:
            return {'success': False, 'note': 'Failed to sanitize tool result'}




    async def get_client_status(self, client_id: Optional[str] = None) -> Dict[str, Any]:
        """Get status of clients via HTTP API"""
        try:
            res = requests.get(f"{self.hq_url}/clients", timeout=30)
            res.raise_for_status()
            data = res.json()
            clients = data.get('clients', {})

            if not client_id or client_id.lower() == 'all':
                return {"success": True, "data": data}

            # Handle comma-separated list
            ids = [c.strip() for c in client_id.split(',')] if ',' in client_id else [client_id]
            results = {}
            not_found = []

            # Match by client_id directly, or by client_name
            name_to_id = {v.get('client_name', ''): k for k, v in clients.items()}

            for cid in ids:
                if cid in clients:
                    results[cid] = clients[cid]
                elif cid in name_to_id:
                    results[name_to_id[cid]] = clients[name_to_id[cid]]
                else:
                    not_found.append(cid)

            if len(ids) == 1:
                if not_found:
                    return {"success": False, "error": f"Client '{ids[0]}' not found. Available: {list(clients.keys())}"}
                # Return the first (and only) entry in results
                only_id = next(iter(results.keys()))
                return {"success": True, "data": results[only_id]}

            # Multiple
            resp = {"success": True, "data": {"multiple_clients": True, "clients": results, "total_requested": len(ids)}}
            if not_found:
                resp["warning"] = f"Not found: {not_found}"
            return resp
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def request_client_logs(self, client_id: str, days: int) -> Dict[str, Any]:
        """Request logs: enqueue HTTP commands for one/many/all clients"""
        try:
            days = min(days, 90)

            # Get current clients
            res = requests.get(f"{self.hq_url}/clients", timeout=30)
            res.raise_for_status()
            clients = res.json().get('clients', {})
            name_to_id = {v.get('client_name', ''): k for k, v in clients.items()}

            def enqueue(cid: str) -> Optional[str]:
                try:
                    r = requests.post(f"{self.hq_url}/command", json={"client_id": cid, "command_type": "get_logs", "params": {"days": days}}, timeout=30)
                    if r.status_code == 200:
                        return r.json().get('command_id')
                except Exception as e:
                    logger.error(f"Enqueue error for {cid}: {e}")
                return None

            if client_id.lower() == 'all':
                ids = list(clients.keys())
                ids.sort()
            else:
                ids = [c.strip() for c in client_id.split(',')] if ',' in client_id else [client_id]
                # Normalize
                norm_ids = []
                not_found = []
                for cid in ids:
                    if cid in clients:
                        norm_ids.append(cid)
                    elif cid in name_to_id:
                        norm_ids.append(name_to_id[cid])
                    else:
                        not_found.append(cid)
                if not_found:
                    return {"success": False, "error": f"Clients not found: {not_found}. Available: {list(clients.keys())}"}



                ids = norm_ids

            results = {}
            for cid in ids:
                cmd_id = enqueue(cid)
                results[cid] = {"command_id": cmd_id, "days": days}
                # Remember the window we just requested for this client
                try:
                    self.last_logs_request_days[cid] = days
                except Exception:
                    pass

            # If only one client, show progress automatically
            if len(results) == 1:
                cmd_id = list(results.values())[0]["command_id"]
                if cmd_id:
                    progress_info = await self._monitor_command_progress(cmd_id, client_id)
                    return {"success": True, "message": f"Log collection completed for {client_id}", "progress": progress_info, "clients": results}

            return {"success": True, "message": f"Log collection requested from {len(ids)} client(s)", "clients": results}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def get_firewall_rules(self, client_id: str) -> Dict[str, Any]:
        """Get firewall rules from client and wait for response"""
        try:
            # First, get the actual client ID if a client name was provided
            actual_client_id = client_id
            res = requests.get(f"{self.hq_url}/clients", timeout=30)
            res.raise_for_status()
            clients = res.json().get('clients', {})

            # Check if client_id is actually a client name, and get the real ID
            if client_id not in clients:
                # Look for client by name
                for cid, client_info in clients.items():
                    if client_info.get('client_name') == client_id:
                        actual_client_id = cid
                        logger.info(f"Mapped client name '{client_id}' to actual client ID '{actual_client_id}'")



                        break
                else:
                    return {"success": False, "error": f"Client '{client_id}' not found"}

            # Check if we have recent rules (less than 5 minutes old)
            try:
                status_res = requests.get(f"{self.hq_url}/rules/status", params={"client_id": actual_client_id}, timeout=10)
                if status_res.status_code == 200:
                    status_data = status_res.json()
                    if status_data.get("success") and status_data.get("age_minutes", 999) < 5:
                        # Get the actual rules XML from the database
                        async with aiosqlite.connect(self.db_path) as db:
                            cursor = await db.execute('''
                                SELECT rules_xml FROM rulesets
                                WHERE client_id = ? AND ruleset_id = ?
                            ''', (actual_client_id, status_data.get("ruleset_id")))
                            rules_result = await cursor.fetchone()

                            rules_xml = rules_result[0] if rules_result else ""

                        return {
                            "success": True,
                            "message": f"Using cached rules for client {client_id} (age: {status_data.get('age_minutes', 0):.1f} minutes)",
                            "rules_count": status_data.get("rules_count", 0),
                            "rules_xml": rules_xml,
                            "ruleset_id": status_data.get("ruleset_id"),
                            "cached": True,
                            "age_minutes": status_data.get("age_minutes", 0)
                        }
            except Exception as e:
                logger.debug(f"Could not check cached rules: {e}")

            # No recent rules found, fetch fresh ones
            logger.info(f"Fetching fresh rules for client {client_id}")
            # Send the command using the provided client_id (name or ID)
            r = requests.post(f"{self.hq_url}/command", json={"client_id": client_id, "command_type": "get_rules"}, timeout=30)
            r.raise_for_status()
            command_id = r.json().get('command_id')

            if not command_id:
                return {"success": False, "error": "No command ID returned"}

            # Wait for the response using the ACTUAL client ID for database lookup
            import time
            max_wait = 30  # seconds
            start_time = time.time()

            while time.time() - start_time < max_wait:
                try:
                    # Check if response is available in database using ACTUAL client ID
                    async with aiosqlite.connect(self.db_path) as db:
                        cursor = await db.execute('''
                            SELECT status, response_data FROM commands
                            WHERE id = ?
                        ''', (command_id,))
                        result = await cursor.fetchone()

                        if result and result[0] == 'completed':
                            response_data = json.loads(result[1]) if result[1] else {}
                            if response_data.get('status') == 'success':
                                rules_xml = response_data.get('rules_xml', '')
                                try:
                                    ing = requests.post(f"{self.hq_url}/rules/ingest", json={
                                        "client_id": actual_client_id,
                                        "rules_xml": rules_xml,
                                        "command_id": command_id
                                    }, timeout=30)
                                    ing.raise_for_status()
                                    ingest_info = ing.json()
                                except Exception as e:
                                    ingest_info = {"success": False, "error": str(e)}
                                return {
                                    "success": True,
                                    "message": f"Fresh firewall rules retrieved and indexed for {client_id}",
                                    "ruleset_id": ingest_info.get("ruleset_id"),
                                    "ingested_at": ingest_info.get("ingested_at"),
                                    "rule_count": ingest_info.get("rule_count"),
                                    "size_bytes": ingest_info.get("size_bytes"),
                                    "cached": False
                                }
                            else:
                                return {"success": False, "error": response_data.get('message', 'Unknown error')}

                except Exception as e:
                    logger.error(f"Error checking command response: {e}")

                # Wait a bit before checking again
                await asyncio.sleep(1)

            return {"success": False, "error": f"Timeout waiting for response from {client_id}"}

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def update_firewall_rules(self, client_id: str, rules_xml: str) -> Dict[str, Any]:
        """Enqueue set_rules with rules_xml to the client via HTTP"""
        try:
            r = requests.post(f"{self.hq_url}/command", json={"client_id": client_id, "command_type": "set_rules", "params": {"rules_xml": rules_xml}}, timeout=60)
            r.raise_for_status()
            return {"success": True, "message": f"Firewall rules update sent to client {client_id}", "command_id": r.json().get('command_id')}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def restart_firewall(self, client_id: str) -> Dict[str, Any]:
        """Enqueue restart_firewall for client via HTTP"""
        try:
            r = requests.post(f"{self.hq_url}/command", json={"client_id": client_id, "command_type": "restart_firewall"}, timeout=30)
            r.raise_for_status()
            return {"success": True, "message": f"Firewall restart command sent to client {client_id}", "command_id": r.json().get('command_id')}
        except Exception as e:
            return {"success": False, "error": str(e)}


    async def get_command_status(self, command_id: str) -> Dict[str, Any]:
        """Query HQ for the status/progress of a command"""
        try:
            res = requests.get(f"{self.hq_url}/command/status", params={"command_id": command_id}, timeout=15)
            if res.status_code != 200:
                return {"success": False, "error": f"Server returned {res.status_code}: {res.text}"}
            data = res.json()
            # Sanitize potentially large fields
            if isinstance(data, dict) and isinstance(data.get("progress"), dict):
                p = dict(data["progress"])  # copy
                # Remove any raw logs if accidentally present
                if "logs" in p:
                    p["logs"] = "[omitted]"
                data["progress"] = p
            return {"success": True, "data": data}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def _monitor_command_progress(self, command_id: str, client_name: str) -> Dict[str, Any]:
        """Monitor command progress and display updates"""
        import time

        print(f"\n📊 Monitoring progress for {client_name} (command: {command_id[:8]}...)")

        max_wait = 120  # 2 minutes max
        start_time = time.time()
        last_progress = -1

        while time.time() - start_time < max_wait:
            try:
                status_result = await self.get_command_status(command_id)
                if not status_result.get("success"):
                    break

                data = status_result.get("data", {})
                status = data.get("status", "unknown")
                progress_data = data.get("progress", {})

                if status == "completed":
                    print(f"✅ Log collection completed for {client_name}")
                    return {"status": "completed", "final_progress": progress_data}
                elif status == "in_progress" and progress_data:
                    progress_pct = progress_data.get("progress_pct", 0)
                    files_done = progress_data.get("files_done", 0)
                    files_total = progress_data.get("files_total", 0)
                    current_file = progress_data.get("current_file", "")

                    # Only show progress if it changed
                    if progress_pct != last_progress:
                        bar_length = 20
                        filled_length = int(bar_length * progress_pct // 100)
                        bar = "█" * filled_length + "░" * (bar_length - filled_length)
                        print(f"\r🔄 [{bar}] {progress_pct}% ({files_done}/{files_total}) {current_file}", end="", flush=True)
                        last_progress = progress_pct

                time.sleep(1)  # Poll every second

            except Exception as e:
                print(f"\n❌ Error monitoring progress: {e}")
                break

        print(f"\n⏰ Progress monitoring timed out after {max_wait} seconds")
        return {"status": "timeout", "elapsed": time.time() - start_time}

    async def get_rules_status(self, client_id: str) -> Dict[str, Any]:
        """Get latest rules status for a client (age, ruleset_id, counts)"""
        try:
            # Map name -> actual ID
            actual_client_id = client_id
            res = requests.get(f"{self.hq_url}/clients", timeout=30)
            res.raise_for_status()
            clients = res.json().get('clients', {})
            if client_id not in clients:
                for cid, info in clients.items():
                    if info.get('client_name') == client_id:
                        actual_client_id = cid
                        break
                else:
                    return {"success": False, "error": f"Client '{client_id}' not found"}



            # Fetch status
            s = requests.get(f"{self.hq_url}/rules/status", params={"client_id": actual_client_id}, timeout=30)
            s.raise_for_status()
            return s.json()
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def get_system_health(self, client_id: str) -> Dict[str, Any]:
        """Get comprehensive system health information for a client"""
        try:
            # Get current clients to find the actual client ID and health data
            res = requests.get(f"{self.hq_url}/clients", timeout=30)
            res.raise_for_status()
            clients = res.json().get('clients', {})

            # Find client by ID or name
            target_client = None
            actual_client_id = client_id

            if client_id in clients:
                target_client = clients[client_id]
            else:
                # Look for client by name
                for cid, client_info in clients.items():
                    if client_info.get('client_name') == client_id:
                        target_client = client_info
                        actual_client_id = cid
                        break

            if not target_client:
                return {"success": False, "error": f"Client '{client_id}' not found"}

            # Get system health from the stored data
            system_health = target_client.get('system_health', {})

            if not system_health:
                return {"success": False, "error": f"No system health data available for '{client_id}'. Client may need to reconnect."}

            # Format the health data for display
            health_status = system_health.get('status', 'unknown')
            if health_status != 'success':
                return {"success": False, "error": f"System health check failed: {system_health.get('message', 'Unknown error')}"}

            # Extract and format key metrics
            uptime_data = system_health.get('uptime', {})
            memory_data = system_health.get('memory', {})
            disk_data = system_health.get('disk', {})
            cpu_data = system_health.get('cpu', {})

            # Format uptime
            uptime_seconds = uptime_data.get('uptime_seconds', 0)
            uptime_days = uptime_seconds // 86400
            uptime_hours = (uptime_seconds % 86400) // 3600
            uptime_minutes = (uptime_seconds % 3600) // 60

            # Format memory
            memory_total_gb = memory_data.get('total', 0) / (1024**3)
            memory_used_gb = memory_data.get('used', 0) / (1024**3)
            memory_percent = memory_data.get('percent', 0)

            # Format disk
            disk_total_gb = disk_data.get('total', 0) / (1024**3)
            disk_used_gb = disk_data.get('used', 0) / (1024**3)
            disk_percent = disk_data.get('percent', 0)

            return {
                "success": True,
                "client_id": actual_client_id,
                "client_name": target_client.get('client_name', 'unknown'),
                "hostname": target_client.get('hostname', 'unknown'),
                "last_seen": target_client.get('last_seen', 'unknown'),
                "connection_type": target_client.get('connection_type', 'unknown'),
                "health": {
                    "uptime": {
                        "days": uptime_days,
                        "hours": uptime_hours,
                        "minutes": uptime_minutes,
                        "total_seconds": uptime_seconds,
                        "boot_time": uptime_data.get('boot_time', 'unknown')
                    },
                    "memory": {
                        "total_gb": round(memory_total_gb, 2),
                        "used_gb": round(memory_used_gb, 2),
                        "percent": round(memory_percent, 1)
                    },
                    "disk": {
                        "total_gb": round(disk_total_gb, 2),
                        "used_gb": round(disk_used_gb, 2),
                        "percent": round(disk_percent, 1)
                    },
                    "cpu": {
                        "percent": cpu_data.get('percent', 0),
                        "cores": cpu_data.get('count', 0)
                    },
                    "network_interfaces": len(system_health.get('network', {})),
                    "timestamp": system_health.get('timestamp', 'unknown')
                }
            }

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def query_cached_rules(self, client_id: str, query: str) -> Dict[str, Any]:
        """Query cached firewall rules using the local Rules Query Engine (no network)."""
        try:
            if RulesQueryEngine is None:
                return {"success": False, "error": "RulesQueryEngine module not available"}

            # Map name -> actual ID
            actual_client_id = client_id
            res = requests.get(f"{self.hq_url}/clients", timeout=30)
            res.raise_for_status()
            clients = res.json().get('clients', {})
            if client_id not in clients:
                for cid, client_info in clients.items():
                    if client_info.get('client_name') == client_id:
                        actual_client_id = cid



                        break
                else:
                    return {"success": False, "error": f"Client '{client_id}' not found"}

            # Load latest cached rules XML from DB
            async with aiosqlite.connect(self.db_path) as db:
                cur = await db.execute(
                    '''SELECT rules_xml, rule_count, ingested_at, id FROM rulesets WHERE client_id = ? ORDER BY ingested_at DESC LIMIT 1''',
                    (actual_client_id,)
                )
                row = await cur.fetchone()
                if not row:
                    return {"success": False, "error": f"No cached rules found for client {client_id}. Use get_firewall_rules first."}
                rules_xml, rule_count, ingested_at, ruleset_id = row

            # Parse with RQE
            rqe = RulesQueryEngine(rules_xml)
            q = query.lower().strip()

            # Determine intent
            results: Dict[str, Any]
            if any(k in q for k in ["port forwarding", "forwarding", "nat", "redirect"]):
                pf = [rqe._nat_to_dict(n) for n in rqe.list_port_forwarding()]
                results = {"port_forwarding": pf}
            elif any(k in q for k in ["ssh"]):
                results = rqe.find_rules_by_service("ssh")
            elif "https" in q:
                results = rqe.find_rules_by_service("https")
            elif "http" in q:
                results = rqe.find_rules_by_service("http")
            elif "port" in q:
                # Extract first integer from the text
                m = re.search(r"(\d{1,5})", q)
                if m:
                    port = int(m.group(1))
                    results = rqe.find_rules_by_port(port)
                else:
                    results = {"nat": [], "filter": []}
            elif any(k in q for k in ["block", "blocked", "reject"]):
                results = {"blocking": rqe.find_blocking_rules()}
            elif any(k in q for k in ["allow", "allowed", "pass"]):
                results = {"allowed": rqe.find_allowed_rules()}
            elif any(k in q for k in ["ip", "address", "host"]):
                # Try to pull an IP fragment after the word
                m = re.search(r"(\d+\.\d+\.\d+\.\d+|\d+\.\d+\.\d+|\d+\.\d+)", q)
                frag = m.group(1) if m else ""
                results = {"matching": rqe.find_rules_with_ip(frag) if frag else []}
            else:
                # Fallback to summary
                results = {"summary": rqe.summarize()}

            return {
                "success": True,
                "query": query,
                "results": results,
                "counts": {
                    "nat": len(results.get("nat", [])) if isinstance(results.get("nat"), list) else None,
                    "filter": len(results.get("filter", [])) if isinstance(results.get("filter"), list) else None,
                    "blocking": len(results.get("blocking", [])) if isinstance(results.get("blocking"), list) else None,
                    "allowed": len(results.get("allowed", [])) if isinstance(results.get("allowed"), list) else None,
                    "port_forwarding": len(results.get("port_forwarding", [])) if isinstance(results.get("port_forwarding"), list) else None,
                },
                "rule_count": rule_count,
                "ruleset_id": ruleset_id
            }
        except Exception as e:
            return {"success": False, "error": str(e)}






    async def push_rules(self, client_id: str, ruleset_id: str) -> Dict[str, Any]:
        """Push a stored ruleset to a client with freshness guard on server"""
        try:
            # Map name -> actual ID
            actual_client_id = client_id
            res = requests.get(f"{self.hq_url}/clients", timeout=30)
            res.raise_for_status()

            clients = res.json().get('clients', {})
            if client_id not in clients:
                for cid, info in clients.items():
                    if info.get('client_name') == client_id:
                        actual_client_id = cid
                        break
                else:
                    return {"success": False, "error": f"Client '{client_id}' not found"}
            # Push
            p = requests.post(f"{self.hq_url}/rules/push", json={"client_id": actual_client_id, "ruleset_id": ruleset_id}, timeout=60)
            if p.status_code == 409:
                return {"success": False, "error": p.json().get('detail', 'Push blocked'), "blocked": True}
            p.raise_for_status()
            return {"success": True, **p.json(), "client_id": actual_client_id}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def get_stored_logs(self, client_id: Optional[str] = None, days: int = 7) -> Dict[str, Any]:
        """Get stored logs from database"""
        try:
            start_date = datetime.now() - timedelta(days=days)

            async with aiosqlite.connect(self.db_path) as db:
                if client_id:
                    cursor = await db.execute('''
                        SELECT client_id, timestamp, log_data, compressed, size_bytes
                        FROM logs
                        WHERE client_id = ? AND timestamp >= ?
                        ORDER BY timestamp DESC
                    ''', (client_id, start_date))
                else:
                    cursor = await db.execute('''
                        SELECT client_id, timestamp, log_data, compressed, size_bytes
                        FROM logs
                        WHERE timestamp >= ?
                        ORDER BY timestamp DESC
                    ''', (start_date,))

                rows = await cursor.fetchall()

                logs_data = []
                total_size = 0

                for row in rows:
                    client_id_db, timestamp, log_data, compressed, size_bytes = row

                    # Decompress if needed
                    if compressed:
                        try:
                            compressed_data = base64.b64decode(log_data.encode('utf-8'))
                            decompressed_data = gzip.decompress(compressed_data)
                            log_entries = json.loads(decompressed_data.decode('utf-8'))
                        except Exception as e:
                            logger.error(f"Error decompressing logs: {e}")
                            log_entries = []
                    else:
                        log_entries = json.loads(log_data)

                    logs_data.append({
                        'client_id': client_id_db,

                        'timestamp': timestamp,
                        'entries': log_entries,
                        'size_bytes': size_bytes
                    })

                    total_size += size_bytes

                return {
                    "success": True,
                    "logs": logs_data,
                    "total_entries": sum(len(log['entries']) for log in logs_data),
                    "total_size_bytes": total_size,
                    "date_range": f"{start_date.isoformat()} to {datetime.now().isoformat()}"
                }

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def execute_function_call(self, function_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a function call from OpenAI"""
        try:
            if function_name == "get_client_status":
                return await self.get_client_status(arguments.get('client_id'))
            elif function_name == "request_client_logs":
                return await self.request_client_logs(
                    arguments['client_id'],
                    arguments['days']
                )
            elif function_name == "get_command_status":
                return await self.get_command_status(arguments['command_id'])
            elif function_name == "get_firewall_rules":
                return await self.get_firewall_rules(arguments['client_id'])
            elif function_name == "get_rules_status":
                return await self.get_rules_status(arguments['client_id'])
            elif function_name == "get_system_health":
                return await self.get_system_health(arguments['client_id'])
            elif function_name == "query_cached_rules":
                return await self.query_cached_rules(arguments['client_id'], arguments['query'])
            elif function_name == "push_rules":

                return await self.update_firewall_rules(
                    arguments['client_id'],
                    arguments['rules_xml']
                )
            elif function_name == "restart_firewall":
                return await self.restart_firewall(arguments['client_id'])
            elif function_name == "get_stored_logs":
                return await self.get_stored_logs(
                    arguments.get('client_id'),
                    arguments.get('days', 7)
                )
            elif function_name == "query_logs":
                return await self.query_logs(
                    arguments['client_id'],
                    arguments['query'],
                    arguments.get('days'),
                    arguments.get('top_n')
                )
            elif function_name == "perform_risk_assessment":
                return await self.perform_risk_assessment(
                    arguments['client_id'],
                    arguments.get('days', 7),
                    arguments.get('force_refresh', False)
                )
            elif function_name == "get_logs_status":
                return await self.get_logs_status(arguments['client_id'])

            else:
                return {"success": False, "error": f"Unknown function: {function_name}"}

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def query_logs(self, client_id: str, query: str, days: Optional[int] = None, top_n: Optional[int] = None) -> Dict[str, Any]:
        """Query locally stored logs using LogQueryEngine. No raw logs are sent to AI."""
        try:
            if LogQueryEngine is None:
                return {"success": False, "error": "LogQueryEngine module not available"}

            # Default window selection: use last requested for this client, else 7
            effective_days = days if isinstance(days, int) and days > 0 else self.last_logs_request_days.get(client_id, 7)
            effective_top_n = top_n if isinstance(top_n, int) and top_n > 0 else 10

            # Map provided name -> actual ID as needed
            actual_client_id = client_id
            try:
                res = requests.get(f"{self.hq_url}/clients", timeout=30)
                res.raise_for_status()
                clients = res.json().get('clients', {})
                name_to_id = {v.get('client_name', ''): k for k, v in clients.items()}
                if client_id in name_to_id:
                    actual_client_id = name_to_id[client_id]
            except Exception:
                pass

            lqe = LogQueryEngine.from_db(self.db_path, actual_client_id, since_days=effective_days)

            def compact(entries: List[Any]) -> List[Dict[str, Any]]:
                out = []
                for x in entries[:effective_top_n]:
                    out.append({
                        'timestamp': getattr(x, 'timestamp', None),
                        'action': getattr(x, 'action', None),
                        'proto': getattr(x, 'proto', None),
                        'interface': getattr(x, 'interface', None),
                        'src': getattr(x, 'src', None),
                        'src_port': getattr(x, 'src_port', None),
                        'dst': getattr(x, 'dst', None),
                        'dst_port': getattr(x, 'dst_port', None),
                    })
                return out

            q = (query or '').strip().lower()
            results: Dict[str, Any] = {}

            # Intent routing
            if 'summary' in q or q in ('logs', 'log summary'):
                results = {'summary': lqe.summarize(top_n=effective_top_n)}
            elif any(k in q for k in ['blocked', 'block', 'reject']):
                bl = lqe.filter_blocked()
                results = {'blocked_count': len(bl), 'examples': compact(bl)}
            elif any(k in q for k in ['allowed', 'allow', 'pass']):
                al = lqe.filter_allowed()
                results = {'allowed_count': len(al), 'examples': compact(al)}
            elif 'ssh' in q:
                hits = lqe.filter_by_service('ssh')
                results = {'service': 'ssh', 'count': len(hits), 'examples': compact(hits)}
            elif 'https' in q:
                hits = lqe.filter_by_service('https')
                results = {'service': 'https', 'count': len(hits), 'examples': compact(hits)}
            elif 'http' in q:
                hits = lqe.filter_by_service('http')
                results = {'service': 'http', 'count': len(hits), 'examples': compact(hits)}
            elif 'port' in q:
                import re as _re
                m = _re.search(r"(\d{1,5})", q)
                if m:
                    p = int(m.group(1))
                    hits = lqe.filter_by_port(p)
                    results = {'port': p, 'count': len(hits), 'examples': compact(hits)}
                else:
                    results = {'note': 'No port number found in query'}
            elif any(k in q for k in ['ip', 'addr', 'address', 'host']):
                import re as _re
                m = _re.search(r"(\d+\.\d+\.\d+\.\d+|\d+\.\d+\.\d+|\d+\.\d+)", q)
                frag = m.group(1) if m else ''
                hits = lqe.filter_by_ip_fragment(frag) if frag else []
                results = {'ip_fragment': frag, 'count': len(hits), 'examples': compact(hits)}
            elif any(k in q for k in ['risk', 'assessment', 'threat', 'security check', 'anomaly']):
                # Risk assessment: aggregate multiple analyses for comprehensive view
                summary = lqe.summarize(top_n=effective_top_n)
                blocked = lqe.filter_blocked()
                allowed = lqe.filter_allowed()
                ssh_hits = lqe.filter_by_service('ssh')  # Potential brute-force
                http_hits = lqe.filter_by_service('http')  # Web attacks
                https_hits = lqe.filter_by_service('https')  # Secure web traffic

                # Use enhanced LQE methods for better detection
                potential_brute = lqe.detect_brute_force(threshold=5)
                port_scans = lqe.detect_port_scans(threshold=10)
                top_blocked_ips = lqe.get_top_blocked_ips(top_n=effective_top_n)

                # Simple risk scoring heuristic
                blocked_count = len(blocked)
                brute_force_count = len(potential_brute)
                port_scan_count = len(port_scans)

                if blocked_count > 100 or brute_force_count > 10 or port_scan_count > 20:
                    risk_level = 'High'
                elif blocked_count > 10 or brute_force_count > 0 or port_scan_count > 5:
                    risk_level = 'Medium'
                else:
                    risk_level = 'Low'

                # Generate recommendations
                recommendations = []
                if brute_force_count > 0:
                    recommendations.append('Block top suspicious IPs if recurring')
                    recommendations.append('Review rules for authentication ports (SSH, RDP)')
                if port_scan_count > 0:
                    recommendations.append('Investigate potential port scanning activity')
                if blocked_count > 50:
                    recommendations.append('Consider rate limiting or additional blocking rules')
                if top_blocked_ips and top_blocked_ips[0][1] > 20:
                    recommendations.append(f'Investigate top blocked IP: {top_blocked_ips[0][0]} ({top_blocked_ips[0][1]} blocks)')

                results = {
                    'risk_summary': summary,
                    'blocked_events': {'count': len(blocked), 'examples': compact(blocked)},
                    'allowed_events': {'count': len(allowed), 'examples': compact(allowed)},
                    'potential_brute_force': {'count': brute_force_count, 'examples': compact(potential_brute)},
                    'potential_port_scans': {'count': port_scan_count, 'examples': compact(port_scans)},
                    'web_traffic': {'http_count': len(http_hits), 'https_count': len(https_hits)},
                    'top_blocked_ips': top_blocked_ips,
                    'risk_level': risk_level,
                    'recommendations': recommendations,
                    'analysis_period_days': effective_days
                }
            else:
                results = {'summary': lqe.summarize(top_n=effective_top_n)}

            return {
                'success': True,
                'query': query,
                'days': effective_days,
                'client_id': actual_client_id,
                'results': results
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}

    async def perform_risk_assessment(self, client_id: str, days: int = 7, force_refresh: bool = False) -> Dict[str, Any]:
        """Perform comprehensive security risk assessment on a client"""
        try:
            # Step 1: Get system health
            health = await self.get_client_status(client_id)
            if not health.get('success'):
                return health  # Propagate error

            # Step 2: Check for recent logs (e.g., last ingestion within 1 day)
            async with aiosqlite.connect(self.db_path) as db:
                # Map provided name -> actual ID as needed
                actual_client_id = client_id
                try:
                    res = requests.get(f"{self.hq_url}/clients", timeout=30)
                    res.raise_for_status()
                    clients = res.json().get('clients', {})
                    name_to_id = {v.get('client_name', ''): k for k, v in clients.items()}
                    if client_id in name_to_id:
                        actual_client_id = name_to_id[client_id]
                except Exception:
                    pass

                cursor = await db.execute("SELECT MAX(timestamp) FROM logs WHERE client_id = ?", (actual_client_id,))
                row = await cursor.fetchone()
                last_log_ts = row[0] if row and row[0] else None
                last_log_dt = datetime.fromisoformat(last_log_ts) if last_log_ts else None

            # Step 3: Request fresh logs if needed
            if force_refresh or not last_log_dt or (datetime.now() - last_log_dt) > timedelta(days=1):
                log_req = await self.request_client_logs(client_id, days)
                if not log_req.get('success'):
                    return log_req
                # Note: In production, you might want to wait for completion here
                # For now, we'll proceed with existing logs and note if refresh was attempted

            # Step 4: Query logs for risk indicators
            risk_query = await self.query_logs(client_id, 'risk assessment', days=days, top_n=10)
            if not risk_query.get('success'):
                return risk_query

            # Step 5: Synthesize assessment
            results = risk_query['results']
            health_data = health.get('data', {})

            # Extract key metrics
            blocked_count = results.get('blocked_events', {}).get('count', 0)
            brute_force_count = results.get('potential_brute_force', {}).get('count', 0)
            top_blocked_ips = results.get('top_blocked_ips', [])
            risk_level = results.get('risk_level', 'Unknown')

            # Generate comprehensive findings
            key_findings = [
                f"Blocked events: {blocked_count}",
                f"Potential brute-force attempts: {brute_force_count}",
                f"Risk level: {risk_level}"
            ]

            if top_blocked_ips:
                key_findings.append(f"Top blocked IP: {top_blocked_ips[0][0]} ({top_blocked_ips[0][1]} blocks)")

            # System health findings
            if isinstance(health_data, dict):
                memory_usage = health_data.get('memory_usage_percent', 0)
                disk_usage = health_data.get('disk_usage_percent', 0)
                if memory_usage > 80:
                    key_findings.append(f"High memory usage: {memory_usage}%")
                if disk_usage > 80:
                    key_findings.append(f"High disk usage: {disk_usage}%")

            assessment = {
                'client_id': actual_client_id,
                'assessment_time': datetime.now().isoformat(),
                'analysis_period_days': days,
                'system_health': health_data,
                'log_analysis': results,
                'risk_level': risk_level,
                'key_findings': key_findings,
                'recommendations': results.get('recommendations', []),
                'log_freshness': {
                    'last_log_time': last_log_ts,
                    'refresh_attempted': force_refresh or (not last_log_dt or (datetime.now() - last_log_dt) > timedelta(days=1))
                }
            }

            return {'success': True, 'assessment': assessment}

        except Exception as e:
            return {'success': False, 'error': str(e)}

    async def get_logs_status(self, client_id: str) -> Dict[str, Any]:
        """Check log recency and status for a client"""
        try:
            # Map provided name -> actual ID as needed
            actual_client_id = client_id
            try:
                res = requests.get(f"{self.hq_url}/clients", timeout=30)
                res.raise_for_status()
                clients = res.json().get('clients', {})
                name_to_id = {v.get('client_name', ''): k for k, v in clients.items()}
                if client_id in name_to_id:
                    actual_client_id = name_to_id[client_id]
            except Exception:
                pass

            async with aiosqlite.connect(self.db_path) as db:
                cursor = await db.execute("""
                    SELECT timestamp, size_bytes, compressed, COUNT(*) as log_count
                    FROM logs WHERE client_id = ?
                    ORDER BY timestamp DESC LIMIT 1
                """, (actual_client_id,))
                row = await cursor.fetchone()

                if not row or not row[0]:
                    return {'success': False, 'error': 'No logs found for client'}

                ts, size, compressed, log_count = row
                age_hours = (datetime.now() - datetime.fromisoformat(ts)).total_seconds() / 3600

                return {
                    'success': True,
                    'client_id': actual_client_id,
                    'last_ingested': ts,
                    'age_hours': age_hours,
                    'size_bytes': size,
                    'compressed': bool(compressed),
                    'total_log_entries': log_count
                }
        except Exception as e:
            return {'success': False, 'error': str(e)}

    async def chat_with_ai(self, user_message: str) -> str:
        """Chat with AI assistant for firewall management"""
        try:
            # Add user message to conversation history
            self.conversation_history.append({
                "role": "user",
                "content": user_message
            })

            # System message for context
            system_message = {
                "role": "system",
                "content": """You are an AI assistant for managing pfSense firewalls. You have access to several functions to:

1. Get status of connected firewall clients (uptime, memory, disk, network stats)
2. Request firewall logs from clients for analysis - includes detailed parsing of:
   - Filter logs (firewall rules, blocked/allowed traffic)
   - pfBlockerNG logs (IP blocking, threat intelligence)
   - System logs (general system events)
3. Get and update firewall rules
4. Restart firewall services when needed
5. Retrieve previously stored logs from the database
6. Query stored logs for summaries, filtered events (e.g., blocked, by port/service/IP)

Log Analysis Capabilities:
- Parse pfSense filter logs with rule numbers, interfaces, actions, protocols, IPs
- Parse pfBlockerNG logs with block lists, threat categories, source/destination details
- Generate statistics: blocked vs allowed connections, top source/destination IPs, protocol distribution
- Track security events and potential threats

Risk Assessment Capabilities:
- When asked for a risk assessment, threat analysis, or security check:
  - First, check system health with get_client_status.
  - Ensure recent logs are available (e.g., request_client_logs if logs are older than 1 day).
  - Use query_logs with targeted queries like 'summary', 'blocked', 'ssh' (for brute-force), 'top blocked IPs', or custom (e.g., 'multiple blocks from same IP on port 22').
  - Analyze for common risks: high blocked traffic (potential attacks), repeated failures on auth ports (brute-force), unusual protocols/ports, top suspicious IPs (e.g., many connections from one source indicating DDoS or scanning).
  - Provide a structured assessment: Low/Medium/High risk level, key findings, recommendations (e.g., block IP, update rules).
  - Prioritize accuracy; if data is insufficient, request more logs or clarification.

When users ask about firewall management, use the appropriate functions to help them. Always be clear about what actions you're taking and ask for confirmation before making changes that could affect firewall security or connectivity.

Current capabilities:
- Monitor multiple pfSense firewall clients by name or ID
- Collect and analyze detailed firewall logs with parsing
- Identify security threats and blocked connections
- Manage firewall rules
- Monitor system health and performance
- Restart firewall services when needed

Client Addressing:
- Clients can be addressed by their friendly names (e.g., "opus-1", "branch-office-2") or client IDs
- Support for multiple clients in one command using comma-separated lists (e.g., "opus-1, james-office, central-lion")
- Use "all" to target all connected clients
- Always provide helpful error messages if a client name is not found

Be helpful, informative, and prioritize security in all recommendations. When analyzing logs, provide insights about security events, blocked threats, and traffic patterns."""
            }

            # Prepare messages for OpenAI (limit history to reduce token usage)
            messages = [system_message] + self.conversation_history[-8:]

            # Make API call to OpenAI
            response = self.openai_client.chat.completions.create(
                model="gpt-4",
                messages=messages,
                tools=self.function_tools,
                tool_choice="auto",
                temperature=0.7,

                max_tokens=1500
            )

            message = response.choices[0].message

            # Handle function calls
            if message.tool_calls:
                # Add assistant message to history
                self.conversation_history.append({
                    "role": "assistant",
                    "content": message.content,
                    "tool_calls": [
                        {
                            "id": tool_call.id,
                            "type": tool_call.type,
                            "function": {
                                "name": tool_call.function.name,
                                "arguments": tool_call.function.arguments
                            }
                        } for tool_call in message.tool_calls
                    ]
                })

                # Execute function calls
                function_results = []
                for tool_call in message.tool_calls:
                    function_name = tool_call.function.name
                    arguments = json.loads(tool_call.function.arguments)

                    if self.verbose:
                        logger.info(f"Executing function: {function_name} with args: {arguments}")

                    result = await self.execute_function_call(function_name, arguments)

                    # Add sanitized function result to conversation (avoid huge payloads)
                    sanitized = self._sanitize_tool_result(result)
                    self.conversation_history.append({
                        "role": "tool",
                        "tool_call_id": tool_call.id,
                        "content": json.dumps(sanitized)
                    })

                    function_results.append(result)

                # Get final response from AI with function results
                final_response = self.openai_client.chat.completions.create(
                    model="gpt-4",
                    messages=[system_message] + self.conversation_history[-8:],
                    temperature=0.7,
                    max_tokens=800
                )

                final_message = final_response.choices[0].message.content

                # Add final response to history
                self.conversation_history.append({
                    "role": "assistant",
                    "content": final_message
                })

                return final_message

            else:
                # No function calls, just return the response
                self.conversation_history.append({
                    "role": "assistant",
                    "content": message.content
                })

                return message.content

        except Exception as e:
            logger.error(f"Error in AI chat: {e}")
            return f"Sorry, I encountered an error: {str(e)}"

    def clear_conversation(self):
        """Clear conversation history"""
        self.conversation_history = []
        logger.info("Conversation history cleared")

async def main():
    """Main function to run AI Command Center"""
    import argparse

    # Load environment variables
    load_dotenv()

    parser = argparse.ArgumentParser(description='AI Command Center for Firewall Management')
    parser.add_argument('--openai-key', help='OpenAI API key (can also be set via OPENAI_API_KEY env var)')
    parser.add_argument('--hq-url', default=os.getenv('HQ_URL', 'http://localhost:8000'), help='HTTP HQ base URL (e.g., https://lnsfirewall.ngrok.app)')
    parser.add_argument('--db', default=DEFAULT_DB_PATH, help='Database file path')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging (shows HTTP requests and function calls)')

    args = parser.parse_args()

    # Configure logging based on verbose flag
    if args.verbose:
        logging.getLogger().setLevel(logging.INFO)
        logging.getLogger('httpx').setLevel(logging.INFO)
        logging.getLogger(__name__).setLevel(logging.INFO)
    else:
        # Hide debug/info logs by default
        logging.getLogger().setLevel(logging.WARNING)
        logging.getLogger('httpx').setLevel(logging.WARNING)
        logging.getLogger(__name__).setLevel(logging.WARNING)

    # Get OpenAI API key from args or environment
    openai_key = args.openai_key or os.getenv('OPENAI_API_KEY')

    if not openai_key:
        print("❌ OpenAI API key is required!")
        print("Either:")
        print("  1. Set OPENAI_API_KEY in your .env file, or")
        print("  2. Use --openai-key argument")
        return

    # Create AI Command Center (HTTP mode)
    ai_center = AICommandCenter(args.hq_url, openai_key, args.db, args.verbose)

    print("🔥 AI Firewall Command Center Started 🔥")
    print("Type 'help' for available commands, 'quit' to exit")
    print("-" * 50)

    while True:
        try:
            user_input = input("\n🤖 AI Assistant: ").strip()

            if user_input.lower() in ['quit', 'exit', 'q']:
                print("Goodbye!")
                break
            elif user_input.lower() == 'clear':
                ai_center.clear_conversation()
                print("Conversation history cleared.")
                continue
            elif user_input.lower() == 'help':
                print("""
Available commands:
- Ask questions about firewall status, logs, or management
- 'clear' - Clear conversation history
- 'quit' - Exit the program

Example queries:
- "Show me the status of all connected firewalls"
- "Get logs from all clients for the last 7 days"
- "What's the memory usage on client abc123?"
- "Restart the firewall on client xyz789"
                """)
                continue
            elif not user_input:
                continue

            # Get AI response
            response = await ai_center.chat_with_ai(user_input)
            print(f"\n🔥 AI: {response}")

        except KeyboardInterrupt:
            print("\nGoodbye!")
            break
        except Exception as e:
            print(f"Error: {e}")

if __name__ == '__main__':
    asyncio.run(main())