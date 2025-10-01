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
    from hq.rqe import RulesQueryEngine
except Exception:
    try:
        from rqe import RulesQueryEngine
    except Exception:
        RulesQueryEngine = None  # Will handle gracefully at call site

# Local LQE (Logs Query Engine)
try:
    from hq.lqe import LogQueryEngine
except Exception:
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
        # Load environment variables first
        load_dotenv()

        self.hq_url = hq_url.rstrip('/')
        self.db_path = db_path or DEFAULT_DB_PATH
        self.openai_client = openai.OpenAI(api_key=openai_api_key)
        self.verbose = verbose
        self.conversation_history = []
        # Remember last requested logs window per client for better defaults
        self.last_logs_request_days: Dict[str, int] = {}
        # Load API tokens from environment if available
        self.ipinfo_token = os.getenv('IPINFO_TOKEN')
        self.abuseipdb_key = os.getenv('ABUSEIPDB_KEY')
        # Load API lookup limits from environment (default: 10)
        self.ipinfo_max_lookups = int(os.getenv('IPINFO_MAX_LOOKUPS', '10'))
        self.abuseipdb_max_lookups = int(os.getenv('ABUSEIPDB_MAX_LOOKUPS', '10'))
        # Load GeoIP2 offline database path (free MaxMind GeoLite2)
        self.geoip2_db_path = os.getenv('GEOIP2_DB_PATH')

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
                        "description": "Analyze locally stored firewall logs and return structured security insights. Use for ALL log/security questions. Supported intents: 'scanning' (port scan detection), 'geographic' (country analysis), 'threat intelligence' (malicious IP check), 'outbound anomaly' (suspicious outbound traffic), 'top blocked IPs', 'summary' (includes top ports/IPs/services), direct filters like 'blocked', 'port 22', 'ssh', 'ip 1.2.3.4'. Never ask the user for port numbers.",
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
                },
                {
                    "type": "function",
                    "function": {
                        "name": "update_client",
                        "description": "Push client software update to a pfSense firewall. Creates bundle, uploads files, and restarts client remotely.",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "client_id": {"type": "string", "description": "Client ID or name to update"},
                                "force_restart": {"type": "boolean", "description": "Force restart even if update fails (default: False)", "default": False}
                            },
                            "required": ["client_id"]
                        }
                    }
                },
                {
                    "type": "function",
                    "function": {
                        "name": "get_wan_performance",
                        "description": "Analyze WAN performance and connectivity from pfSense perspective. Monitors gateway latency, packet loss, interface errors, and bandwidth usage without requiring SD-WAN router access.",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "client_id": {"type": "string", "description": "Client ID or name to analyze WAN performance for"}
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
                # Only truncate truly massive fields, preserve analysis results
                massive_fields = [
                    'rules_xml', 'config_xml', 'raw_logs'  # Removed 'log_data', 'content', 'data', 'entries'
                ]
                for f in massive_fields:
                    if f in res and isinstance(res[f], str):
                        res[f] = self._truncate_string(res[f], 2000)

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

                # Preserve query_logs results and WAN performance analysis - these are already processed summaries
                is_query_result = any(key in res for key in ['summary', 'blocked_count', 'allowed_count', 'service', 'top_ips', 'top_ports'])
                is_wan_analysis = any(key in res for key in ['analysis', 'wan_interfaces', 'gateway_quality', 'performance_analysis', 'quality_metrics', 'current_status', 'bandwidth_analysis', 'recommendations'])
                is_security_assessment = isinstance(res.get('assessment'), dict)

                # If it's a security assessment, attach a compact summary to guide the LLM
                if is_security_assessment:
                    a = res['assessment']
                    la = a.get('log_analysis', {}) if isinstance(a.get('log_analysis'), dict) else {}
                    sh = a.get('system_health', {}) if isinstance(a.get('system_health'), dict) else {}
                    blocked = la.get('blocked_events', {}).get('count', la.get('blocked_count', 0))
                    allowed = la.get('allowed_events', {}).get('count', la.get('allowed_count', 0))
                    total = (blocked or 0) + (allowed or 0)
                    pct = lambda n: round((n / total) * 100, 1) if total else 0.0
                    top_ip = None
                    tip = la.get('top_blocked_ips')
                    if isinstance(tip, list) and tip:
                        try:
                            # tip may be list of [ip, count] pairs
                            ip0, cnt0 = tip[0][0], tip[0][1]
                            top_ip = {"ip": ip0, "count": cnt0}
                        except Exception:
                            pass
                    res['assessment_summary'] = {
                        'risk_level': a.get('risk_level', 'Unknown'),
                        'analysis_period_days': a.get('analysis_period_days'),
                        'totals': {
                            'total_connections': total,
                            'blocked': {'count': blocked, 'percent': pct(blocked)},
                            'allowed': {'count': allowed, 'percent': pct(allowed)}
                        },
                        'top_blocked_ip': top_ip,
                        'brute_force_attempts': la.get('potential_brute_force', {}).get('count', 0),
                        'port_scans': la.get('potential_port_scans', {}).get('count', 0),
                        'system_health': {
                            'uptime': sh.get('uptime_human') or sh.get('uptime'),
                            'memory_usage_percent': sh.get('memory_usage_percent'),
                            'disk_usage_percent': sh.get('disk_usage_percent'),
                            'cpu_percent': (sh.get('cpu', {}) or {}).get('percent') if isinstance(sh.get('cpu'), dict) else sh.get('cpu_percent'),
                            'network_interfaces': sh.get('network_interfaces')
                        }
                    }

                if not (is_query_result or is_wan_analysis or is_security_assessment):
                    # Remove large arrays only for non-query/non-WAN/non-assessment results
                    for key in list(res.keys()):
                        if isinstance(res[key], list) and len(res[key]) > 20:
                            res[key] = f"[{len(res[key])} items - truncated for context]"

                # More lenient size limit for query results, WAN analysis, and assessments
                size_limit = 8000 if (is_query_result or is_wan_analysis or is_security_assessment) else 3000
                payload = json.dumps(res)
                if len(payload) > size_limit:
                    if (is_query_result or is_wan_analysis or is_security_assessment):
                        # For rich analyses, just truncate long example arrays but keep summaries
                        if 'examples' in res and isinstance(res['examples'], list):
                            res['examples'] = res['examples'][:5]
                        return res
                    else:
                        # Keep only essential keys for non-query results
                        summary = {
                            'success': res.get('success', True),
                            'message': res.get('message', ''),
                            'command_id': res.get('command_id', ''),
                            'note': f'Payload truncated for AI context limits (was {len(payload)} chars)'
                        }
                        # Add specific summaries for known result types
                        if 'total_entries' in res:
                            summary['total_log_entries'] = res['total_entries']
                        if 'updated_files' in res:
                            summary['files_updated'] = len(res['updated_files']) if isinstance(res['updated_files'], list) else 'yes'
                        if 'analysis' in res:
                            summary['wan_analysis'] = 'WAN performance analysis completed'
                        return summary
                return res
            return result
        except Exception:
            return {'success': False, 'note': 'Failed to sanitize tool result'}

    def _compress_message_to_keywords(self, message: Dict[str, Any]) -> str:
        """Compress a conversation message to essential keywords."""
        role = message.get('role', '')
        content = message.get('content', '') or ''

        # Handle None content
        if content is None:
            content = ''

        if role == 'user':
            # Extract action verbs and key nouns from user input
            import re
            # Common firewall management actions (extended with WAN/perf terms)
            actions = re.findall(r'\b(update|restart|get|check|analyze|risk|assessment|status|logs|rules|block|allow|monitor|wan|performance|latency|bandwidth|quality)\b', str(content).lower())
            # Client names and identifiers
            clients = re.findall(r'\b(opus-\d+|[\w-]+office|[\w-]+client|all)\b', str(content).lower())
            # Time/quantity indicators
            timeframes = re.findall(r'\b(\d+\s*days?|today|yesterday|week|month)\b', str(content).lower())

            keywords = []
            if actions: keywords.append(f"action:{','.join(set(actions))}")
            if clients: keywords.append(f"target:{','.join(set(clients))}")
            if timeframes: keywords.append(f"time:{','.join(set(timeframes))}")

            return f"user: {' | '.join(keywords)}" if keywords else f"user: {str(content)[:50]}"

        elif role == 'assistant':
            # Extract key outcomes from assistant responses
            content_str = str(content).lower()
            if 'successfully' in content_str or 'completed' in content_str:
                return "assistant: success"
            elif 'error' in content_str or 'failed' in content_str:
                return "assistant: error"
            elif 'monitoring' in content_str or 'progress' in content_str:
                return "assistant: monitoring"
            else:
                return "assistant: response"

        elif role == 'tool':
            # Summarize tool results
            try:
                if content is None:
                    return "tool: empty"
                tool_data = json.loads(content) if isinstance(content, str) else content
                if isinstance(tool_data, dict):
                    if tool_data.get('success'):
                        result_type = "success"
                        if 'total_entries' in tool_data:
                            result_type += f":logs({tool_data['total_entries']})"
                        elif 'updated_files' in tool_data:
                            result_type += ":update"
                        elif 'clients' in tool_data:
                            result_type += ":status"
                        return f"tool: {result_type}"
                    else:
                        return "tool: error"
            except:
                pass
            return "tool: result"

        return f"{role}: {str(content)[:30]}"

    def _get_safe_conversation_history(self) -> List[Dict[str, Any]]:
        """Get conversation history with keyword compression while preserving tool-call structure.
        Ensures that if there is a trailing sequence of [assistant(tool_calls), tool, tool, ...],
        that entire chunk is kept verbatim so OpenAI can correlate tool outputs.
        """
        # Take a slightly larger window to be safe
        recent = self.conversation_history[-12:]

        # Find the last assistant message with tool_calls and keep it + all following messages
        tail_start = None
        for i in range(len(recent) - 1, -1, -1):
            m = recent[i]
            if m.get('role') == 'assistant' and m.get('tool_calls'):
                tail_start = i
                break
            # If we encounter a non-tool message before finding assistant tool_calls, stop search
            if m.get('role') != 'tool':
                break

        if tail_start is not None:
            head = recent[:tail_start]
            tail = recent[tail_start:]
        else:
            # Fallback: just keep the last 2 messages as-is
            head = recent[:-2] if len(recent) > 2 else []
            tail = recent[-2:] if len(recent) >= 2 else recent

        compressed_history: List[Dict[str, Any]] = []

        # Compress the head: skip tool and assistant-with-tool_calls, keyword-compress others
        for msg in head:
            if msg.get('role') == 'tool':
                continue
            if msg.get('role') == 'assistant' and msg.get('tool_calls'):
                continue
            compressed_content = self._compress_message_to_keywords(msg)
            compressed_history.append({
                "role": msg.get('role', 'user'),
                "content": compressed_content
            })

        # Append the tail verbatim to preserve tool-call context
        compressed_history.extend(tail)

        return compressed_history


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
        """Monitor command progress and display updates (non-blocking prints)."""
        import time
        import asyncio

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
                cmd_type = data.get("command_type", "command")

                if status == "completed":
                    label = "Update" if cmd_type == "update_client" else cmd_type.replace("_", " ").title()
                    print(f"✅ {label} completed for {client_name}")
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

                await asyncio.sleep(1)  # Poll every second without blocking

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
            elif function_name == "update_client":
                return await self.update_client(
                    arguments['client_id'],
                    arguments.get('force_restart', False)
                )
            elif function_name == "get_wan_performance":
                return await self.get_wan_performance(arguments['client_id'])

            else:
                return {"success": False, "error": f"Unknown function: {function_name}"}

        except Exception as e:
            return {"success": False, "error": str(e)}

    async def _ensure_fresh_logs(self, client_id: str, max_age_hours: int = 6) -> Dict[str, Any]:
        """
        Ensure logs are fresh (less than max_age_hours old).
        If logs are stale, automatically request fresh logs from client.

        Returns:
            {"fresh": True/False, "age_hours": float, "refreshed": True/False}
        """
        try:
            # Check when logs were last updated
            async with aiosqlite.connect(self.db_path) as db:
                cursor = await db.execute('''
                    SELECT MAX(timestamp) as last_log_time
                    FROM logs
                    WHERE client_id = ?
                ''', (client_id,))
                row = await cursor.fetchone()

                if not row or not row[0]:
                    # No logs found - need to fetch
                    logger.info(f"No logs found for {client_id}, requesting fresh logs...")
                    await self.request_client_logs(client_id, days=7)  # Default to 7 days
                    return {"fresh": False, "age_hours": None, "refreshed": True}

                last_log_time = datetime.fromisoformat(row[0])
                age = datetime.now() - last_log_time
                age_hours = age.total_seconds() / 3600

                if age_hours > max_age_hours:
                    logger.info(f"Logs for {client_id} are {age_hours:.1f} hours old (max: {max_age_hours}h), requesting fresh logs...")
                    await self.request_client_logs(client_id, days=7)  # Default to 7 days
                    return {"fresh": False, "age_hours": age_hours, "refreshed": True}

                logger.info(f"Logs for {client_id} are fresh ({age_hours:.1f} hours old)")
                return {"fresh": True, "age_hours": age_hours, "refreshed": False}

        except Exception as e:
            logger.error(f"Error checking log freshness for {client_id}: {e}")
            return {"fresh": False, "age_hours": None, "refreshed": False, "error": str(e)}

    async def query_logs(self, client_id: str, query: str, days: Optional[int] = None, top_n: Optional[int] = None, auto_refresh: bool = True) -> Dict[str, Any]:
        """
        Query locally stored logs using LogQueryEngine. No raw logs are sent to AI.

        Args:
            client_id: Client ID or name
            query: Natural language query
            days: Number of days to analyze
            top_n: Number of top results to return
            auto_refresh: If True, automatically refresh logs if older than 6 hours
        """
        try:
            if LogQueryEngine is None:
                return {"success": False, "error": "LogQueryEngine module not available"}

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

            # Auto-refresh logs if stale (older than 6 hours)
            if auto_refresh:
                freshness = await self._ensure_fresh_logs(actual_client_id, max_age_hours=6)
                if freshness.get('refreshed'):
                    # Wait a moment for logs to be ingested
                    await asyncio.sleep(2)

            # Default window selection: use last requested for this client, else 7
            effective_days = days if isinstance(days, int) and days > 0 else self.last_logs_request_days.get(client_id, 7)
            effective_top_n = top_n if isinstance(top_n, int) and top_n > 0 else 10

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
            elif any(k in q for k in ['scan', 'scanning', 'reconnaissance', 'recon', 'sweep', 'probe']):
                # Dedicated scanning detection query
                scan_results = lqe.detect_scanning_activity(
                    port_scan_threshold=15,
                    network_sweep_threshold=15
                )
                results = {
                    'scanning_activity': scan_results,
                    'analysis_type': 'port_scan_and_network_sweep_detection'
                }
            elif any(k in q for k in ['geo', 'geographic', 'geography', 'country', 'countries', 'location', 'origin']):
                # Geographic threat mapping query
                geo_results = lqe.map_geographic_threats(
                    ipinfo_token=self.ipinfo_token,
                    top_n=effective_top_n,
                    cache_db_path=self.db_path,
                    blocked_only=True,
                    max_api_lookups=self.ipinfo_max_lookups,
                    geoip2_db_path=self.geoip2_db_path
                )
                results = {
                    'geographic_analysis': geo_results,
                    'analysis_type': 'geographic_threat_mapping'
                }
            elif any(k in q for k in ['threat intel', 'threat intelligence', 'malicious', 'known threat', 'abuseipdb', 'reputation']):
                # Threat intelligence correlation query
                threat_intel_results = lqe.correlate_with_threat_intel(
                    abuseipdb_key=self.abuseipdb_key,
                    cache_db_path=self.db_path,
                    blocked_only=True,
                    confidence_threshold=50,
                    max_api_lookups=self.abuseipdb_max_lookups
                )
                results = {
                    'threat_intelligence': threat_intel_results,
                    'analysis_type': 'threat_intelligence_correlation'
                }
            elif any(k in q for k in ['outbound', 'c2', 'command and control', 'exfiltration', 'calling home', 'compromise', 'malware']):
                # Outbound connection anomaly monitoring
                outbound_results = lqe.monitor_outbound_connections(
                    internal_subnets=None,  # Use RFC1918 defaults
                    common_ports=None,      # Use standard ports
                    min_connections=1
                )
                results = {
                    'outbound_analysis': outbound_results,
                    'analysis_type': 'outbound_connection_monitoring'
                }
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
                scanning_activity = lqe.detect_scanning_activity(
                    port_scan_threshold=15,
                    network_sweep_threshold=15
                )
                top_blocked_ips = lqe.get_top_blocked_ips(top_n=effective_top_n)

                # Geographic threat analysis (optional, can use free GeoIP2 or paid ipinfo)
                geographic_analysis = None
                if self.ipinfo_token or self.geoip2_db_path:
                    try:
                        geographic_analysis = lqe.map_geographic_threats(
                            ipinfo_token=self.ipinfo_token,
                            top_n=effective_top_n,
                            cache_db_path=self.db_path,
                            blocked_only=True,
                            max_api_lookups=self.ipinfo_max_lookups,
                            geoip2_db_path=self.geoip2_db_path
                        )
                    except Exception as e:
                        logger.warning(f"Geographic analysis failed: {e}")

                # Threat intelligence correlation (optional, requires abuseipdb key)
                threat_intel_analysis = None
                if self.abuseipdb_key:
                    try:
                        threat_intel_analysis = lqe.correlate_with_threat_intel(
                            abuseipdb_key=self.abuseipdb_key,
                            cache_db_path=self.db_path,
                            blocked_only=True,
                            confidence_threshold=50,
                            max_api_lookups=self.abuseipdb_max_lookups
                        )
                    except Exception as e:
                        logger.warning(f"Threat intelligence correlation failed: {e}")

                # Outbound connection monitoring (always run - critical for compromise detection)
                outbound_analysis = None
                try:
                    outbound_analysis = lqe.monitor_outbound_connections(
                        internal_subnets=None,  # Use RFC1918 defaults
                        common_ports=None,      # Use standard ports
                        min_connections=1
                    )
                except Exception as e:
                    logger.warning(f"Outbound connection monitoring failed: {e}")

                # Enhanced risk scoring heuristic
                blocked_count = len(blocked)
                brute_force_count = len(potential_brute)
                vertical_scan_count = scanning_activity.get('total_vertical_scans', 0)
                horizontal_scan_count = scanning_activity.get('total_horizontal_scans', 0)
                total_scan_count = vertical_scan_count + horizontal_scan_count
                malicious_ips_count = threat_intel_analysis.get('malicious_ips_detected', 0) if threat_intel_analysis and threat_intel_analysis.get('success') else 0
                suspicious_outbound_count = outbound_analysis.get('unique_internal_hosts_affected', 0) if outbound_analysis and outbound_analysis.get('success') else 0

                # Risk level calculation (enhanced with threat intel and outbound monitoring)
                if suspicious_outbound_count > 0 or malicious_ips_count > 0 or blocked_count > 100 or brute_force_count > 10 or total_scan_count > 5:
                    risk_level = 'High'
                elif blocked_count > 10 or brute_force_count > 0 or total_scan_count > 0:
                    risk_level = 'Medium'
                else:
                    risk_level = 'Low'

                # Generate recommendations
                recommendations = []

                # Outbound anomaly recommendations (CRITICAL - indicates potential compromise)
                if outbound_analysis and outbound_analysis.get('success'):
                    if suspicious_outbound_count > 0:
                        recommendations.append(f'🚨 CRITICAL: {suspicious_outbound_count} internal host(s) making suspicious outbound connections - POSSIBLE COMPROMISE')
                        suspicious_conns = outbound_analysis.get('suspicious_connections', [])
                        if suspicious_conns:
                            top_outbound = suspicious_conns[0]
                            recommendations.append(
                                f"Top suspicious outbound: {top_outbound['source_ip']} → {top_outbound['destination_ip']}:{top_outbound['destination_port']} "
                                f"({top_outbound['protocol']}) - {top_outbound['connection_count']} connections - INVESTIGATE IMMEDIATELY"
                            )

                # Threat intelligence-based recommendations (highest priority)
                if threat_intel_analysis and threat_intel_analysis.get('success'):
                    if malicious_ips_count > 0:
                        recommendations.append(f'⚠️ CRITICAL: {malicious_ips_count} known malicious IP(s) detected - IMMEDIATE BLOCKING RECOMMENDED')
                        threat_findings = threat_intel_analysis.get('threat_findings', [])
                        if threat_findings:
                            top_threat = threat_findings[0]
                            recommendations.append(
                                f"Top threat: {top_threat['ip']} (Confidence: {top_threat['abuse_confidence_score']}%, "
                                f"{top_threat['total_reports']} reports) - {top_threat['blocked_connections']} blocked connections"
                            )

                if brute_force_count > 0:
                    recommendations.append('Block top suspicious IPs if recurring')
                    recommendations.append('Review rules for authentication ports (SSH, RDP)')
                if vertical_scan_count > 0:
                    recommendations.append(f'Detected {vertical_scan_count} vertical port scan(s) - consider blocking scanning IPs')
                if horizontal_scan_count > 0:
                    recommendations.append(f'Detected {horizontal_scan_count} network sweep(s) - investigate reconnaissance activity')
                if blocked_count > 50:
                    recommendations.append('Consider rate limiting or additional blocking rules')
                if top_blocked_ips and top_blocked_ips[0][1] > 20:
                    recommendations.append(f'Investigate top blocked IP: {top_blocked_ips[0][0]} ({top_blocked_ips[0][1]} blocks)')

                # Geographic-based recommendations
                if geographic_analysis and geographic_analysis.get('success'):
                    top_countries = geographic_analysis.get('top_source_countries', [])
                    if top_countries:
                        top_country = top_countries[0]
                        if top_country['blocked_connections'] > 50:
                            recommendations.append(
                                f"High volume from {top_country['country_name']} ({top_country['country_code']}): "
                                f"{top_country['blocked_connections']} blocked connections - consider country-level blocking"
                            )

                results = {
                    'risk_summary': summary,
                    'blocked_events': {'count': len(blocked), 'examples': compact(blocked)},
                    'allowed_events': {'count': len(allowed), 'examples': compact(allowed)},
                    'potential_brute_force': {'count': brute_force_count, 'examples': compact(potential_brute)},
                    'scanning_activity': scanning_activity,
                    'web_traffic': {'http_count': len(http_hits), 'https_count': len(https_hits)},
                    'top_blocked_ips': top_blocked_ips,
                    'risk_level': risk_level,
                    'recommendations': recommendations,
                    'analysis_period_days': effective_days
                }

                # Add geographic analysis if available
                if geographic_analysis:
                    results['geographic_analysis'] = geographic_analysis

                # Add threat intelligence if available
                if threat_intel_analysis:
                    results['threat_intelligence'] = threat_intel_analysis

                # Add outbound analysis if available
                if outbound_analysis:
                    results['outbound_analysis'] = outbound_analysis
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
        """
        Perform comprehensive security risk assessment on a client.
        Automatically ensures logs are fresh (< 6 hours old) before analysis.
        """
        try:
            # Step 1: Get system health
            health = await self.get_client_status(client_id)
            if not health.get('success'):
                return health  # Propagate error

            # Step 2: Map provided name -> actual ID as needed
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

            # Step 3: Ensure fresh logs (< 6 hours old) before running analysis
            freshness = await self._ensure_fresh_logs(actual_client_id, max_age_hours=6)
            if force_refresh and not freshness.get('refreshed'):
                # Force refresh even if logs are fresh
                log_req = await self.request_client_logs(client_id, days)
                if not log_req.get('success'):
                    return log_req
                freshness['refreshed'] = True

            # Wait for logs to be ingested if we just refreshed
            if freshness.get('refreshed'):
                await asyncio.sleep(2)

            # Step 4: Query logs for risk indicators (auto_refresh=False since we already checked)
            risk_query = await self.query_logs(client_id, 'summary', days=days, top_n=10, auto_refresh=False)
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

            # Get log freshness info
            last_log_ts = "Unknown"
            last_log_dt = None
            if freshness.get('age_hours') is not None:
                age_hours = freshness['age_hours']
                last_log_dt = datetime.now() - timedelta(hours=age_hours)
                last_log_ts = last_log_dt.isoformat()

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

    async def _resolve_client_id(self, client_id: str) -> Optional[str]:
        """Resolve client name to actual client ID"""
        try:
            res = requests.get(f"{self.hq_url}/clients", timeout=30)
            res.raise_for_status()
            clients = res.json().get('clients', {})
            name_to_id = {v.get('client_name', ''): k for k, v in clients.items()}
            if client_id in name_to_id:
                return name_to_id[client_id]
            # If not found by name, assume it's already an ID
            if client_id in clients:
                return client_id
            return None
        except Exception:
            # If API call fails, assume client_id is the actual ID
            return client_id

    async def _maybe_handle_direct_intent(self, user_message: str) -> Optional[str]:
        """Fast-path certain natural-language intents without calling the LLM.
        Currently supports WAN performance requests like 'wan performance for opus-1'.
        Returns a ready-to-print assistant reply string, or None to continue normal flow.
        """
        try:
            text = (user_message or "").lower()
            if "wan" in text and any(t in text for t in ["performance", "latency", "packet", "loss", "bandwidth", "quality"]):
                # Try to detect target client by name from /clients
                target_client_name = None
                try:
                    res = requests.get(f"{self.hq_url}/clients", timeout=15)
                    res.raise_for_status()
                    clients = res.json().get("clients", {})
                    names = {v.get("client_name", ""): k for k, v in clients.items()}
                    # Choose the first name that appears in the text
                    for name in names.keys():
                        if name and name.lower() in text:
                            target_client_name = name
                            break
                    # If no explicit name found and exactly one connected client, default to it
                    if not target_client_name and len(names) == 1:
                        target_client_name = next(iter(names.keys()))
                except Exception:
                    pass

                if not target_client_name:
                    return ("Please specify a target client, e.g., 'wan performance for opus-1'. "
                            "I couldn't determine which client to use.")

                # Execute WAN performance analysis directly
                result = await self.get_wan_performance(target_client_name)
                if not result.get("success"):
                    return f"Failed to get WAN performance for {target_client_name}: {result.get('error','unknown error')}"

                # Build a comprehensive human-readable summary
                parts = [f"🌐 WAN Performance Analysis for {target_client_name}"]
                parts.append("=" * 50)

                # Overall Quality Metrics
                qm = result.get("quality_metrics") or {}
                if isinstance(qm, dict):
                    parts.append("📊 Overall Quality Metrics:")
                    lat = qm.get("average_latency")
                    loss = qm.get("average_packet_loss")
                    score = qm.get("overall_quality_score")
                    interface_count = qm.get("interface_count", 0)

                    if lat is not None:
                        parts.append(f"   • Average Latency: {lat} ms")
                    if loss is not None:
                        parts.append(f"   • Average Packet Loss: {loss}%")
                    if score is not None:
                        parts.append(f"   • Quality Score: {score}/100")
                    parts.append(f"   • Active Interfaces: {interface_count}")
                    parts.append("")

                # Performance Analysis
                pa = result.get("performance_analysis") or {}
                if isinstance(pa, dict):
                    status = pa.get("overall_status")
                    if status:
                        status_emoji = "✅" if status == "healthy" else "⚠️" if status == "degraded" else "❌"
                        parts.append(f"🔍 Overall Status: {status_emoji} {status.upper()}")
                        parts.append("")

                    # Interface Details
                    interface_analysis = pa.get("interface_analysis", {})
                    if interface_analysis:
                        parts.append("🔌 Interface Analysis:")
                        for interface, details in interface_analysis.items():
                            if isinstance(details, dict):
                                iface_status = details.get("status", "unknown")
                                iface_emoji = "✅" if iface_status == "healthy" else "⚠️" if iface_status == "degraded" else "❌"
                                parts.append(f"   {iface_emoji} {interface}:")

                                if "latency_ms" in details:
                                    parts.append(f"      - Latency: {details['latency_ms']} ms")
                                if "packet_loss_percent" in details:
                                    parts.append(f"      - Packet Loss: {details['packet_loss_percent']}%")
                                if "quality_score" in details:
                                    parts.append(f"      - Quality Score: {details['quality_score']}/100")

                                issues = details.get("issues", [])
                                if issues:
                                    parts.append(f"      - Issues: {'; '.join(issues)}")
                        parts.append("")

                # Bandwidth Analysis
                ba = result.get("bandwidth_analysis") or {}
                if isinstance(ba, dict):
                    parts.append("📈 Bandwidth Usage:")
                    total_sent = ba.get("total_bytes_sent", 0)
                    total_recv = ba.get("total_bytes_received", 0)

                    def format_bytes(bytes_val):
                        if bytes_val >= 1024**4:
                            return f"{bytes_val / (1024**4):.2f} TB"
                        elif bytes_val >= 1024**3:
                            return f"{bytes_val / (1024**3):.2f} GB"
                        elif bytes_val >= 1024**2:
                            return f"{bytes_val / (1024**2):.2f} MB"
                        elif bytes_val >= 1024:
                            return f"{bytes_val / 1024:.2f} KB"
                        else:
                            return f"{bytes_val} bytes"

                    parts.append(f"   • Total Sent: {format_bytes(total_sent)}")
                    parts.append(f"   • Total Received: {format_bytes(total_recv)}")

                    interface_usage = ba.get("interface_usage", {})
                    if interface_usage:
                        parts.append("   • Per Interface:")
                        for interface, usage in interface_usage.items():
                            if isinstance(usage, dict):
                                sent = usage.get("bytes_sent", 0)
                                recv = usage.get("bytes_received", 0)
                                if sent > 0 or recv > 0:  # Only show active interfaces
                                    parts.append(f"      - {interface}: ↑{format_bytes(sent)} ↓{format_bytes(recv)}")
                    parts.append("")

                # Gateway Details
                current_status = result.get("current_status", {})
                if isinstance(current_status, dict):
                    wan_interfaces = current_status.get("wan_interfaces", {})
                    if wan_interfaces:
                        parts.append("🌐 Gateway Monitoring:")
                        for interface, details in wan_interfaces.items():
                            if isinstance(details, dict):
                                gw_monitoring = details.get("gateway_monitoring", {})
                                if isinstance(gw_monitoring, dict) and gw_monitoring.get("status") == "success":
                                    gw_ip = gw_monitoring.get("gateway_ip")
                                    latency_samples = gw_monitoring.get("latency_samples", [])
                                    parts.append(f"   • {interface} → {gw_ip}")
                                    if latency_samples:
                                        min_lat = min(latency_samples)
                                        max_lat = max(latency_samples)
                                        parts.append(f"      - Latency Range: {min_lat}-{max_lat} ms")
                                        parts.append(f"      - Samples: {latency_samples}")
                        parts.append("")

                # Recommendations
                recs = result.get("recommendations")
                if isinstance(recs, list) and recs:
                    parts.append("💡 Recommendations:")
                    for rec in recs[:5]:  # Show up to 5 recommendations
                        parts.append(f"   • {rec}")

                return "\n".join(parts)

            # Direct handling: Security assessment/summary with explicit timeframe
            import re as _re

            def _parse_days(text_in: str) -> int:
                t = (text_in or "").lower()
                # Explicit hour-based
                if "24 hour" in t or "24hour" in t or "last day" in t or "today" in t:
                    return 1
                # Common phrases
                if any(p in t for p in ["past week", "last week", "this week"]):
                    return 7
                if any(p in t for p in ["past month", "last month"]):
                    return 30
                # Generic 'last/past X days' or standalone 'X days'
                m = _re.search(r"(?:last|past|over the last)\s*(\d{1,3})\s*day", t)
                if m:
                    return max(1, min(90, int(m.group(1))))
                m2 = _re.search(r"\b(\d{1,3})\s*days\b", t)
                if m2:
                    return max(1, min(90, int(m2.group(1))))
                # Fallback to default 7 days
                return 7

            def _detect_target_client(text_in: str) -> Optional[str]:
                # Try to detect target client by name from /clients
                try:
                    res = requests.get(f"{self.hq_url}/clients", timeout=15)
                    res.raise_for_status()
                    clients = res.json().get("clients", {})
                    names = {v.get("client_name", ""): k for k, v in clients.items()}
                    # Choose the first name that appears in the text
                    for name in names.keys():
                        if name and name.lower() in (text_in or "").lower():
                            return name
                    # If no explicit name found and exactly one connected client, default to it
                    if len(names) == 1:
                        return next(iter(names.keys()))
                except Exception:
                    pass
                return None

            # Assessment first: more specific intent
            if any(k in text for k in ["risk assessment", "security assessment", "assessment"]):
                target_client_name = _detect_target_client(user_message)
                if not target_client_name:
                    return ("Please specify a target client, e.g., 'security assessment for opus-1'. "
                            "I couldn't determine which client to use.")
                days = _parse_days(user_message)
                assess = await self.perform_risk_assessment(target_client_name, days=days, force_refresh=False)
                if not assess.get("success"):
                    return f"Failed to perform risk assessment for {target_client_name}: {assess.get('error','unknown error')}"
                a = assess.get("assessment", {}) or {}
                rl = a.get("risk_level", "Unknown")
                kf = a.get("key_findings", []) or []
                lines = [f"Security risk assessment for {target_client_name} (last {days} day(s)):"]
                lines.append(f"Risk level: {rl}")
                if kf:
                    lines.append("Key findings:")
                    for item in kf[:6]:
                        lines.append(f"- {item}")
                return "\n".join(lines)

            # Summary intent
            if any(k in text for k in ["security summary", "log summary", "summary", "overview"]):
                target_client_name = _detect_target_client(user_message)
                if not target_client_name:
                    return ("Please specify a target client, e.g., 'security summary for opus-1'. "
                            "I couldn't determine which client to use.")
                days = _parse_days(user_message)
                qres = await self.query_logs(target_client_name, 'summary', days=days, top_n=10, auto_refresh=True)
                if not qres.get("success"):
                    return f"Failed to get security summary for {target_client_name}: {qres.get('error','unknown error')}"
                summ = (qres.get("results", {}) or {}).get("summary", {}) or {}
                total = summ.get("total_entries", 0)
                blocked = summ.get("blocked_count", 0)
                allowed = summ.get("allowed_count", 0)
                top_dst_ports = summ.get("top_dst_ports", []) or []
                top_src_ips = summ.get("top_src_ips", []) or []

                lines = [f"Security summary for {target_client_name} (last {days} day(s)):"]
                lines.append(f"Total log entries: {total}")
                lines.append(f"Blocked: {blocked}")
                lines.append(f"Allowed: {allowed}")
                if top_dst_ports:
                    lines.append("Top destination ports:")
                    for item in top_dst_ports[:5]:
                        port = item.get("value")
                        cnt = item.get("count")
                        lines.append(f"- {port}: {cnt}")
                if top_src_ips:
                    lines.append("Top source IPs:")
                    for item in top_src_ips[:5]:
                        ip = item.get("value")
                        cnt = item.get("count")
                        lines.append(f"- {ip}: {cnt}")
                return "\n".join(lines)

        except Exception:
            # On any error, fall back to normal LLM flow
            return None
        return None

    async def _send_command(self, client_id: str, command_type: str, params: Dict[str, Any]) -> Optional[str]:
        """Send a command to a client and return command ID"""
        try:
            res = requests.post(f"{self.hq_url}/command", json={
                "client_id": client_id,
                "command_type": command_type,
                "params": params
            }, timeout=30)
            res.raise_for_status()
            result = res.json()
            return result.get("command_id")
        except Exception as e:
            if self.verbose:
                print(f"Failed to send command: {e}")
            return None

    async def update_client(self, client_id: str, force_restart: bool = False) -> Dict[str, Any]:
        """Push client software update over the existing client channel by sending .py files.
        No SSH required: the client writes files locally and restarts itself.
        Also auto-monitors the update progress for a single client and reports completion."""
        try:
            # Resolve client name to ID
            resolved_client_id = await self._resolve_client_id(client_id)
            if not resolved_client_id:
                return {"success": False, "error": f"Client '{client_id}' not found"}

            # Build files payload from repo
            repo_root = BASE_DIR
            files_spec = []
            file_defs = [
                ("client/pfsense_client.py", "/usr/local/bin/pfsense_client.py", "0755"),
                ("client/psutil_stub.py", "/usr/local/bin/psutil_stub.py", "0644")
            ]
            for rel_path, target, mode in file_defs:
                abs_path = os.path.join(repo_root, rel_path)
                if os.path.exists(abs_path):
                    with open(abs_path, "rb") as f:
                        content_b64 = base64.b64encode(f.read()).decode("utf-8")
                    files_spec.append({
                        "name": os.path.basename(rel_path),
                        "path": rel_path,
                        "target": target,
                        "mode": mode,
                        "content_b64": content_b64
                    })

            if not files_spec:
                return {"success": False, "error": "No client files found to send"}

            params = {
                "restart": True,
                "force_restart": force_restart,
                "files": files_spec,
                "timestamp": datetime.now().isoformat(),
                "strategy": "replace_py"
            }

            # Send update command to client
            command_id = await self._send_command(resolved_client_id, "update_client", params)
            if not command_id:
                return {"success": False, "error": "Failed to send update command to client"}

            # Auto-monitor progress for single-client update
            progress_info = await self._monitor_command_progress(command_id, client_id)

            return {
                "success": True,
                "command_id": command_id,
                "message": f"Client update completed for {client_id}" if progress_info.get("status") == "completed" else f"Client update in progress for {client_id}",
                "progress": progress_info,
                "details": {
                    "client_id": resolved_client_id,
                    "files": [f[0] for f in file_defs]
                }
            }
        except Exception as e:
            return {"success": False, "error": f"Failed to update client: {str(e)}"}

    async def get_wan_performance(self, client_id: str) -> Dict[str, Any]:
        """Get WAN performance analysis from pfSense client"""
        try:
            # Resolve client name to ID
            resolved_client_id = await self._resolve_client_id(client_id)
            if not resolved_client_id:
                return {"success": False, "error": f"Client '{client_id}' not found"}

            # Send WAN performance analysis command
            res = requests.post(f"{self.hq_url}/command", json={
                "client_id": resolved_client_id,
                "command_type": "get_wan_performance",
                "params": {}
            }, timeout=30)
            res.raise_for_status()
            command_id = res.json().get("command_id")

            if not command_id:
                return {"success": False, "error": "Failed to enqueue WAN performance command"}

            # Monitor command progress and get results
            progress_info = await self._monitor_command_progress(command_id, client_id)

            if progress_info.get("status") == "completed":
                # NOTE: _monitor_command_progress returns the final payload under 'final_progress'
                result = progress_info.get("final_progress", {})
                # Flatten the analysis data to top level for better AI processing
                if isinstance(result, dict) and "analysis" in result:
                    flattened_result = {
                        "success": True,
                        "client_id": client_id,
                        "message": f"WAN performance analysis completed for {client_id}",
                        **result.get("analysis", {})  # Flatten analysis data to top level
                    }
                    return flattened_result
                else:
                    return {
                        "success": True,
                        "client_id": client_id,
                        "analysis": result,
                        "message": f"WAN performance analysis completed for {client_id}"
                    }
            else:
                return {
                    "success": False,
                    "error": f"WAN performance analysis failed or timed out for {client_id}",
                    "progress": progress_info
                }

        except Exception as e:
            logger.error(f"Error getting WAN performance for {client_id}: {e}")
            return {"success": False, "error": str(e)}

    async def chat_with_ai(self, user_message: str) -> str:
        """Chat with AI assistant for firewall management"""
        try:
            # Add user message to conversation history
            self.conversation_history.append({
                "role": "user",
                "content": user_message
            })

            # Fast-path direct intents (e.g., 'wan performance for opus-1')
            direct = await self._maybe_handle_direct_intent(user_message)
            if direct:
                # Record assistant reply in history and return
                self.conversation_history.append({"role": "assistant", "content": direct})
                return direct

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

TOOL-FIRST POLICY:
- For ANY user question that requires data or analysis, you MUST call one of the provided tools on your first turn.
- Do NOT respond with narrative like "initiating analysis" or "starting a scan" without actually calling a tool.
- For log/security questions, ALWAYS call query_logs immediately with the correct parameters.
- DEFAULT: If a log/security intent is unclear, call query_logs with query='summary'.

Log Analysis Capabilities:
- Parse pfSense filter logs with rule numbers, interfaces, actions, protocols, IPs
- Parse pfBlockerNG logs with block lists, threat categories, source/destination details
- Generate statistics: blocked vs allowed connections, top source/destination IPs, protocol distribution
- Track security events and potential threats

Specific Query Types (use these exact mappings):
- PORT SCANNING ("port scanning activity", "detected scans", "reconnaissance") -> call query_logs with query='scanning'
- GEOGRAPHIC ("which countries", "attack sources") -> call query_logs with query='geographic'
- THREAT INTELLIGENCE ("malicious IPs", "known threats") -> call query_logs with query='threat intelligence'
- OUTBOUND ANOMALIES ("suspicious outbound", "outbound traffic") -> call query_logs with query='outbound anomaly'
- TOP BLOCKED IPs ("top blocked", "most attacks") -> call query_logs with query='top blocked IPs'
- PORTS TARGETED MOST ("ports targeted the most", "most targeted ports", "top ports") -> call query_logs with query='summary' and report top_ports
- SECURITY SUMMARY OVER TIME ("security summary", "last 24 hours/7 days/30 days") -> call query_logs with query='summary' and set days accordingly

Time Window Parsing:
- "last 24 hours" / "today" / "past day" => days=1
- "last 7 days" / "past week" / "this week" => days=7
- "last 30 days" / "past month" => days=30
- If the timeframe is not specified, default to days=7

Response formatting by query type (be concise, factual, include key numbers):
- Port Scanning: report total_vertical_scans, total_horizontal_scans; list top scanner IPs with attempt counts.
- Top Blocked IPs: provide a ranked list of IPs with block counts (e.g., IP · 1,234 blocks), plus total blocked.
- Threat Intelligence: report malicious_ips_detected / total_ips_checked; list top 3–5 IPs with confidence/abuse scores and category/country if available.
- Outbound Anomaly: report suspicious_connections; if zero, say none were detected.
- Ports Targeted Most: list top ports with counts and service names (e.g., 22/SSH · 496 attempts).
- Time-based Summary: explicitly state the timeframe (e.g., "last 24 hours") and provide blocked/allowed counts and top items.

CRITICAL:
- Never ask users to specify ports or provide more details for these queries — the tools automatically analyze all relevant data.
- When asked about port scanning, scanning activity, or reconnaissance — IMMEDIATELY call query_logs with query='scanning'. Do NOT provide procedural responses.

Risk Assessment Capabilities:
- When asked for a risk assessment, threat analysis, or security check:
  - First, check system health with get_client_status.
  - Ensure recent logs are available (e.g., request_client_logs if logs are older than 1 day).
  - Use query_logs with targeted queries like 'summary', 'blocked', 'ssh' (for brute-force), 'top blocked IPs', or custom (e.g., 'multiple blocks from same IP on port 22').
  - Analyze for common risks: high blocked traffic (potential attacks), repeated failures on auth ports (brute-force), unusual protocols/ports, top suspicious IPs (e.g., many connections from one source indicating DDoS or scanning).
  - Provide a structured assessment: Low/Medium/High risk level, key findings, recommendations (e.g., block IP, update rules).
  - Prioritize accuracy; if data is insufficient, request more logs or clarification.

Formatting requirements for risk assessments (always include these sections with numbers when available):
- System Health: uptime, memory usage %, disk usage %, CPU %, network interfaces
- Firewall Logs Analysis: total connections, blocked count and %, allowed count and %
- Threat Analysis: top blocked IP with count, brute-force attempts on auth ports (e.g., 22/3389), unusual protocols/ports, potential scans
- Risk Level: Low/Medium/High with 1–3 bullets why
- Recommendations: 3–5 concrete actions (block IP, adjust rules, increase logging, etc.)

When users ask about firewall management, use the appropriate functions to help them. Always be clear about what actions you're taking and ask for confirmation before making changes that could affect firewall security or connectivity.

Current capabilities:
- Monitor multiple pfSense firewall clients by name or ID
- Collect and analyze detailed firewall logs with parsing
- Identify security threats and blocked connections
- Manage firewall rules
- Monitor system health and performance
- Restart firewall services when needed
- Update client software remotely (push new code, restart services)
- Analyze WAN performance and connectivity from pfSense perspective (gateway latency, packet loss, interface errors, bandwidth usage)

Client Addressing:
- Clients can be addressed by their friendly names (e.g., "opus-1", "branch-office-2") or client IDs
- Support for multiple clients in one command using comma-separated lists (e.g., "opus-1, james-office, central-lion")
- Use "all" to target all connected clients
- Always provide helpful error messages if a client name is not found

Be helpful, informative, and prioritize security in all recommendations. When analyzing logs, provide insights about security events, blocked threats, and traffic patterns.

Behavioral rules for user experience:
- For single-client software update requests (e.g., "update opus-1"), do NOT ask for confirmation; initiate immediately, auto-monitor progress, and announce completion automatically. Provide the command ID, but do not require the user to manually run a status check.
- Only ask for confirmation when the request is ambiguous, risky, or targets multiple clients without clear intent."""
            }

            # Prepare messages for OpenAI (aggressive token management)
            messages = [system_message] + self._get_safe_conversation_history()

            # Make API call to OpenAI
            response = self.openai_client.chat.completions.create(
                model="gpt-4o",
                messages=messages,
                tools=self.function_tools,
                tool_choice="auto",
                temperature=0.2,

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
                    model="gpt-4o",
                    messages=[system_message] + self._get_safe_conversation_history(),
                    temperature=0.2,
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