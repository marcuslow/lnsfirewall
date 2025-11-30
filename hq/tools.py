"""
Firewall Management Tools for DeepAgents
All tools communicate with HQ server via HTTP API
"""

import os
import json
import asyncio
import requests
from typing import Optional, Dict, Any
from datetime import datetime
from dotenv import load_dotenv

# Load environment
load_dotenv()

# HQ Server URL - configurable via environment
HQ_URL = os.getenv('HQ_URL', 'http://localhost:8000').rstrip('/')

# Lazy imports for query engines
_RulesQueryEngine = None
_LogQueryEngine = None
_db_module = None


def _get_rqe():
    global _RulesQueryEngine
    if _RulesQueryEngine is None:
        try:
            from hq.rqe import RulesQueryEngine
            _RulesQueryEngine = RulesQueryEngine
        except ImportError:
            try:
                from rqe import RulesQueryEngine
                _RulesQueryEngine = RulesQueryEngine
            except ImportError:
                pass
    return _RulesQueryEngine


def _get_lqe():
    global _LogQueryEngine
    if _LogQueryEngine is None:
        try:
            from hq.lqe import LogQueryEngine
            _LogQueryEngine = LogQueryEngine
        except ImportError:
            try:
                from lqe import LogQueryEngine
                _LogQueryEngine = LogQueryEngine
            except ImportError:
                pass
    return _LogQueryEngine


def _get_db():
    global _db_module
    if _db_module is None:
        try:
            from hq.db_async import get_db
            _db_module = get_db
        except ImportError:
            from db_async import get_db
            _db_module = get_db
    return _db_module


def _resolve_client_id(client_id: str) -> tuple[str, str, dict]:
    """Resolve client name to actual ID. Returns (actual_id, client_name, all_clients)"""
    res = requests.get(f"{HQ_URL}/clients", timeout=30)
    res.raise_for_status()
    clients = res.json().get('clients', {})
    
    if client_id in clients:
        return client_id, clients[client_id].get('client_name', client_id), clients
    
    # Search by name
    for cid, info in clients.items():
        if info.get('client_name', '').lower() == client_id.lower():
            return cid, info.get('client_name', client_id), clients
    
    return None, None, clients


# ============== TOOLS ==============

def get_client_status(client_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Get status information for all connected firewall clients or a specific client.
    
    Args:
        client_id: Optional specific client ID or name. If not provided, returns all clients.
    
    Returns:
        Dict with client status including connection state, last seen, system health
    """
    try:
        res = requests.get(f"{HQ_URL}/clients", timeout=30)
        res.raise_for_status()
        clients = res.json().get('clients', {})
        
        if not client_id:
            return {"success": True, "clients": clients, "count": len(clients)}
        
        actual_id, name, _ = _resolve_client_id(client_id)
        if not actual_id:
            return {"success": False, "error": f"Client '{client_id}' not found. Available: {list(clients.keys())}"}
        
        return {"success": True, "data": clients[actual_id]}
    except Exception as e:
        return {"success": False, "error": str(e)}


def request_client_logs(client_id: str, days: int = 7) -> Dict[str, Any]:
    """
    Request log collection from one or more clients.
    
    Args:
        client_id: Client ID/name, comma-separated list, or 'all'
        days: Number of days of logs to collect (default: 7, max: 90)
    
    Returns:
        Dict with command IDs for tracking log collection progress
    """
    try:
        days = min(days, 90)
        res = requests.get(f"{HQ_URL}/clients", timeout=30)
        res.raise_for_status()
        clients = res.json().get('clients', {})
        
        if client_id.lower() == 'all':
            ids = list(clients.keys())
        else:
            ids = [c.strip() for c in client_id.split(',')]
            resolved = []
            for cid in ids:
                actual_id, _, _ = _resolve_client_id(cid)
                if actual_id:
                    resolved.append(actual_id)
                else:
                    return {"success": False, "error": f"Client '{cid}' not found"}
            ids = resolved
        
        results = {}
        for cid in ids:
            r = requests.post(f"{HQ_URL}/command", json={
                "client_id": cid, 
                "command_type": "get_logs", 
                "params": {"days": days}
            }, timeout=30)
            cmd_id = r.json().get('command_id') if r.status_code == 200 else None
            results[cid] = {"command_id": cmd_id, "days": days}
        
        return {"success": True, "message": f"Log collection requested from {len(ids)} client(s)", "clients": results}
    except Exception as e:
        return {"success": False, "error": str(e)}


def get_command_status(command_id: str) -> Dict[str, Any]:
    """
    Get the current status/progress of a previously enqueued command.

    Args:
        command_id: Command ID returned by a previous request

    Returns:
        Dict with command status, progress percentage, and stage information
    """
    try:
        res = requests.get(f"{HQ_URL}/command/status", params={"command_id": command_id}, timeout=15)
        if res.status_code != 200:
            return {"success": False, "error": f"Server returned {res.status_code}"}
        return {"success": True, "data": res.json()}
    except Exception as e:
        return {"success": False, "error": str(e)}


def get_firewall_rules(client_id: str) -> Dict[str, Any]:
    """
    Get firewall rules from a client (uses cache if recent, fetches fresh if needed).

    Args:
        client_id: Client ID or name to get rules from

    Returns:
        Dict with rules count, ruleset ID, and success status
    """
    try:
        actual_id, name, clients = _resolve_client_id(client_id)
        if not actual_id:
            return {"success": False, "error": f"Client '{client_id}' not found"}

        # Check cache first
        try:
            status_res = requests.get(f"{HQ_URL}/rules/status", params={"client_id": actual_id}, timeout=10)
            if status_res.status_code == 200:
                status = status_res.json()
                if status.get("success") and status.get("age_minutes", 999) < 5:
                    return {
                        "success": True,
                        "message": f"Using cached rules (age: {status.get('age_minutes', 0):.1f} min)",
                        "rules_count": status.get("rules_count", 0),
                        "ruleset_id": status.get("ruleset_id"),
                        "cached": True
                    }
        except Exception:
            pass

        # Fetch fresh rules
        r = requests.post(f"{HQ_URL}/command", json={
            "client_id": client_id,
            "command_type": "get_rules"
        }, timeout=30)
        r.raise_for_status()
        command_id = r.json().get('command_id')

        # Wait for response
        import time
        max_wait = 30
        start = time.time()

        while time.time() - start < max_wait:
            status_res = requests.get(f"{HQ_URL}/command/status", params={"command_id": command_id}, timeout=10)
            if status_res.status_code == 200:
                data = status_res.json()
                if data.get('status') == 'completed':
                    resp = data.get('response_data', {})
                    if isinstance(resp, str):
                        resp = json.loads(resp)
                    if resp.get('status') == 'success':
                        # Ingest rules
                        ing = requests.post(f"{HQ_URL}/rules/ingest", json={
                            "client_id": actual_id,
                            "rules_xml": resp.get('rules_xml', ''),
                            "command_id": command_id
                        }, timeout=30)
                        ing_data = ing.json() if ing.status_code == 200 else {}
                        return {
                            "success": True,
                            "message": f"Fresh rules retrieved for {client_id}",
                            "ruleset_id": ing_data.get("ruleset_id"),
                            "rule_count": ing_data.get("rule_count"),
                            "cached": False
                        }
            time.sleep(1)

        return {"success": False, "error": f"Timeout waiting for rules from {client_id}"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def get_rules_status(client_id: str) -> Dict[str, Any]:
    """
    Get the status and metadata of the latest ingested ruleset for a client.

    Args:
        client_id: Client ID or name to check rules status for

    Returns:
        Dict with ruleset age, ID, counts, and freshness info
    """
    try:
        actual_id, _, clients = _resolve_client_id(client_id)
        if not actual_id:
            return {"success": False, "error": f"Client '{client_id}' not found"}

        res = requests.get(f"{HQ_URL}/rules/status", params={"client_id": actual_id}, timeout=30)
        res.raise_for_status()
        return res.json()
    except Exception as e:
        return {"success": False, "error": str(e)}


def get_system_health(client_id: str) -> Dict[str, Any]:
    """
    Get comprehensive system health information for a firewall client.
    Includes uptime, CPU, memory, disk usage, and network stats.

    Args:
        client_id: Client ID or client name to get health info for

    Returns:
        Dict with CPU, memory, disk, uptime, and network interface stats
    """
    try:
        actual_id, _, clients = _resolve_client_id(client_id)
        if not actual_id:
            return {"success": False, "error": f"Client '{client_id}' not found"}

        target = clients[actual_id]
        health = target.get('system_health', {})

        if not health:
            return {"success": False, "error": f"No health data for '{client_id}'. Client may need to reconnect."}

        if health.get('status') != 'success':
            return {"success": False, "error": health.get('message', 'Health check failed')}

        # Format uptime
        uptime_sec = health.get('uptime', {}).get('uptime_seconds', 0)
        days = uptime_sec // 86400
        hours = (uptime_sec % 86400) // 3600

        return {
            "success": True,
            "client_id": client_id,
            "uptime": f"{days}d {hours}h",
            "uptime_seconds": uptime_sec,
            "memory": health.get('memory', {}),
            "disk": health.get('disk', {}),
            "cpu": health.get('cpu', {}),
            "network_interfaces": health.get('network_interfaces', [])
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


def push_rules(client_id: str, ruleset_id: str) -> Dict[str, Any]:
    """
    Push a specific ruleset to a client (enforces 6-hour freshness check).

    Args:
        client_id: Client ID or name to push rules to
        ruleset_id: Ruleset ID to push (must be the latest for the client)

    Returns:
        Dict with push status and any warnings about freshness
    """
    try:
        actual_id, _, clients = _resolve_client_id(client_id)
        if not actual_id:
            return {"success": False, "error": f"Client '{client_id}' not found"}

        res = requests.post(f"{HQ_URL}/rules/push", json={
            "client_id": actual_id,
            "ruleset_id": ruleset_id
        }, timeout=60)

        if res.status_code == 409:
            return {"success": False, "error": res.json().get('detail', 'Push blocked'), "blocked": True}

        res.raise_for_status()
        return {"success": True, **res.json(), "client_id": actual_id}
    except Exception as e:
        return {"success": False, "error": str(e)}


def get_logs_status(client_id: str) -> Dict[str, Any]:
    """
    Check log recency and status for a client to determine if fresh logs are needed.

    Args:
        client_id: Client ID or name

    Returns:
        Dict with log age, count, and freshness status
    """
    try:
        actual_id, name, _ = _resolve_client_id(client_id)
        if not actual_id:
            return {"success": False, "error": f"Client '{client_id}' not found"}

        client_name_db = name.lower() if name else actual_id.lower()

        get_db = _get_db()

        async def _check():
            async with get_db() as db:
                cursor = await db.execute('''
                    SELECT COUNT(*) as count, MAX(log_timestamp) as last_time
                    FROM log_entries WHERE client_id = %s
                ''', (client_name_db,))
                row = await db.fetchone(cursor)
                return row

        row = asyncio.run(_check())

        if not row or not row.get('count'):
            return {"success": True, "has_logs": False, "message": "No logs stored for this client"}

        last_time = row.get('last_time')
        age_hours = None
        if last_time:
            try:
                if isinstance(last_time, str):
                    last_time = datetime.fromisoformat(last_time.replace('Z', '+00:00'))
                age = datetime.now() - last_time.replace(tzinfo=None)
                age_hours = age.total_seconds() / 3600
            except Exception:
                pass

        return {
            "success": True,
            "has_logs": True,
            "log_count": row.get('count', 0),
            "last_log_time": str(last_time),
            "age_hours": round(age_hours, 1) if age_hours else None,
            "fresh": age_hours < 6 if age_hours else False
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


def update_client(client_id: str, force_restart: bool = False) -> Dict[str, Any]:
    """
    Push client software update to a pfSense firewall.
    Creates bundle, uploads files, and restarts client remotely.

    Args:
        client_id: Client ID or name to update
        force_restart: Force restart even if update fails (default: False)

    Returns:
        Dict with update status and command ID for tracking
    """
    try:
        actual_id, _, clients = _resolve_client_id(client_id)
        if not actual_id:
            return {"success": False, "error": f"Client '{client_id}' not found"}

        res = requests.post(f"{HQ_URL}/command", json={
            "client_id": actual_id,
            "command_type": "update_client",
            "params": {"force_restart": force_restart}
        }, timeout=30)
        res.raise_for_status()

        return {
            "success": True,
            "message": f"Update command sent to {client_id}",
            "command_id": res.json().get('command_id')
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


def get_wan_performance(client_id: str) -> Dict[str, Any]:
    """
    Analyze WAN performance and connectivity from pfSense perspective.
    Monitors gateway latency, packet loss, interface errors, and bandwidth usage.

    Args:
        client_id: Client ID or name to analyze WAN performance for

    Returns:
        Dict with gateway quality, latency, packet loss, and interface stats
    """
    try:
        actual_id, _, clients = _resolve_client_id(client_id)
        if not actual_id:
            return {"success": False, "error": f"Client '{client_id}' not found"}

        target = clients[actual_id]
        health = target.get('system_health', {})

        if not health:
            return {"success": False, "error": f"No health data for '{client_id}'"}

        # Extract WAN-relevant data
        interfaces = health.get('network_interfaces', [])
        wan_interfaces = [i for i in interfaces if 'wan' in i.get('name', '').lower()]

        gateways = health.get('gateways', [])

        return {
            "success": True,
            "client_id": client_id,
            "wan_interfaces": wan_interfaces,
            "gateways": gateways,
            "analysis": {
                "wan_count": len(wan_interfaces),
                "gateway_count": len(gateways)
            }
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


def query_cached_rules(client_id: str, query: str) -> Dict[str, Any]:
    """
    Query and analyze cached firewall rules without fetching fresh data.
    Use this to search/analyze rules that were already retrieved.

    Args:
        client_id: Client ID or name to query cached rules for
        query: What to search for (e.g., 'port forwarding', 'SSH access', 'port 80', 'blocked')

    Returns:
        Dict with matching rules, counts, and analysis results
    """
    import re
    try:
        RulesQueryEngine = _get_rqe()
        if RulesQueryEngine is None:
            return {"success": False, "error": "RulesQueryEngine not available"}

        actual_id, name, _ = _resolve_client_id(client_id)
        if not actual_id:
            return {"success": False, "error": f"Client '{client_id}' not found"}

        get_db = _get_db()
        client_name_db = (name or actual_id).lower()

        async def _get_rules():
            async with get_db() as db:
                cur = await db.execute('''
                    SELECT rules_xml, rule_count, ruleset_id
                    FROM firewall_rules WHERE client_id = %s
                    ORDER BY ingested_at DESC LIMIT 1
                ''', (client_name_db,))
                return await db.fetchone(cur)

        row = asyncio.run(_get_rules())

        if not row:
            return {"success": False, "error": f"No cached rules for {client_id}. Use get_firewall_rules first."}

        rules_xml = row.get('rules_xml', '')
        rqe = RulesQueryEngine(rules_xml)
        q = query.lower().strip()

        # Determine intent and run query
        if any(k in q for k in ["port forwarding", "forwarding", "nat", "redirect"]):
            pf = [rqe._nat_to_dict(n) for n in rqe.list_port_forwarding()]
            results = {"port_forwarding": pf}
        elif "ssh" in q:
            results = rqe.find_rules_by_service("ssh")
        elif "https" in q:
            results = rqe.find_rules_by_service("https")
        elif "http" in q:
            results = rqe.find_rules_by_service("http")
        elif "port" in q:
            m = re.search(r"(\d{1,5})", q)
            if m:
                results = rqe.find_rules_by_port(int(m.group(1)))
            else:
                results = {"nat": [], "filter": []}
        elif any(k in q for k in ["block", "blocked", "reject"]):
            results = {"blocking": rqe.find_blocking_rules()}
        elif any(k in q for k in ["allow", "allowed", "pass"]):
            results = {"allowed": rqe.find_allowed_rules()}
        elif any(k in q for k in ["ip", "address", "host"]):
            m = re.search(r"(\d+\.\d+\.\d+\.\d+|\d+\.\d+\.\d+|\d+\.\d+)", q)
            frag = m.group(1) if m else ""
            results = {"matching": rqe.find_rules_with_ip(frag) if frag else []}
        else:
            results = {"summary": rqe.summarize()}

        return {
            "success": True,
            "query": query,
            "results": results,
            "rule_count": row.get('rule_count', 0),
            "ruleset_id": row.get('ruleset_id')
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


def query_logs(client_id: str, query: str, days: int = 7, top_n: int = 10) -> Dict[str, Any]:
    """
    Analyze locally stored firewall logs and return structured security insights.

    Supported query types:
    - 'scanning' - port scan detection
    - 'geographic' - country analysis
    - 'threat intelligence' - malicious IP check
    - 'top blocked IPs' - most blocked sources
    - 'summary' - overview with top ports/IPs/services
    - 'blocked', 'port 22', 'ssh', 'ip 1.2.3.4' - direct filters

    Args:
        client_id: Client ID or name to query logs for
        query: What to look for in logs
        days: Lookback window in days (default: 7)
        top_n: How many top items to return (default: 10)

    Returns:
        Dict with structured analysis results (no raw logs)
    """
    try:
        LogQueryEngine = _get_lqe()
        if LogQueryEngine is None:
            return {"success": False, "error": "LogQueryEngine not available"}

        actual_id, name, _ = _resolve_client_id(client_id)
        if not actual_id:
            return {"success": False, "error": f"Client '{client_id}' not found"}

        client_name_db = (name or actual_id).lower()

        # Create LQE instance and run query
        lqe = LogQueryEngine(client_id=client_name_db, days=days, top_n=top_n)

        # Run the async query
        async def _run_query():
            return await lqe.analyze(query)

        result = asyncio.run(_run_query())

        return {
            "success": True,
            "client_id": client_id,
            "query": query,
            "days": days,
            "analysis": result
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


def perform_risk_assessment(client_id: str, days: int = 7, force_refresh: bool = False) -> Dict[str, Any]:
    """
    Perform a comprehensive security risk assessment on a client.
    Checks health, ensures recent logs, analyzes for threats (blocked events,
    brute-force, anomalies), and provides a structured report.

    Args:
        client_id: Client ID or name
        days: Log lookback days (default: 7)
        force_refresh: Force fresh log request (default: False)

    Returns:
        Dict with risk level, threat analysis, and recommendations
    """
    try:
        # Get system health
        health = get_system_health(client_id)

        # Check if logs are fresh, refresh if needed
        log_status = get_logs_status(client_id)

        if force_refresh or not log_status.get('fresh', False):
            # Request fresh logs
            request_client_logs(client_id, days=days)
            import time
            time.sleep(5)  # Brief wait for logs to start coming in

        # Query for security-relevant data
        blocked = query_logs(client_id, "blocked", days=days, top_n=20)
        scanning = query_logs(client_id, "scanning", days=days, top_n=10)

        # Determine risk level
        blocked_count = 0
        if blocked.get('success') and blocked.get('analysis'):
            blocked_count = blocked['analysis'].get('total_count', 0)

        scan_count = 0
        if scanning.get('success') and scanning.get('analysis'):
            scan_count = scanning['analysis'].get('scan_count', 0)

        if blocked_count > 10000 or scan_count > 100:
            risk_level = "HIGH"
        elif blocked_count > 1000 or scan_count > 10:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        return {
            "success": True,
            "client_id": client_id,
            "assessment": {
                "risk_level": risk_level,
                "analysis_period_days": days,
                "system_health": health.get('data', health) if health.get('success') else None,
                "log_analysis": {
                    "blocked_count": blocked_count,
                    "scan_attempts": scan_count,
                    "top_blocked": blocked.get('analysis', {}).get('top_ips', [])[:5] if blocked.get('success') else []
                },
                "recommendations": _generate_recommendations(risk_level, blocked_count, scan_count)
            }
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


def _generate_recommendations(risk_level: str, blocked: int, scans: int) -> list:
    """Generate security recommendations based on assessment."""
    recs = []

    if risk_level == "HIGH":
        recs.append("Immediate review of firewall rules recommended")
        recs.append("Consider implementing geo-blocking for high-risk regions")

    if scans > 10:
        recs.append("Port scanning activity detected - review exposed services")

    if blocked > 5000:
        recs.append("High volume of blocked traffic - verify rules are correctly configured")

    if not recs:
        recs.append("No immediate concerns detected - continue monitoring")

    return recs


# Export all tools for DeepAgents
FIREWALL_TOOLS = [
    get_client_status,
    request_client_logs,
    get_command_status,
    get_firewall_rules,
    get_rules_status,
    get_system_health,
    push_rules,
    get_logs_status,
    update_client,
    get_wan_performance,
    query_cached_rules,
    query_logs,
    perform_risk_assessment,
]

