#!/usr/bin/env python3
"""
HTTP HQ Server (FastAPI) for Firewall Management
Replaces WebSocket transport with HTTP(S) polling, easy to test via ngrok.
"""

import asyncio
import json
import uuid
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import websockets
import os
import hashlib
import logging
import sys
import base64
import gzip

# Add the hq directory to Python path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from client_updater import ClientUpdater
from db_async import (
    get_db,
    insert_log_entries_batch,
    update_command_progress,
    mark_command_complete,
    get_command_status
)
from db_config import POSTGRES_CONFIG

# Base directory
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # repo root
# Legacy SQLite path (kept for reference, but using Postgres now)
DB_PATH = os.path.join(BASE_DIR, "hq_database.db")

app = FastAPI(title="pfSense Firewall HQ (HTTP)")

# In-memory connections (for live view); persistence is via SQLite
clients_live: Dict[str, Dict[str, Any]] = {}
commands_queue: Dict[str, List[Dict[str, Any]]] = {}

# WebSocket connections
websocket_connections: Dict[str, WebSocket] = {}  # client_id -> WebSocket

# Client updater instance
client_updater = ClientUpdater(BASE_DIR, DB_PATH)

def resolve_client_identifier(client_id: str) -> str:
    """
    Resolve client_id to a consistent storage identifier (normalized to lowercase).

    For WebSocket clients: client_id is the friendly name (e.g., 'opus-1')
    For HTTP clients: client_id is a hash, but we need to find the friendly name

    Returns the normalized identifier to use for database storage/lookup.
    """
    # First, try direct lookup (WebSocket clients use friendly name as key)
    if client_id in clients_live:
        # For HTTP clients, the key is the hash and client_name is in the dict
        client_info = clients_live[client_id]
        if 'client_name' in client_info:
            return client_info['client_name'].lower()
        return client_id.lower()

    # Second, check if this is a friendly name that maps to a hash (reverse lookup)
    for key, info in clients_live.items():
        if info.get('client_name', '').lower() == client_id.lower():
            return client_id.lower()
        # Also check if client_id is the hash_id for a WebSocket client
        if info.get('hash_id') == client_id:
            return info.get('client_name', client_id).lower()

    # Fallback: just normalize what we have
    return client_id.lower()

class RegisterRequest(BaseModel):
    client_id: str
    client_name: Optional[str] = None
    hostname: Optional[str] = None
    system_health: Optional[Dict[str, Any]] = None

class HeartbeatRequest(BaseModel):
    client_id: str

class PollRequest(BaseModel):
    client_id: str

class CommandResponse(BaseModel):
    client_id: str
    command_id: Optional[str] = None
    data: Dict[str, Any]

class CreateCommandRequest(BaseModel):
    client_id: str
    command_type: str
    params: Optional[Dict[str, Any]] = None

async def init_database():
    """Test PostgreSQL connection on startup"""
    try:
        async with get_db() as db:
            cur = await db.execute("SELECT version()")
            version = await db.fetchone(cur)
            # PostgreSQL returns dict with RealDictCursor
            version_str = version.get('version', 'Unknown') if version else 'Unknown'
            # Truncate long version string
            if len(version_str) > 60:
                version_str = version_str[:60] + '...'
            print(f"✅ Connected to PostgreSQL: {version_str}")
    except Exception as e:
        print(f"❌ Failed to connect to PostgreSQL: {e}")
        print(f"   Config: {POSTGRES_CONFIG['user']}@{POSTGRES_CONFIG['host']}:{POSTGRES_CONFIG['port']}/{POSTGRES_CONFIG['database']}")
        raise

def parse_raw_log_line(line: str, filename: str) -> Optional[Dict[str, Any]]:
    """
    Parse a single raw log line from pfSense.
    Returns a dict with extracted fields or None if unparseable.
    """
    if not line or not line.strip():
        return None

    try:
        # Determine log type from filename
        is_pfblocker = 'ip_block' in filename.lower()

        # Extract timestamp and message parts
        # Format: "Oct  1 00:00:00 LNS filterlog[13334]: ..."
        parts = line.split(maxsplit=4)
        if len(parts) < 5:
            return None

        month, day, time, hostname, message_part = parts[0], parts[1], parts[2], parts[3], parts[4]

        # Normalize timestamp (handle double spaces)
        log_date_str = f"{month} {day} {time}"
        try:
            log_date = datetime.strptime(log_date_str, "%b %d %H:%M:%S")
            # Add current year
            log_date = log_date.replace(year=datetime.now().year)
            log_timestamp = log_date.isoformat()
            timestamp_obj = log_date
        except ValueError:
            log_timestamp = None
            timestamp_obj = datetime.now()

        # Parse based on log type
        if is_pfblocker:
            # pfBlockerNG format: timestamp,action,interface,src,dst,proto,dstport
            if ':' in message_part:
                csv_part = message_part.split(':', 1)[1].strip()
                fields = csv_part.split(',')
                if len(fields) >= 6:
                    return {
                        'timestamp': timestamp_obj,
                        'log_timestamp': log_timestamp,
                        'source': filename,
                        'log_type': 'pfblockerng',
                        'hostname': hostname,
                        'raw_message': line,
                        'rule_number': None,
                        'interface': fields[2] if len(fields) > 2 else None,
                        'action': fields[1] if len(fields) > 1 else None,
                        'direction': None,
                        'protocol': fields[5] if len(fields) > 5 else None,
                        'source_ip': fields[3] if len(fields) > 3 else None,
                        'dest_ip': fields[4] if len(fields) > 4 else None,
                        'source_port': None,
                        'dest_port': int(fields[6]) if len(fields) > 6 and fields[6].isdigit() else None,
                    }
        else:
            # Filter log format: filterlog[PID]: CSV fields
            if 'filterlog' in message_part and ':' in message_part:
                csv_part = message_part.split(':', 1)[1].strip()
                fields = csv_part.split(',')

                if len(fields) >= 10:
                    # Extract key fields from CSV
                    rule_num = fields[0] if fields[0].isdigit() else None
                    interface = fields[4] if len(fields) > 4 else None
                    action = fields[6] if len(fields) > 6 else None
                    direction = fields[7] if len(fields) > 7 else None
                    protocol = fields[16] if len(fields) > 16 else None

                    # IP addresses and ports depend on protocol
                    source_ip = fields[18] if len(fields) > 18 else None
                    dest_ip = fields[19] if len(fields) > 19 else None

                    # Ports for TCP/UDP
                    source_port = None
                    dest_port = None
                    if protocol in ['tcp', 'udp'] and len(fields) > 21:
                        source_port = int(fields[20]) if fields[20].isdigit() else None
                        dest_port = int(fields[21]) if fields[21].isdigit() else None

                    return {
                        'timestamp': timestamp_obj,
                        'log_timestamp': log_timestamp,
                        'source': filename,
                        'log_type': 'filter',
                        'hostname': hostname,
                        'raw_message': line,
                        'rule_number': int(rule_num) if rule_num else None,
                        'interface': interface,
                        'action': action,
                        'direction': direction,
                        'protocol': protocol,
                        'source_ip': source_ip,
                        'dest_ip': dest_ip,
                        'source_port': source_port,
                        'dest_port': dest_port,
                    }

        # Unparsed entry
        return {
            'timestamp': timestamp_obj,
            'log_timestamp': log_timestamp,
            'source': filename,
            'log_type': 'unparsed',
            'hostname': hostname,
            'raw_message': line,
            'rule_number': None,
            'interface': None,
            'action': None,
            'direction': None,
            'protocol': None,
            'source_ip': None,
            'dest_ip': None,
            'source_port': None,
            'dest_port': None,
        }

    except Exception as e:
        logging.debug(f"Failed to parse line: {e}")
        return None


def parse_log_entries_for_storage(logs_data: Any) -> List[Dict[str, Any]]:
    """
    Parse log data and extract individual log entries.
    Handles both raw log files and pre-parsed log entries.
    Returns a list of dicts ready for insertion into log_entries table.
    """
    entries = []

    try:
        # Handle different input formats
        if isinstance(logs_data, str):
            logs_list = json.loads(logs_data)
        elif isinstance(logs_data, list):
            logs_list = logs_data
        else:
            logging.warning(f"Unexpected log data type: {type(logs_data)}")
            return entries

        # Check if this is raw log files or pre-parsed entries
        if logs_list and isinstance(logs_list[0], dict) and 'content' in logs_list[0]:
            # Raw log files - parse each line
            print(f"   Parsing {len(logs_list)} raw log files...")
            for log_file in logs_list:
                filename = log_file.get('filename', 'unknown')
                content = log_file.get('content', '')
                lines = content.split('\n')

                for line in lines:
                    parsed = parse_raw_log_line(line, filename)
                    if parsed:
                        entries.append(parsed)

            print(f"   Parsed {len(entries)} log entries from raw files")
        else:
            # Pre-parsed entries (legacy format)
            print(f"   Processing {len(logs_list)} pre-parsed log entries...")
            for log_entry in logs_list:
                if not isinstance(log_entry, dict):
                    continue

                # Extract timestamp
                log_timestamp = log_entry.get('timestamp')
                timestamp_obj = None
                if log_timestamp:
                    try:
                        timestamp_obj = datetime.fromisoformat(log_timestamp)
                    except (ValueError, TypeError):
                        timestamp_obj = datetime.now()
                else:
                    timestamp_obj = datetime.now()

                # Extract all relevant fields
                parsed_entry = {
                    'timestamp': timestamp_obj,
                    'log_timestamp': log_timestamp,
                    'source': log_entry.get('source'),
                    'log_type': log_entry.get('log_type'),
                    'hostname': log_entry.get('hostname'),
                    'raw_message': log_entry.get('raw_message'),
                    'rule_number': log_entry.get('rule_number'),
                    'interface': log_entry.get('interface'),
                    'action': log_entry.get('action'),
                    'direction': log_entry.get('direction'),
                    'protocol': log_entry.get('protocol') or log_entry.get('proto'),
                    'source_ip': log_entry.get('source_ip') or log_entry.get('src'),
                    'dest_ip': log_entry.get('dest_ip') or log_entry.get('dst'),
                    'source_port': log_entry.get('source_port') or log_entry.get('src_port'),
                    'dest_port': log_entry.get('dest_port') or log_entry.get('dst_port'),
                }

                # Convert port numbers to integers
                for port_field in ['source_port', 'dest_port']:
                    if parsed_entry[port_field]:
                        try:
                            parsed_entry[port_field] = int(parsed_entry[port_field])
                        except (ValueError, TypeError):
                            parsed_entry[port_field] = None

                # Convert rule_number to integer
                if parsed_entry['rule_number']:
                    try:
                        parsed_entry['rule_number'] = int(parsed_entry['rule_number'])
                    except (ValueError, TypeError):
                        parsed_entry['rule_number'] = None

                entries.append(parsed_entry)

    except Exception as e:
        logging.error(f"Error parsing log entries: {e}")
        import traceback
        traceback.print_exc()

    return entries

@app.on_event("startup")
async def startup_event():
    await init_database()

@app.get("/")
async def root():
    return {"status": "online", "server_time": datetime.now().isoformat()}

@app.get("/clients")
async def list_clients():
    # Return live clients and status
    return {
        "total": len(clients_live),
        "clients": clients_live
    }

@app.post("/register")
async def register_client(req: RegisterRequest):
    client_id = req.client_id
    client_name = req.client_name or f"firewall-{client_id[:8]}"
    hostname = req.hostname or "unknown"
    system_health = req.system_health or {}

    clients_live[client_id] = {
        "client_name": client_name,
        "hostname": hostname,
        "last_seen": datetime.now().isoformat(),
        "connected_at": datetime.now().isoformat(),
        "system_health": system_health
    }

    async with get_db() as db:
        # Store hostname and system_health in metadata JSONB column
        metadata = {
            'hostname': hostname,
            'system_health': system_health or {}
        }
        # PostgreSQL uses INSERT ... ON CONFLICT for upsert
        await db.execute('''
            INSERT INTO clients (id, client_name, last_seen, metadata)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (id) DO UPDATE SET
                client_name = EXCLUDED.client_name,
                last_seen = EXCLUDED.last_seen,
                metadata = EXCLUDED.metadata
        ''', (client_id, client_name, datetime.now(), json.dumps(metadata)))
        await db.commit()

    return {"registered": True, "client_id": client_id, "client_name": client_name}

@app.post("/heartbeat")
async def heartbeat(req: HeartbeatRequest):
    client_id = req.client_id
    if client_id in clients_live:
        clients_live[client_id]["last_seen"] = datetime.now().isoformat()
    async with get_db() as db:
        await db.execute('UPDATE clients SET last_seen=%s WHERE id=%s', (datetime.now(), client_id))
        await db.commit()
    return {"ok": True}

@app.post("/poll")
async def poll_commands(req: PollRequest):
    client_id = req.client_id
    # Return and clear queued commands for this client
    cmds = commands_queue.get(client_id, [])
    commands_queue[client_id] = []
    return {"commands": cmds}

@app.post("/response")
async def post_response(resp: CommandResponse):
    command_id = resp.command_id
    data = resp.data

    # Persist logs if present (handle both 'logs' and 'raw_logs' keys)
    logs_key = 'raw_logs' if 'raw_logs' in data else 'logs'
    if isinstance(data, dict) and data.get(logs_key) is not None:
        try:
            print(f"🔄 Processing {logs_key} for {resp.client_id}...")
            logs_data = data.get(logs_key)
            is_compressed = data.get('compressed', False)
            print(f"   Logs data type: {type(logs_data)}, compressed: {is_compressed}")
            print(f"   Logs data length: {len(logs_data) if isinstance(logs_data, str) else 'N/A'}")

            # Get client name for temp directory
            client_name_for_storage = resp.client_id  # fallback
            if resp.client_id in clients_live:
                client_name_for_storage = clients_live[resp.client_id].get('client_name', resp.client_id).lower()

            # Create temp directory for this client
            temp_dir = os.path.join(BASE_DIR, 'temp', client_name_for_storage)
            os.makedirs(temp_dir, exist_ok=True)

            # Generate timestamp for filenames
            timestamp_str = datetime.now().strftime('%Y%m%d_%H%M%S')

            # If logs are compressed, save to disk first, then decompress
            if is_compressed and isinstance(logs_data, str):
                try:
                    # Save compressed data to disk
                    compressed_file = os.path.join(temp_dir, f'{timestamp_str}_compressed.gz.b64')
                    print(f"   Saving compressed data to: {compressed_file}")
                    with open(compressed_file, 'w') as f:
                        f.write(logs_data)
                    print(f"   ✅ Saved compressed data ({len(logs_data):,} bytes)")

                    # Decode base64
                    print(f"   Decoding base64...")
                    decoded_data = base64.b64decode(logs_data)

                    # Save decoded gzip to disk
                    gzip_file = os.path.join(temp_dir, f'{timestamp_str}_data.gz')
                    with open(gzip_file, 'wb') as f:
                        f.write(decoded_data)
                    print(f"   ✅ Saved gzip data to: {gzip_file} ({len(decoded_data):,} bytes)")

                    # Decompress
                    print(f"   Decompressing gzip...")
                    decompressed_data = gzip.decompress(decoded_data)

                    # Save decompressed JSON to disk
                    json_file = os.path.join(temp_dir, f'{timestamp_str}_data.json')
                    with open(json_file, 'wb') as f:
                        f.write(decompressed_data)
                    print(f"   ✅ Saved decompressed JSON to: {json_file} ({len(decompressed_data):,} bytes)")

                    # Decode UTF-8 and parse JSON
                    logs_json = decompressed_data.decode('utf-8')
                    print(f"📥 Decompressed {logs_key} for {resp.client_id}: {len(logs_json):,} chars")
                    logs_data = json.loads(logs_json)  # Convert to list for parsing

                    print(f"   ✅ All intermediate files saved to: {temp_dir}")
                except Exception as e:
                    print(f"❌ Failed to decompress {logs_key} for {resp.client_id}: {e}")
                    print(f"   Check files in: {temp_dir}")
                    import traceback
                    traceback.print_exc()
                    logs_data = None
            elif isinstance(logs_data, str):
                # Parse JSON string to list (uncompressed)
                try:
                    # Save uncompressed JSON to disk
                    json_file = os.path.join(temp_dir, f'{timestamp_str}_data.json')
                    with open(json_file, 'w') as f:
                        f.write(logs_data)
                    print(f"   ✅ Saved uncompressed JSON to: {json_file}")

                    logs_data = json.loads(logs_data)
                except Exception as e:
                    print(f"❌ Failed to parse log JSON: {e}")
                    print(f"   Check file: {json_file}")
                    logs_data = None

            # Parse log entries for individual row storage
            if logs_data:
                print(f"   Parsing log entries...")
                log_entries = parse_log_entries_for_storage(logs_data)
                print(f"   Parsed {len(log_entries)} log entries")

                # Save parsed entries to disk for debugging
                try:
                    parsed_file = os.path.join(temp_dir, f'{timestamp_str}_parsed.json')
                    with open(parsed_file, 'w') as f:
                        # Save first 100 entries as sample (full list would be huge)
                        sample_entries = log_entries[:100]
                        json.dump(sample_entries, f, indent=2, default=str)
                    print(f"   ✅ Saved parsed sample to: {parsed_file} (first 100 entries)")

                    # Save parsing statistics
                    stats_file = os.path.join(temp_dir, f'{timestamp_str}_stats.txt')
                    with open(stats_file, 'w') as f:
                        f.write(f"Parsing Statistics\n")
                        f.write(f"==================\n\n")
                        f.write(f"Total entries: {len(log_entries)}\n")

                        # Count by log type
                        log_types = {}
                        for entry in log_entries:
                            log_type = entry.get('log_type', 'unknown')
                            log_types[log_type] = log_types.get(log_type, 0) + 1

                        f.write(f"\nBy Log Type:\n")
                        for log_type, count in sorted(log_types.items(), key=lambda x: x[1], reverse=True):
                            f.write(f"  {log_type}: {count:,}\n")

                        # Count by action
                        actions = {}
                        for entry in log_entries:
                            action = entry.get('action', 'unknown')
                            actions[action] = actions.get(action, 0) + 1

                        f.write(f"\nBy Action:\n")
                        for action, count in sorted(actions.items(), key=lambda x: x[1], reverse=True):
                            f.write(f"  {action}: {count:,}\n")

                    print(f"   ✅ Saved parsing stats to: {stats_file}")
                except Exception as e:
                    print(f"   ⚠️  Failed to save parsed data: {e}")

                # Get client name for storage (normalize to lowercase)
                client_name_for_storage = resp.client_id  # fallback
                if resp.client_id in clients_live:
                    client_name_for_storage = clients_live[resp.client_id].get('client_name', resp.client_id).lower()

                print(f"   Storing {len(log_entries)} log entries to PostgreSQL...")
                total_inserted = await insert_log_entries_batch(
                    client_name_for_storage,
                    log_entries,
                    None  # No command_id for HTTP endpoint
                )
                print(f"✅ Stored {total_inserted} individual log entries for {resp.client_id}")
        except Exception as e:
            print(f"❌ CRITICAL ERROR storing logs for {resp.client_id}: {e}")
            import traceback
            traceback.print_exc()

    # Update command status/progress
    if command_id:
        is_progress = isinstance(data, dict) and (data.get('status') in ('in_progress', 'progress') or 'progress_pct' in data or 'files_done' in data)
        if is_progress:
            await update_command_progress(command_id, 'in_progress', data)
        else:
            await mark_command_complete(command_id, data)

    return {"ok": True}

@app.post("/command")
async def create_command(cmd: CreateCommandRequest):
    client_id = cmd.client_id
    command_id = str(uuid.uuid4())

    command = {
        "type": cmd.command_type,
        "id": command_id,
        "params": cmd.params or {},
        "timestamp": datetime.now().isoformat()
    }

    # Enrich update_client with files payload if missing
    if cmd.command_type == "update_client":
        try:
            params = command.get("params") or {}
            files = params.get("files") or []
            if not files:
                # Build files from repo
                file_defs = [
                    (os.path.join(BASE_DIR, "client", "pfsense_client.py"), "/usr/local/bin/pfsense_client.py", "0755"),
                    (os.path.join(BASE_DIR, "client", "psutil_stub.py"), "/usr/local/bin/psutil_stub.py", "0644"),
                ]
                files_payload = []
                for src, target, mode in file_defs:
                    if os.path.exists(src):
                        with open(src, "rb") as f:
                            content_b64 = base64.b64encode(f.read()).decode("utf-8")
                        files_payload.append({
                            "name": os.path.basename(src),
                            "path": os.path.relpath(src, BASE_DIR),
                            "target": target,
                            "mode": mode,
                            "content_b64": content_b64,
                        })
                params["files"] = files_payload
                params.setdefault("restart", True)
                params.setdefault("strategy", "replace_py")
                command["params"] = params
        except Exception as e:
            print(f"Warning: failed to embed files for update_client: {e}")

    # Save to DB
    try:
        async with get_db() as db:
            # PostgreSQL JSONB expects dict, not JSON string
            params_json = json.dumps(cmd.params or {})
            await db.execute('''
                INSERT INTO commands (id, client_id, command_type, params, created_at, status)
                VALUES (%s, %s, %s, %s, %s, %s)
            ''', (command_id, client_id, cmd.command_type, params_json, datetime.now(), 'queued'))
            await db.commit()
            print(f"✅ Command {command_id} saved to database")
    except Exception as e:
        print(f"❌ Failed to save command to database: {e}")
        print(f"   Command ID: {command_id}")
        print(f"   Client ID: {client_id}")
        print(f"   Command Type: {cmd.command_type}")
        print(f"   Params: {cmd.params}")
        raise HTTPException(status_code=500, detail=f"Failed to save command: {e}")


    # Try to send to WebSocket client first (for non-update commands)
    sent_via_websocket = await send_command_to_websocket_client(client_id, command)

    if not sent_via_websocket:
        # Push to in-memory queue for HTTP polling clients
        if client_id not in commands_queue:
            commands_queue[client_id] = []
        commands_queue[client_id].append(command)
        return {"enqueued": True, "command_id": command_id, "delivery": "queued_for_polling"}
    else:
        return {"enqueued": True, "command_id": command_id, "delivery": "sent_via_websocket"}

@app.get("/status")
async def server_status():
    # Summary for quick checks
    return {
        "status": "online",
        "clients": len(clients_live),
        "websocket_clients": len(websocket_connections),
        "server_time": datetime.now().isoformat()
    }

@app.get("/command/status")
async def command_status(command_id: str):
    result = await get_command_status(command_id)
    if not result:
        raise HTTPException(status_code=404, detail="Command not found")

    # Return formatted response matching /command/{command_id} endpoint
    return {
        "command_id": result['id'],
        "client_id": result['client_id'],
        "command_type": result['command_type'],
        "created_at": result['created_at'],
        "completed_at": result['completed_at'],
        "status": result['status'] or "pending",
        "progress": result['response_data']
    }

@app.get("/command/{command_id}")
async def get_command_status_endpoint(command_id: str):
    """Get command status by ID - returns 200 with 'pending' status instead of 404 for queued commands"""
    result = await get_command_status(command_id)
    if not result:
        raise HTTPException(status_code=404, detail="Command not found")

    # Return 200 OK even for pending/queued commands
    return {
        "command_id": result['id'],
        "client_id": result['client_id'],
        "command_type": result['command_type'],
        "created_at": result['created_at'],
        "completed_at": result['completed_at'],
        "status": result['status'] or "pending",
        "progress": result['response_data']
    }

# WebSocket endpoint
@app.post("/rules/ingest")
async def rules_ingest(payload: Dict[str, Any]):
    client_id = payload.get("client_id")
    rules_xml = payload.get("rules_xml")
    created_by_command_id = payload.get("command_id")
    if not client_id or not rules_xml:
        raise HTTPException(status_code=400, detail="client_id and rules_xml are required")

    # Compute metadata
    content_hash = hashlib.sha256(rules_xml.encode('utf-8')).hexdigest()
    size_bytes = len(rules_xml.encode('utf-8'))
    # Minimal rule count: count <rule tags
    rule_count = rules_xml.count('<rule')
    ruleset_id = str(uuid.uuid4())
    now = datetime.now()

    async with get_db() as db:
        # Resolve client_id to consistent identifier (handles both HTTP hash and WebSocket friendly name)
        client_name_for_storage = resolve_client_identifier(client_id)

        await db.execute('''
            INSERT INTO firewall_rules (client_id, ruleset_id, rules_xml, rule_count, ingested_at)
            VALUES (%s, %s, %s, %s, %s)
        ''', (client_name_for_storage, ruleset_id, rules_xml, rule_count, now))
        await db.commit()

    return {
        "success": True,
        "ruleset_id": ruleset_id,
        "client_id": client_id,
        "ingested_at": now.isoformat(),
        "content_hash": content_hash,
        "size_bytes": size_bytes,
        "rule_count": rule_count
    }

@app.get("/rules/status")
async def rules_status(client_id: str):
    # Resolve client_id to consistent identifier
    normalized_client_id = resolve_client_identifier(client_id)
    async with get_db() as db:
        cursor = await db.execute('''
            SELECT id, ingested_at, rule_count, ruleset_id
            FROM firewall_rules WHERE client_id = %s
            ORDER BY ingested_at DESC LIMIT 1
        ''', (normalized_client_id,))
        row = await db.fetchone(cursor)
        if not row:
            return {"success": True, "has_rules": False, "client_id": client_id}

        # PostgreSQL returns dict with RealDictCursor
        latest_id = row['id']
        ingested_at = row['ingested_at']
        rule_count = row['rule_count']
        ruleset_id = row.get('ruleset_id', '')

        # ingested_at is already a datetime object from PostgreSQL
        dt = ingested_at if isinstance(ingested_at, datetime) else datetime.fromisoformat(str(ingested_at))
        age_minutes = int((datetime.now() - dt).total_seconds() // 60)
        return {
            "success": True,
            "has_rules": True,
            "client_id": client_id,
            "latest_ruleset_id": ruleset_id,  # Use ruleset_id (UUID) instead of id (integer)
            "ingested_at": dt.isoformat(),
            "age_minutes": age_minutes,
            "rule_count": rule_count,
            "ruleset_id": ruleset_id
        }

@app.post("/rules/push")
async def rules_push(payload: Dict[str, Any]):
    client_id = payload.get("client_id")
    ruleset_id = payload.get("ruleset_id")
    if not client_id or not ruleset_id:
        raise HTTPException(status_code=400, detail="client_id and ruleset_id are required")

    # Resolve client_id to consistent identifier
    normalized_client_id = resolve_client_identifier(client_id)

    # Fetch latest ruleset for freshness
    async with get_db() as db:
        cur = await db.execute('''
            SELECT ruleset_id, ingested_at FROM firewall_rules WHERE client_id = %s ORDER BY ingested_at DESC LIMIT 1
        ''', (normalized_client_id,))
        latest = await db.fetchone(cur)
        if not latest:
            raise HTTPException(status_code=400, detail="No rules available to push for this client")
        latest_ruleset_id = latest['ruleset_id']
        latest_ingested_at = latest['ingested_at']
        # Already a datetime from PostgreSQL
        if isinstance(latest_ingested_at, str):
            try:
                latest_dt = datetime.fromisoformat(latest_ingested_at)
            except Exception:
                latest_dt = datetime.now()
        else:
            latest_dt = latest_ingested_at
        age_minutes = int((datetime.now() - latest_dt).total_seconds() // 60)
        if age_minutes > 360:
            raise HTTPException(status_code=409, detail="Latest rules are older than 6 hours; fetch latest before pushing")
        if ruleset_id != latest_ruleset_id:
            raise HTTPException(status_code=409, detail="Selected ruleset is not the latest; push is blocked to prevent stale updates")

        # Fetch rules_xml for the selected ruleset
        cur2 = await db.execute('''
            SELECT rules_xml FROM firewall_rules WHERE ruleset_id = %s AND client_id = %s
        ''', (ruleset_id, normalized_client_id))
        row = await db.fetchone(cur2)
        if not row:
            raise HTTPException(status_code=404, detail="Ruleset not found for client")
        rules_xml = row.get('rules_xml', '')

    # Build and insert command similar to /command
    command_id = str(uuid.uuid4())
    command = {
        "type": "set_rules",
        "id": command_id,
        "params": {"rules_xml": rules_xml},
        "timestamp": datetime.now().isoformat()
    }
    async with get_db() as db:
        await db.execute('''
            INSERT INTO commands (id, client_id, command_type, params, created_at, status)
            VALUES (%s, %s, %s, %s, %s, %s)
        ''', (command_id, client_id, "set_rules", json.dumps(command), datetime.now(), 'queued'))
        await db.commit()

    sent_via_websocket = await send_command_to_websocket_client(client_id, command)
    if not sent_via_websocket:
        if client_id not in commands_queue:
            commands_queue[client_id] = []
        commands_queue[client_id].append(command)
        return {"enqueued": True, "command_id": command_id, "delivery": "queued_for_polling"}
    else:
        return {"enqueued": True, "command_id": command_id, "delivery": "sent_via_websocket"}

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    client_id = None

    try:
        # Wait for initial registration message
        data = await websocket.receive_text()
        message = json.loads(data)

        if message.get("type") == "register":
            client_id = message.get("client_id")
            client_name = message.get("client_name", f"firewall-{client_id[:8]}")
            hostname = message.get("hostname", "unknown")
            system_health = message.get("system_health", {})

            if not client_id:
                await websocket.send_text(json.dumps({
                    "type": "error",
                    "message": "client_id required"
                }))
                return

            # Register client with system health (use client_name as primary identifier)
            clients_live[client_name] = {
                "client_name": client_name,
                "hostname": hostname,
                "last_seen": datetime.now().isoformat(),
                "connected_at": datetime.now().isoformat(),
                "connection_type": "websocket",
                "system_health": system_health,
                "hash_id": client_id  # Store hash as metadata
            }

            # Store WebSocket connection by client_name
            websocket_connections[client_name] = websocket

            # Save to database (use client_name as primary key)
            async with get_db() as db:
                # Combine hostname, system_health, and hash_id into metadata
                metadata = {
                    'hostname': hostname,
                    'system_health': system_health,
                    'hash_id': client_id
                }
                await db.execute('''
                    INSERT INTO clients (id, client_name, last_seen, metadata)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (id) DO UPDATE SET
                        client_name = EXCLUDED.client_name,
                        last_seen = EXCLUDED.last_seen,
                        metadata = EXCLUDED.metadata
                ''', (client_name, client_name, datetime.now(), json.dumps(metadata)))
                await db.commit()

            # Send registration confirmation
            await websocket.send_text(json.dumps({
                "type": "registered",
                "client_id": client_name,  # Return client_name as client_id
                "client_name": client_name
            }))

            print(f"✅ WebSocket client registered: {client_name}")

            # Send any queued commands (use client_name)
            if client_name in commands_queue and commands_queue[client_name]:
                for command in commands_queue[client_name]:
                    await websocket.send_text(json.dumps({
                        "type": "command",
                        "command": command
                    }))
                commands_queue[client_name] = []  # Clear queue

            # Keep connection alive and handle incoming messages
            while True:
                try:
                    data = await websocket.receive_text()
                    message = json.loads(data)

                    if message.get("type") == "heartbeat":
                        # Update last seen
                        if client_name in clients_live:
                            clients_live[client_name]["last_seen"] = datetime.now().isoformat()

                        # Update database
                        async with get_db() as db:
                            await db.execute('UPDATE clients SET last_seen=%s WHERE id=%s',
                                           (datetime.now(), client_name))
                            await db.commit()

                        # Send heartbeat response
                        await websocket.send_text(json.dumps({
                            "type": "heartbeat_ack",
                            "timestamp": datetime.now().isoformat()
                        }))

                    elif message.get("type") == "progress":
                        # Handle incremental progress update
                        command_id = message.get("command_id")
                        progress_data = message.get("data", {})
                        await update_command_progress(command_id, 'in_progress', progress_data)

                    elif message.get("type") == "log_batch":
                        # Handle batched log data
                        command_id = message.get("command_id")
                        batch_session_id = message.get("batch_session_id")
                        batch_num = message.get("batch_num")
                        total_batches = message.get("total_batches")
                        batch_data = message.get("batch_data")

                        print(f"📦 Received batch {batch_num}/{total_batches} for command {command_id[:8]}... ({len(batch_data):,} bytes)")

                        # Get client name for temp directory
                        client_name_for_storage = client_id  # fallback
                        if client_id in clients_live:
                            client_name_for_storage = clients_live[client_id].get('client_name', client_id).lower()

                        # Create temp directory for batches
                        temp_dir = os.path.join(BASE_DIR, 'temp', client_name_for_storage, 'batches', batch_session_id)
                        os.makedirs(temp_dir, exist_ok=True)

                        # Save this batch to disk (overwrite if retrying)
                        batch_file = os.path.join(temp_dir, f'batch_{batch_num:03d}.dat')
                        with open(batch_file, 'w') as f:
                            f.write(batch_data)

                        # Update progress (with error handling to prevent WebSocket crashes)
                        progress_data = {
                            "status": "in_progress",
                            "stage": "receiving_batches",
                            "batch_num": batch_num,
                            "total_batches": total_batches,
                            "progress_pct": int((batch_num / total_batches) * 100),
                            "timestamp": datetime.now().isoformat()
                        }

                        await update_command_progress(command_id, 'in_progress', progress_data)

                        # Check if all batches received
                        received_batches = len([f for f in os.listdir(temp_dir) if f.startswith('batch_')])

                        if received_batches == total_batches:
                            print(f"✅ All {total_batches} batches received, reassembling...")

                            # Reassemble all batches
                            reassembled_data = ""
                            for i in range(1, total_batches + 1):
                                batch_file = os.path.join(temp_dir, f'batch_{i:03d}.dat')
                                with open(batch_file, 'r') as f:
                                    reassembled_data += f.read()

                            print(f"   Reassembled {len(reassembled_data):,} bytes from {total_batches} batches")

                            # Process the reassembled data (same as regular log processing)
                            try:
                                # Move to main temp directory
                                main_temp_dir = os.path.join(BASE_DIR, 'temp', client_name_for_storage)
                                timestamp_str = datetime.now().strftime('%Y%m%d_%H%M%S')

                                # Save compressed data
                                compressed_file = os.path.join(main_temp_dir, f'{timestamp_str}_compressed.gz.b64')
                                with open(compressed_file, 'w') as f:
                                    f.write(reassembled_data)
                                print(f"   ✅ Saved reassembled compressed data ({len(reassembled_data):,} bytes)")

                                # Decode and decompress
                                decoded_data = base64.b64decode(reassembled_data)
                                gzip_file = os.path.join(main_temp_dir, f'{timestamp_str}_data.gz')
                                with open(gzip_file, 'wb') as f:
                                    f.write(decoded_data)
                                print(f"   ✅ Saved gzip data ({len(decoded_data):,} bytes)")

                                decompressed_data = gzip.decompress(decoded_data)
                                json_file = os.path.join(main_temp_dir, f'{timestamp_str}_data.json')
                                with open(json_file, 'wb') as f:
                                    f.write(decompressed_data)
                                print(f"   ✅ Saved decompressed JSON ({len(decompressed_data):,} bytes)")

                                # Parse and store logs
                                logs_json = decompressed_data.decode('utf-8')
                                logs_data = json.loads(logs_json)

                                # Parse log entries
                                log_entries = parse_log_entries_for_storage(logs_data)

                                # Save parsed sample and stats
                                parsed_file = os.path.join(main_temp_dir, f'{timestamp_str}_parsed.json')
                                with open(parsed_file, 'w') as f:
                                    sample_entries = log_entries[:100] if len(log_entries) > 100 else log_entries
                                    json.dump(sample_entries, f, indent=2, default=str)
                                print(f"   ✅ Saved parsed sample to: {parsed_file}")

                                # Generate statistics
                                stats_file = os.path.join(main_temp_dir, f'{timestamp_str}_stats.txt')
                                with open(stats_file, 'w') as f:
                                    f.write(f"Parsing Statistics\n")
                                    f.write(f"==================\n\n")
                                    f.write(f"Total entries: {len(log_entries):,}\n\n")

                                    # Count by log type
                                    log_types = {}
                                    for entry in log_entries:
                                        log_type = entry.get('log_type', 'unknown')
                                        log_types[log_type] = log_types.get(log_type, 0) + 1

                                    f.write(f"By Log Type:\n")
                                    for log_type, count in sorted(log_types.items(), key=lambda x: x[1], reverse=True):
                                        f.write(f"  {log_type}: {count:,}\n")
                                print(f"   ✅ Saved parsing stats to: {stats_file}")

                                # Store to database using PostgreSQL batch insert
                                print(f"   Inserting {len(log_entries):,} individual log entries...")
                                total_inserted = await insert_log_entries_batch(
                                    client_name_for_storage,
                                    log_entries,
                                    command_id
                                )

                                print(f"✅ Stored {total_inserted:,} individual log entries for {client_name_for_storage}")

                                # Clean up batch directory
                                import shutil
                                shutil.rmtree(os.path.join(BASE_DIR, 'temp', client_name_for_storage, 'batches', batch_session_id))

                                # Mark command as completed
                                await mark_command_complete(command_id, {
                                    'status': 'success',
                                    'entries_stored': total_inserted,
                                    'batches_received': total_batches
                                })

                            except Exception as e:
                                print(f"❌ Failed to process batched logs: {e}")
                                import traceback
                                traceback.print_exc()

                                # Mark command as failed
                                await mark_command_complete(command_id, {
                                    'status': 'error',
                                    'message': str(e)
                                })

                    elif message.get("type") == "response":
                        # Handle command final response
                        command_id = message.get("command_id")
                        response_data = message.get("data", {})

                        # Persist logs if present (same logic as HTTP endpoint)
                        # Handle both 'logs' and 'raw_logs' keys
                        logs_key = 'raw_logs' if 'raw_logs' in response_data else 'logs'
                        if isinstance(response_data, dict) and response_data.get(logs_key) is not None:
                            try:
                                print(f"🔄 Processing {logs_key} for {client_id} via WebSocket...")
                                logs_data = response_data.get(logs_key)
                                is_compressed = response_data.get('compressed', False)
                                print(f"   Logs data type: {type(logs_data)}, compressed: {is_compressed}")
                                print(f"   Logs data length: {len(logs_data) if isinstance(logs_data, str) else 'N/A'}")

                                # Get client name for temp directory
                                client_name_for_storage = client_id  # fallback
                                if client_id in clients_live:
                                    client_name_for_storage = clients_live[client_id].get('client_name', client_id).lower()

                                # Create temp directory for this client
                                temp_dir = os.path.join(BASE_DIR, 'temp', client_name_for_storage)
                                os.makedirs(temp_dir, exist_ok=True)

                                # Generate timestamp for filenames
                                timestamp_str = datetime.now().strftime('%Y%m%d_%H%M%S')

                                # If logs are compressed, save to disk first, then decompress
                                if is_compressed and isinstance(logs_data, str):
                                    try:
                                        # Save compressed data to disk
                                        compressed_file = os.path.join(temp_dir, f'{timestamp_str}_compressed.gz.b64')
                                        print(f"   Saving compressed data to: {compressed_file}")
                                        with open(compressed_file, 'w') as f:
                                            f.write(logs_data)
                                        print(f"   ✅ Saved compressed data ({len(logs_data):,} bytes)")

                                        # Decode base64
                                        print(f"   Decoding base64...")
                                        decoded_data = base64.b64decode(logs_data)

                                        # Save decoded gzip to disk
                                        gzip_file = os.path.join(temp_dir, f'{timestamp_str}_data.gz')
                                        with open(gzip_file, 'wb') as f:
                                            f.write(decoded_data)
                                        print(f"   ✅ Saved gzip data to: {gzip_file} ({len(decoded_data):,} bytes)")

                                        # Decompress
                                        print(f"   Decompressing gzip...")
                                        decompressed_data = gzip.decompress(decoded_data)

                                        # Save decompressed JSON to disk
                                        json_file = os.path.join(temp_dir, f'{timestamp_str}_data.json')
                                        with open(json_file, 'wb') as f:
                                            f.write(decompressed_data)
                                        print(f"   ✅ Saved decompressed JSON to: {json_file} ({len(decompressed_data):,} bytes)")

                                        # Decode UTF-8 and parse JSON
                                        logs_json = decompressed_data.decode('utf-8')
                                        print(f"📥 Decompressed {logs_key} for {client_id}: {len(logs_json):,} chars")
                                        logs_data = json.loads(logs_json)  # Convert to list for parsing

                                        print(f"   ✅ All intermediate files saved to: {temp_dir}")
                                    except Exception as e:
                                        print(f"❌ Failed to decompress {logs_key} for {client_id}: {e}")
                                        print(f"   Check files in: {temp_dir}")
                                        import traceback
                                        traceback.print_exc()
                                        logs_data = None
                                elif isinstance(logs_data, str):
                                    # Parse JSON string to list (uncompressed)
                                    try:
                                        # Save uncompressed JSON to disk
                                        json_file = os.path.join(temp_dir, f'{timestamp_str}_data.json')
                                        with open(json_file, 'w') as f:
                                            f.write(logs_data)
                                        print(f"   ✅ Saved uncompressed JSON to: {json_file}")

                                        logs_data = json.loads(logs_data)
                                    except Exception as e:
                                        print(f"❌ Failed to parse log JSON: {e}")
                                        print(f"   Check file: {json_file}")
                                        logs_data = None

                                # Parse log entries for individual row storage
                                if logs_data:
                                    print(f"   Parsing log entries...")
                                    log_entries = parse_log_entries_for_storage(logs_data)
                                    print(f"   Parsed {len(log_entries)} log entries")

                                    # Save parsed entries to disk for debugging
                                    try:
                                        parsed_file = os.path.join(temp_dir, f'{timestamp_str}_parsed.json')
                                        with open(parsed_file, 'w') as f:
                                            # Save first 100 entries as sample
                                            sample_entries = log_entries[:100]
                                            json.dump(sample_entries, f, indent=2, default=str)
                                        print(f"   ✅ Saved parsed sample to: {parsed_file} (first 100 entries)")

                                        # Save parsing statistics
                                        stats_file = os.path.join(temp_dir, f'{timestamp_str}_stats.txt')
                                        with open(stats_file, 'w') as f:
                                            f.write(f"Parsing Statistics\n")
                                            f.write(f"==================\n\n")
                                            f.write(f"Total entries: {len(log_entries)}\n")

                                            # Count by log type
                                            log_types = {}
                                            for entry in log_entries:
                                                log_type = entry.get('log_type', 'unknown')
                                                log_types[log_type] = log_types.get(log_type, 0) + 1

                                            f.write(f"\nBy Log Type:\n")
                                            for log_type, count in sorted(log_types.items(), key=lambda x: x[1], reverse=True):
                                                f.write(f"  {log_type}: {count:,}\n")

                                            # Count by action
                                            actions = {}
                                            for entry in log_entries:
                                                action = entry.get('action', 'unknown')
                                                actions[action] = actions.get(action, 0) + 1

                                            f.write(f"\nBy Action:\n")
                                            for action, count in sorted(actions.items(), key=lambda x: x[1], reverse=True):
                                                f.write(f"  {action}: {count:,}\n")

                                        print(f"   ✅ Saved parsing stats to: {stats_file}")
                                    except Exception as e:
                                        print(f"   ⚠️  Failed to save parsed data: {e}")

                                    # Get client name for storage (normalize to lowercase)
                                    client_name_for_storage = client_id  # fallback
                                    if client_id in clients_live:
                                        client_name_for_storage = clients_live[client_id].get('client_name', client_id).lower()

                                    print(f"   Storing {len(log_entries)} log entries to PostgreSQL...")
                                    total_inserted = await insert_log_entries_batch(
                                        client_name_for_storage,
                                        log_entries,
                                        command_id
                                    )
                                    print(f"✅ Stored {total_inserted} individual log entries for {client_id}")
                            except Exception as e:
                                print(f"❌ CRITICAL ERROR storing logs for {client_id}: {e}")
                                import traceback
                                traceback.print_exc()

                        # Update command status
                        await mark_command_complete(command_id, response_data)
                        print(f"📨 Received response from {client_id} for command {command_id}")

                except WebSocketDisconnect:
                    break
                except json.JSONDecodeError:
                    await websocket.send_text(json.dumps({
                        "type": "error",
                        "message": "Invalid JSON"
                    }))
                except Exception as e:
                    print(f"❌ WebSocket error for {client_id}: {e}")
                    break

        else:
            await websocket.send_text(json.dumps({
                "type": "error",
                "message": "First message must be registration"
            }))

    except WebSocketDisconnect:
        pass
    except Exception as e:
        print(f"❌ WebSocket connection error: {e}")

    finally:
        # Clean up on disconnect
        if client_id:
            if client_id in websocket_connections:
                del websocket_connections[client_id]
            if client_id in clients_live:
                del clients_live[client_id]
            print(f"🔌 WebSocket client disconnected: {client_id}")

# Helper function to send command to WebSocket client
async def send_command_to_websocket_client(client_id: str, command: Dict[str, Any]) -> bool:
    """Send command to WebSocket client if connected"""
    # First try direct client_id lookup
    target_client_id = client_id

    # If not found, try to find by client name
    if client_id not in websocket_connections:
        for cid, client_info in clients_live.items():
            if client_info.get('client_name') == client_id:
                target_client_id = cid
                break

    if target_client_id in websocket_connections:
        try:
            websocket = websocket_connections[target_client_id]
            await websocket.send_text(json.dumps({
                "type": "command",
                "command": command
            }))
            print(f"📨 Sent command to WebSocket client {target_client_id} (requested as {client_id})")
            return True
        except Exception as e:
            print(f"❌ Failed to send command to WebSocket client {target_client_id}: {e}")
            # Remove broken connection
            if target_client_id in websocket_connections:
                del websocket_connections[target_client_id]
            if target_client_id in clients_live:
                del clients_live[target_client_id]
    return False

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)