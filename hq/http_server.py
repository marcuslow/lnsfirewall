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
import aiosqlite
import websockets
import os
import hashlib

# Use a single, absolute DB path so AI and server share the same file
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # repo root
DB_PATH = os.getenv("HQ_DB_PATH", os.path.join(BASE_DIR, "hq_database.db"))

app = FastAPI(title="pfSense Firewall HQ (HTTP)")

# In-memory connections (for live view); persistence is via SQLite
clients_live: Dict[str, Dict[str, Any]] = {}
commands_queue: Dict[str, List[Dict[str, Any]]] = {}

# WebSocket connections
websocket_connections: Dict[str, WebSocket] = {}  # client_id -> WebSocket

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
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute('''
            CREATE TABLE IF NOT EXISTS clients (
                client_id TEXT PRIMARY KEY,
                client_name TEXT,
                hostname TEXT,
                first_seen TIMESTAMP,
                last_seen TIMESTAMP,
                status_data TEXT
            )
        ''')
        await db.execute('''
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_id TEXT,
                timestamp TIMESTAMP,
                log_data TEXT,
                compressed BOOLEAN,
                size_bytes INTEGER,
                FOREIGN KEY (client_id) REFERENCES clients (client_id)
            )
        ''')
        await db.execute('''
            CREATE TABLE IF NOT EXISTS commands (
                id TEXT PRIMARY KEY,
                client_id TEXT,
                command_type TEXT,
                command_data TEXT,
                created_at TIMESTAMP,
                completed_at TIMESTAMP,
                status TEXT,
                response_data TEXT
            )
        ''')
        await db.execute('''
            CREATE TABLE IF NOT EXISTS rulesets (
                id TEXT PRIMARY KEY,
                client_id TEXT NOT NULL,
                ingested_at TIMESTAMP NOT NULL,
                content_hash TEXT NOT NULL,
                size_bytes INTEGER NOT NULL,
                rule_count INTEGER NOT NULL,
                created_by_command_id TEXT,
                compressed BOOLEAN DEFAULT 0,
                rules_xml TEXT
            )
        ''')
        await db.execute('''
            CREATE INDEX IF NOT EXISTS idx_rulesets_client_time
            ON rulesets(client_id, ingested_at DESC)
        ''')
        await db.commit()

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

    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute('''
            INSERT OR REPLACE INTO clients (client_id, client_name, hostname, first_seen, last_seen)
            VALUES (?, ?, ?, COALESCE((SELECT first_seen FROM clients WHERE client_id=?), ?), ?)
        ''', (client_id, client_name, hostname, client_id, datetime.now(), datetime.now()))
        await db.commit()

    return {"registered": True, "client_id": client_id, "client_name": client_name}

@app.post("/heartbeat")
async def heartbeat(req: HeartbeatRequest):
    client_id = req.client_id
    if client_id in clients_live:
        clients_live[client_id]["last_seen"] = datetime.now().isoformat()
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute('UPDATE clients SET last_seen=? WHERE client_id=?', (datetime.now(), client_id))
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

    # Persist logs if present
    if isinstance(data, dict) and data.get("logs") is not None:
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute('''
                INSERT INTO logs (client_id, timestamp, log_data, compressed, size_bytes)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                resp.client_id,
                datetime.now(),
                json.dumps(data.get('logs')),
                data.get('compressed', False),
                data.get('size_bytes', 0)
            ))
            await db.commit()

    # Update command status/progress
    if command_id:
        is_progress = isinstance(data, dict) and (data.get('status') in ('in_progress', 'progress') or 'progress_pct' in data or 'files_done' in data)
        async with aiosqlite.connect(DB_PATH) as db:
            if is_progress:
                await db.execute('''
                    UPDATE commands
                    SET status=?, response_data=?
                    WHERE id=?
                ''', ('in_progress', json.dumps(data), command_id))
            else:
                await db.execute('''
                    UPDATE commands
                    SET completed_at=?, status=?, response_data=?
                    WHERE id=?
                ''', (datetime.now(), data.get('status', 'unknown'), json.dumps(data), command_id))
            await db.commit()

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

    # Save to DB
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute('''
            INSERT INTO commands (id, client_id, command_type, command_data, created_at, status)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (command_id, client_id, cmd.command_type, json.dumps(command), datetime.now(), 'queued'))
        await db.commit()

    # Try to send to WebSocket client first
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
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute('''
            SELECT id, client_id, command_type, created_at, completed_at, status, response_data
            FROM commands WHERE id = ?
        ''', (command_id,))
        row = await cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Command not found")
        id_, client_id, command_type, created_at, completed_at, status, response_data = row
        try:
            progress = json.loads(response_data) if response_data else None
        except Exception:
            progress = None
        return {
            "command_id": id_,
            "client_id": client_id,
            "command_type": command_type,
            "created_at": created_at.isoformat() if hasattr(created_at, "isoformat") else str(created_at) if created_at else None,
            "completed_at": completed_at.isoformat() if hasattr(completed_at, "isoformat") else str(completed_at) if completed_at else None,
            "status": status,
            "progress": progress
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

    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute('''
            INSERT INTO rulesets (id, client_id, ingested_at, content_hash, size_bytes, rule_count, created_by_command_id, compressed, rules_xml)
            VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)
        ''', (ruleset_id, client_id, now, content_hash, size_bytes, rule_count, created_by_command_id, rules_xml))
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
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute('''
            SELECT id, ingested_at, rule_count, size_bytes, content_hash
            FROM rulesets WHERE client_id = ?
            ORDER BY ingested_at DESC LIMIT 1
        ''', (client_id,))
        row = await cursor.fetchone()
        if not row:
            return {"success": True, "has_rules": False, "client_id": client_id}
        latest_id, ingested_at, rule_count, size_bytes, content_hash = row
        # ingested_at stored as string or datetime depending on sqlite adapter; coerce
        if isinstance(ingested_at, str):
            try:
                dt = datetime.fromisoformat(ingested_at)
            except Exception:
                dt = datetime.now()
        else:
            dt = ingested_at
        age_minutes = int((datetime.now() - dt).total_seconds() // 60)
        return {
            "success": True,
            "has_rules": True,
            "client_id": client_id,
            "latest_ruleset_id": latest_id,
            "ingested_at": dt.isoformat(),
            "age_minutes": age_minutes,
            "rule_count": rule_count,
            "size_bytes": size_bytes,
            "content_hash": content_hash
        }

@app.post("/rules/push")
async def rules_push(payload: Dict[str, Any]):
    client_id = payload.get("client_id")
    ruleset_id = payload.get("ruleset_id")
    if not client_id or not ruleset_id:
        raise HTTPException(status_code=400, detail="client_id and ruleset_id are required")

    # Fetch latest ruleset for freshness
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute('''
            SELECT id, ingested_at FROM rulesets WHERE client_id = ? ORDER BY ingested_at DESC LIMIT 1
        ''', (client_id,))
        latest = await cur.fetchone()
        if not latest:
            raise HTTPException(status_code=400, detail="No rules available to push for this client")
        latest_id, latest_ingested_at = latest
        # Coerce to datetime
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
        if ruleset_id != latest_id:
            raise HTTPException(status_code=409, detail="Selected ruleset is not the latest; push is blocked to prevent stale updates")

        # Fetch rules_xml for the selected ruleset
        cur2 = await db.execute('''
            SELECT rules_xml FROM rulesets WHERE id = ? AND client_id = ?
        ''', (ruleset_id, client_id))
        row = await cur2.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Ruleset not found for client")
        rules_xml = row[0]

    # Build and insert command similar to /command
    command_id = str(uuid.uuid4())
    command = {
        "type": "set_rules",
        "id": command_id,
        "params": {"rules_xml": rules_xml},
        "timestamp": datetime.now().isoformat()
    }
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute('''
            INSERT INTO commands (id, client_id, command_type, command_data, created_at, status)
            VALUES (?, ?, ?, ?, ?, ?)
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

            # Register client with system health
            clients_live[client_id] = {
                "client_name": client_name,
                "hostname": hostname,
                "last_seen": datetime.now().isoformat(),
                "connected_at": datetime.now().isoformat(),
                "connection_type": "websocket",
                "system_health": system_health
            }

            # Store WebSocket connection
            websocket_connections[client_id] = websocket

            # Save to database
            async with aiosqlite.connect(DB_PATH) as db:
                await db.execute('''
                    INSERT OR REPLACE INTO clients (client_id, client_name, hostname, first_seen, last_seen)
                    VALUES (?, ?, ?, COALESCE((SELECT first_seen FROM clients WHERE client_id=?), ?), ?)
                ''', (client_id, client_name, hostname, client_id, datetime.now(), datetime.now()))
                await db.commit()

            # Send registration confirmation
            await websocket.send_text(json.dumps({
                "type": "registered",
                "client_id": client_id,
                "client_name": client_name
            }))

            print(f"✅ WebSocket client registered: {client_name} ({client_id})")

            # Send any queued commands
            if client_id in commands_queue and commands_queue[client_id]:
                for command in commands_queue[client_id]:
                    await websocket.send_text(json.dumps({
                        "type": "command",
                        "command": command
                    }))
                commands_queue[client_id] = []  # Clear queue

            # Keep connection alive and handle incoming messages
            while True:
                try:
                    data = await websocket.receive_text()
                    message = json.loads(data)

                    if message.get("type") == "heartbeat":
                        # Update last seen
                        if client_id in clients_live:
                            clients_live[client_id]["last_seen"] = datetime.now().isoformat()

                        # Update database
                        async with aiosqlite.connect(DB_PATH) as db:
                            await db.execute('UPDATE clients SET last_seen=? WHERE client_id=?',
                                           (datetime.now(), client_id))
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
                        async with aiosqlite.connect(DB_PATH) as db:
                            await db.execute('''
                                UPDATE commands SET status=?, response_data=?
                                WHERE id=?
                            ''', ('in_progress', json.dumps(progress_data), command_id))
                            await db.commit()

                    elif message.get("type") == "response":
                        # Handle command final response
                        command_id = message.get("command_id")
                        response_data = message.get("data", {})
                        async with aiosqlite.connect(DB_PATH) as db:
                            await db.execute('''
                                UPDATE commands SET status=?, response_data=?, completed_at=?
                                WHERE id=?
                            ''', ('completed', json.dumps(response_data), datetime.now(), command_id))
                            await db.commit()
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