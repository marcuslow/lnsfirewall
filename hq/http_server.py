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

DB_PATH = "hq_database.db"

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

    clients_live[client_id] = {
        "client_name": client_name,
        "hostname": hostname,
        "last_seen": datetime.now().isoformat(),
        "connected_at": datetime.now().isoformat()
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

    # Store command completion
    if command_id:
        async with aiosqlite.connect(DB_PATH) as db:
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

# WebSocket endpoint
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

            if not client_id:
                await websocket.send_text(json.dumps({
                    "type": "error",
                    "message": "client_id required"
                }))
                return

            # Register client
            clients_live[client_id] = {
                "client_name": client_name,
                "hostname": hostname,
                "last_seen": datetime.now().isoformat(),
                "connected_at": datetime.now().isoformat(),
                "connection_type": "websocket"
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

                    elif message.get("type") == "response":
                        # Handle command response
                        command_id = message.get("command_id")
                        response_data = message.get("data", {})

                        # Store response in database
                        async with aiosqlite.connect(DB_PATH) as db:
                            await db.execute('''
                                UPDATE commands SET status=?, response_data=?, completed_at=?
                                WHERE id=? AND client_id=?
                            ''', ('completed', json.dumps(response_data), datetime.now(), command_id, client_id))
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
    if client_id in websocket_connections:
        try:
            websocket = websocket_connections[client_id]
            await websocket.send_text(json.dumps({
                "type": "command",
                "command": command
            }))
            return True
        except Exception as e:
            print(f"❌ Failed to send command to WebSocket client {client_id}: {e}")
            # Remove broken connection
            if client_id in websocket_connections:
                del websocket_connections[client_id]
            if client_id in clients_live:
                del clients_live[client_id]
    return False

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)