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

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class AICommandCenter:
    def __init__(self, hq_url: str, openai_api_key: str, db_path: str = 'hq_database.db'):
        self.hq_url = hq_url.rstrip('/')
        self.db_path = db_path
        self.openai_client = openai.OpenAI(api_key=openai_api_key)
        self.conversation_history = []

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
                                "description": "Optional client ID or client name to get status for specific client. Can be a single client or comma-separated list. If not provided, returns status for all clients. Examples: 'opus-1', 'opus-1,james-office,central-lion', 'firewall-branch-2'"
                            }
                        }
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "request_client_logs",
                    "description": "Request firewall logs from one or all clients for a specified time period. Includes filter logs, pfBlockerNG logs, and system logs with detailed parsing and statistics.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "client_id": {
                                "type": "string",
                                "description": "Client ID or client name to request logs from. Can be single client, comma-separated list, or 'all' for all clients. Examples: 'opus-1', 'opus-1,james-office,central-lion', 'all'"
                            },
                            "days": {
                                "type": "integer",
                                "description": "Number of days of logs to retrieve (max 90)",
                                "minimum": 1,
                                "maximum": 90
                            }
                        },
                        "required": ["client_id", "days"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "get_firewall_rules",
                    "description": "Get current firewall rules from a specific client",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "client_id": {
                                "type": "string",
                                "description": "Client ID to get firewall rules from"
                            }
                        },
                        "required": ["client_id"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "update_firewall_rules",
                    "description": "Update firewall rules on a specific client",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "client_id": {
                                "type": "string",
                                "description": "Client ID to update firewall rules on"
                            },
                            "rules_xml": {
                                "type": "string",
                                "description": "New firewall rules in XML format"
                            }
                        },
                        "required": ["client_id", "rules_xml"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "restart_firewall",
                    "description": "Restart firewall service on a specific client",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "client_id": {
                                "type": "string",
                                "description": "Client ID to restart firewall on"
                            }
                        },
                        "required": ["client_id"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "get_stored_logs",
                    "description": "Retrieve previously collected logs from the database",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "client_id": {
                                "type": "string",
                                "description": "Optional client ID to filter logs. If not provided, returns logs from all clients"
                            },
                            "days": {
                                "type": "integer",
                                "description": "Number of days back to retrieve logs from database",
                                "minimum": 1,
                                "maximum": 365
                            }
                        }
                    }
                }
            }
        ]

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

            return {"success": True, "message": f"Log collection requested from {len(ids)} client(s)", "clients": results}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def get_firewall_rules(self, client_id: str) -> Dict[str, Any]:
        """Enqueue get_rules for client via HTTP"""
        try:
            r = requests.post(f"{self.hq_url}/command", json={"client_id": client_id, "command_type": "get_rules"}, timeout=30)
            r.raise_for_status()
            return {"success": True, "message": f"Firewall rules requested from client {client_id}", "command_id": r.json().get('command_id')}
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
            elif function_name == "get_firewall_rules":
                return await self.get_firewall_rules(arguments['client_id'])
            elif function_name == "update_firewall_rules":
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
            else:
                return {"success": False, "error": f"Unknown function: {function_name}"}

        except Exception as e:
            return {"success": False, "error": str(e)}

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
4. Restart firewall services
5. Retrieve previously stored logs from the database

Log Analysis Capabilities:
- Parse pfSense filter logs with rule numbers, interfaces, actions, protocols, IPs
- Parse pfBlockerNG logs with block lists, threat categories, source/destination details
- Generate statistics: blocked vs allowed connections, top source/destination IPs, protocol distribution
- Track security events and potential threats

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

            # Prepare messages for OpenAI
            messages = [system_message] + self.conversation_history[-10:]  # Keep last 10 messages

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

                    logger.info(f"Executing function: {function_name} with args: {arguments}")

                    result = await self.execute_function_call(function_name, arguments)

                    # Add function result to conversation
                    self.conversation_history.append({
                        "role": "tool",
                        "tool_call_id": tool_call.id,
                        "content": json.dumps(result)
                    })

                    function_results.append(result)

                # Get final response from AI with function results
                final_response = self.openai_client.chat.completions.create(
                    model="gpt-4",
                    messages=[system_message] + self.conversation_history[-15:],
                    temperature=0.7,
                    max_tokens=1500
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
    parser.add_argument('--db', default='hq_database.db', help='Database file path')

    args = parser.parse_args()

    # Get OpenAI API key from args or environment
    openai_key = args.openai_key or os.getenv('OPENAI_API_KEY')

    if not openai_key:
        print("❌ OpenAI API key is required!")
        print("Either:")
        print("  1. Set OPENAI_API_KEY in your .env file, or")
        print("  2. Use --openai-key argument")
        return

    # Create AI Command Center (HTTP mode)
    ai_center = AICommandCenter(args.hq_url, openai_key, args.db)

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