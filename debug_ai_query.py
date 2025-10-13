#!/usr/bin/env python3
"""Debug why AI query returns 0 results"""
import asyncio
import sys
from hq.ai_command_center import AICommandCenter

async def debug_query():
    print("=" * 60)
    print("DEBUG: AI Query Execution")
    print("=" * 60)
    
    ai = AICommandCenter(
        hq_url="http://localhost:8000",
        openai_api_key="test-key"
    )
    
    # Test 1: Check what client_id is being used
    print("\n1. Checking client resolution...")
    import requests
    r = requests.get("http://localhost:8000/clients")
    clients = r.json().get('clients', {})
    print(f"   Available clients: {list(clients.keys())}")
    for k, v in clients.items():
        print(f"   - {k}: {v.get('client_name')}")
    
    # Test 2: Manually resolve client_id
    print("\n2. Resolving 'opus-1'...")
    client_id = "opus-1"
    actual_client_id = client_id
    client_name_for_db = client_id.lower()
    
    name_to_id = {v.get('client_name', ''): k for k, v in clients.items()}
    if client_id in name_to_id:
        actual_client_id = name_to_id[client_id]
        print(f"   Resolved to client_id: {actual_client_id}")
    
    for cid, info in clients.items():
        if cid == actual_client_id or info.get('client_name', '').lower() == client_id.lower():
            client_name_for_db = info.get('client_name', client_id).lower()
            print(f"   client_name_for_db: {client_name_for_db}")
            break
    
    # Test 3: Check database directly
    print("\n3. Checking database...")
    import sqlite3
    conn = sqlite3.connect('hq_database.db')
    cur = conn.cursor()
    
    cur.execute('SELECT DISTINCT client_id FROM log_entries')
    db_clients = [row[0] for row in cur.fetchall()]
    print(f"   client_ids in database: {db_clients}")
    
    # Test 4: Try LogQueryEngine with the resolved client_name
    print(f"\n4. Testing LogQueryEngine with client_id='{client_name_for_db}'...")
    from hq.lqe import LogQueryEngine
    
    lqe = LogQueryEngine.from_db('hq_database.db', client_name_for_db, since_days=7, sample_rate=5)
    print(f"   Loaded {len(lqe.entries)} entries")
    
    if len(lqe.entries) > 0:
        summary = lqe.summarize(top_n=5)
        print(f"   Blocked count: {summary['blocked_count']}")
        print(f"   Allowed count: {summary['allowed_count']}")
    else:
        print("   ❌ No entries loaded!")
    
    # Test 5: Run the actual query_logs function
    print("\n5. Running actual query_logs function...")
    result = await ai.query_logs(
        client_id="opus-1",
        query="risk assessment",
        days=7,
        auto_refresh=False
    )
    
    print(f"   Success: {result.get('success')}")
    if result.get('success'):
        results = result.get('results', {})
        print(f"   Risk level: {results.get('risk_level')}")
        print(f"   Blocked events: {results.get('blocked_events', {}).get('count', 0)}")
    else:
        print(f"   Error: {result.get('error')}")
    
    conn.close()

if __name__ == "__main__":
    asyncio.run(debug_query())

