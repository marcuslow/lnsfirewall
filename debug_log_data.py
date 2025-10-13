#!/usr/bin/env python3
"""
Debug script to examine actual log data structure in the database
"""
import sqlite3
import json
import gzip
import base64
from datetime import datetime, timedelta

def examine_log_data(db_path="hq_database.db", client_id=None, limit=5):
    """Examine the actual structure of log data in the database"""
    print("=== Log Data Structure Analysis ===")
    
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    
    # Get basic info
    if client_id:
        cur.execute("SELECT COUNT(*) FROM logs WHERE client_id = ?", (client_id,))
    else:
        cur.execute("SELECT COUNT(*) FROM logs")
    total_logs = cur.fetchone()[0]
    print(f"Total log entries in DB: {total_logs}")
    
    # Get recent logs
    if client_id:
        cur.execute("""
            SELECT client_id, timestamp, log_data, compressed, size_bytes 
            FROM logs 
            WHERE client_id = ? 
            ORDER BY timestamp DESC 
            LIMIT ?
        """, (client_id, limit))
    else:
        cur.execute("""
            SELECT client_id, timestamp, log_data, compressed, size_bytes 
            FROM logs 
            ORDER BY timestamp DESC 
            LIMIT ?
        """, (limit,))
    
    rows = cur.fetchall()
    
    for i, (cid, ts, log_data, compressed, size_bytes) in enumerate(rows):
        print(f"\n--- Log Entry {i+1} ---")
        print(f"Client ID: {cid}")
        print(f"Timestamp: {ts}")
        print(f"Compressed: {compressed}")
        print(f"Size: {size_bytes} bytes")
        
        # Decompress if needed
        if compressed:
            try:
                compressed_data = base64.b64decode(log_data.encode('utf-8'))
                decompressed_data = gzip.decompress(compressed_data)
                log_entries = json.loads(decompressed_data.decode('utf-8'))
            except Exception as e:
                print(f"Error decompressing: {e}")
                continue
        else:
            try:
                log_entries = json.loads(log_data)
            except Exception as e:
                print(f"Error parsing JSON: {e}")
                continue
        
        print(f"Number of log entries: {len(log_entries) if isinstance(log_entries, list) else 'Not a list'}")
        
        # Examine first few entries
        if isinstance(log_entries, list) and log_entries:
            print(f"\n--- Sample Log Entries (first 3) ---")
            for j, entry in enumerate(log_entries[:3]):
                print(f"\nEntry {j+1}:")
                if isinstance(entry, dict):
                    # Show all fields
                    for key, value in entry.items():
                        print(f"  {key}: {value}")
                else:
                    print(f"  Raw: {entry}")
        
        # Count actions if possible
        if isinstance(log_entries, list):
            actions = {}
            blocked_count = 0
            allowed_count = 0
            
            for entry in log_entries:
                if isinstance(entry, dict):
                    action = entry.get('action')
                    if action:
                        actions[action] = actions.get(action, 0) + 1
                        if action in ('block', 'blocked', 'reject'):
                            blocked_count += 1
                        elif action in ('pass', 'allow', 'allowed'):
                            allowed_count += 1
            
            print(f"\n--- Action Summary ---")
            print(f"Actions found: {actions}")
            print(f"Blocked: {blocked_count}")
            print(f"Allowed: {allowed_count}")
    
    conn.close()

def test_lqe_with_real_data(db_path="hq_database.db", client_id=None):
    """Test LogQueryEngine with real data from database"""
    print(f"\n=== Testing LogQueryEngine with Real Data ===")
    
    import sys
    import os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'hq'))
    from lqe import LogQueryEngine
    
    try:
        lqe = LogQueryEngine.from_db(db_path, client_id, since_days=7)
        print(f"LQE loaded {len(lqe.entries)} entries")
        
        if lqe.entries:
            print(f"\n--- First Entry Analysis ---")
            first_entry = lqe.entries[0]
            print(f"Timestamp: {first_entry.timestamp}")
            print(f"Action: {first_entry.action}")
            print(f"Interface: {first_entry.interface}")
            print(f"Protocol: {first_entry.proto}")
            print(f"Source: {first_entry.src}")
            print(f"Source Port: {first_entry.src_port}")
            print(f"Destination: {first_entry.dst}")
            print(f"Destination Port: {first_entry.dst_port}")
            
            print(f"\n--- Basic Filters Test ---")
            blocked = lqe.filter_blocked()
            allowed = lqe.filter_allowed()
            print(f"Blocked entries: {len(blocked)}")
            print(f"Allowed entries: {len(allowed)}")
            
            if blocked:
                print(f"\n--- Sample Blocked Entry ---")
                sample_blocked = blocked[0]
                print(f"Action: {sample_blocked.action}")
                print(f"Source: {sample_blocked.src}")
                print(f"Destination: {sample_blocked.dst}:{sample_blocked.dst_port}")
            
            # Test new methods
            print(f"\n--- Advanced Detection Test ---")
            brute_force = lqe.detect_brute_force(threshold=5)
            port_scans = lqe.detect_port_scans(threshold=10)
            top_blocked = lqe.get_top_blocked_ips(top_n=5)
            
            print(f"Brute force attempts: {len(brute_force)}")
            print(f"Port scan attempts: {len(port_scans)}")
            print(f"Top blocked IPs: {top_blocked}")
            
        else:
            print("No entries found in LQE!")
            
    except Exception as e:
        print(f"Error testing LQE: {e}")
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    import sys
    
    client_id = None
    if len(sys.argv) > 1:
        client_id = sys.argv[1]
        print(f"Analyzing logs for client: {client_id}")
    else:
        print("Analyzing logs for all clients")
        print("Usage: python debug_log_data.py [client_id]")
    
    examine_log_data(client_id=client_id)
    test_lqe_with_real_data(client_id=client_id)
