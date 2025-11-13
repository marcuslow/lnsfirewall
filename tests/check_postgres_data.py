#!/usr/bin/env python3
"""Check PostgreSQL database for legitimate data"""

import psycopg2
import psycopg2.extras

DB_CONFIG = {
    'host': 'localhost',
    'port': 5432,
    'database': 'lnsfirewall',
    'user': 'postgres',
    'password': 'lnsFirewall2024!',
}

try:
    conn = psycopg2.connect(**DB_CONFIG)
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    
    print("=" * 70)
    print("PostgreSQL Database Check")
    print("=" * 70)
    
    # 1. Check clients table
    print("\n1. CLIENTS TABLE:")
    print("-" * 70)
    cur.execute("SELECT id, client_name, last_seen, metadata FROM clients")
    clients = cur.fetchall()
    print(f"Total clients: {len(clients)}")
    for client in clients:
        print(f"  ID: {client['id']}")
        print(f"  Name: {client['client_name']}")
        print(f"  Last seen: {client['last_seen']}")
        print(f"  Metadata: {client['metadata']}")
        print()
    
    # 2. Check commands table
    print("\n2. COMMANDS TABLE:")
    print("-" * 70)
    cur.execute("""
        SELECT id, client_id, command_type, status, created_at, completed_at 
        FROM commands 
        ORDER BY created_at DESC 
        LIMIT 10
    """)
    commands = cur.fetchall()
    print(f"Total commands (showing last 10): {len(commands)}")
    for cmd in commands:
        print(f"  ID: {cmd['id'][:8]}...")
        print(f"  Client: {cmd['client_id']}")
        print(f"  Type: {cmd['command_type']}")
        print(f"  Status: {cmd['status']}")
        print(f"  Created: {cmd['created_at']}")
        print(f"  Completed: {cmd['completed_at']}")
        print()
    
    # 3. Check log_entries table
    print("\n3. LOG_ENTRIES TABLE:")
    print("-" * 70)
    
    # Count total entries
    cur.execute("SELECT COUNT(*) as count FROM log_entries")
    total = cur.fetchone()['count']
    print(f"Total log entries: {total:,}")
    
    # Count by client
    cur.execute("""
        SELECT client_id, COUNT(*) as count 
        FROM log_entries 
        GROUP BY client_id
    """)
    by_client = cur.fetchall()
    print(f"\nEntries by client:")
    for row in by_client:
        print(f"  {row['client_id']}: {row['count']:,} entries")
    
    # Check date range
    cur.execute("""
        SELECT 
            MIN(log_timestamp) as earliest,
            MAX(log_timestamp) as latest
        FROM log_entries
    """)
    date_range = cur.fetchone()
    print(f"\nDate range:")
    print(f"  Earliest: {date_range['earliest']}")
    print(f"  Latest: {date_range['latest']}")
    
    # Sample entries
    print(f"\nSample entries (first 5):")
    cur.execute("""
        SELECT log_timestamp, source, action, protocol, source_ip, dest_ip, 
               source_port, dest_port, rule_number, data_length
        FROM log_entries 
        ORDER BY id 
        LIMIT 5
    """)
    samples = cur.fetchall()
    for i, entry in enumerate(samples, 1):
        print(f"\n  Entry {i}:")
        print(f"    Timestamp: {entry['log_timestamp']}")
        print(f"    Source: {entry['source']}")
        print(f"    Action: {entry['action']}")
        print(f"    Protocol: {entry['protocol']}")
        print(f"    {entry['source_ip']}:{entry['source_port']} -> {entry['dest_ip']}:{entry['dest_port']}")
        print(f"    Rule: {entry['rule_number']}, Data length: {entry['data_length']}")
    
    # Check for any suspicious values
    print(f"\n\nChecking for suspicious values:")
    print("-" * 70)
    
    # Check for NULL client_ids
    cur.execute("SELECT COUNT(*) as count FROM log_entries WHERE client_id IS NULL")
    null_clients = cur.fetchone()['count']
    print(f"Entries with NULL client_id: {null_clients}")
    
    # Check for extremely large port numbers
    cur.execute("""
        SELECT COUNT(*) as count 
        FROM log_entries 
        WHERE source_port > 65535 OR dest_port > 65535
    """)
    bad_ports = cur.fetchone()['count']
    print(f"Entries with invalid port numbers (>65535): {bad_ports}")
    
    # Check for very large integers
    cur.execute("""
        SELECT 
            MAX(rule_number) as max_rule,
            MAX(source_port) as max_sport,
            MAX(dest_port) as max_dport,
            MAX(data_length) as max_data
        FROM log_entries
    """)
    max_vals = cur.fetchone()
    print(f"\nMax integer values:")
    print(f"  Max rule_number: {max_vals['max_rule']}")
    print(f"  Max source_port: {max_vals['max_sport']}")
    print(f"  Max dest_port: {max_vals['max_dport']}")
    print(f"  Max data_length: {max_vals['max_data']}")
    
    # 4. Check firewall_rules table
    print("\n\n4. FIREWALL_RULES TABLE:")
    print("-" * 70)
    cur.execute("SELECT COUNT(*) as count FROM firewall_rules")
    rules_count = cur.fetchone()['count']
    print(f"Total firewall rule snapshots: {rules_count}")
    
    if rules_count > 0:
        cur.execute("""
            SELECT client_id, ruleset_id, rule_count, ingested_at 
            FROM firewall_rules 
            ORDER BY ingested_at DESC 
            LIMIT 5
        """)
        rules = cur.fetchall()
        print(f"\nRecent rule snapshots:")
        for rule in rules:
            print(f"  Client: {rule['client_id']}")
            print(f"  Ruleset ID: {rule['ruleset_id']}")
            print(f"  Rule count: {rule['rule_count']}")
            print(f"  Ingested: {rule['ingested_at']}")
            print()
    
    # 5. Check cache tables
    print("\n5. CACHE TABLES:")
    print("-" * 70)
    
    cur.execute("SELECT COUNT(*) as count FROM ip_geolocation_cache")
    geo_count = cur.fetchone()['count']
    print(f"IP geolocation cache entries: {geo_count}")
    
    cur.execute("SELECT COUNT(*) as count FROM threat_intel_cache")
    threat_count = cur.fetchone()['count']
    print(f"Threat intel cache entries: {threat_count}")
    
    print("\n" + "=" * 70)
    print("Database check complete!")
    print("=" * 70)
    
    cur.close()
    conn.close()
    
except Exception as e:
    print(f"❌ Error: {e}")
    import traceback
    traceback.print_exc()

