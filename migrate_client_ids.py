#!/usr/bin/env python3
"""Migrate client IDs from hash to client_name"""

import psycopg2

DB_CONFIG = {
    'host': 'localhost',
    'port': 5432,
    'database': 'lnsfirewall',
    'user': 'postgres',
    'password': 'lnsFirewall2024!',
}

conn = psycopg2.connect(**DB_CONFIG)
cur = conn.cursor()

print("=" * 70)
print("Migrating client IDs from hash to client_name")
print("=" * 70)

# Step 0: Drop foreign key constraints temporarily
print("\nDropping foreign key constraints...")
cur.execute("ALTER TABLE commands DROP CONSTRAINT IF EXISTS commands_client_id_fkey")
cur.execute("ALTER TABLE log_entries DROP CONSTRAINT IF EXISTS log_entries_client_id_fkey")
cur.execute("ALTER TABLE firewall_rules DROP CONSTRAINT IF EXISTS firewall_rules_client_id_fkey")
conn.commit()
print("  ✅ Constraints dropped")

# Step 1: Get current clients
cur.execute("SELECT id, client_name FROM clients")
clients = cur.fetchall()

print(f"\nFound {len(clients)} client(s):")
for hash_id, name in clients:
    print(f"  {hash_id} -> {name}")

# Step 2: For each client, update all references
for hash_id, name in clients:
    print(f"\nMigrating {hash_id} to {name}...")
    
    # Update commands table
    cur.execute("UPDATE commands SET client_id = %s WHERE client_id = %s", (name, hash_id))
    print(f"  ✅ Updated {cur.rowcount} commands")
    
    # Update log_entries table
    cur.execute("UPDATE log_entries SET client_id = %s WHERE client_id = %s", (name, hash_id))
    print(f"  ✅ Updated {cur.rowcount} log entries")
    
    # Update firewall_rules table
    cur.execute("UPDATE firewall_rules SET client_id = %s WHERE client_id = %s", (name, hash_id))
    print(f"  ✅ Updated {cur.rowcount} firewall rules")
    
    # Update clients table (change the ID itself)
    # First, we need to insert a new row with the name as ID, then delete the old one
    cur.execute("SELECT metadata FROM clients WHERE id = %s", (hash_id,))
    row = cur.fetchone()
    metadata = row[0] if row else '{}'
    
    # Insert new client with name as ID
    cur.execute("""
        INSERT INTO clients (id, client_name, last_seen, metadata)
        SELECT %s, client_name, last_seen, metadata
        FROM clients WHERE id = %s
        ON CONFLICT (id) DO UPDATE SET
            client_name = EXCLUDED.client_name,
            last_seen = EXCLUDED.last_seen,
            metadata = EXCLUDED.metadata
    """, (name, hash_id))
    
    # Delete old client with hash ID
    cur.execute("DELETE FROM clients WHERE id = %s", (hash_id,))
    print(f"  ✅ Updated client record")

conn.commit()

print("\n" + "=" * 70)
print("Verification:")
print("=" * 70)

cur.execute("SELECT id, client_name FROM clients")
clients = cur.fetchall()
print(f"\nClients after migration:")
for client_id, name in clients:
    print(f"  id={client_id}, name={name}")

cur.execute("SELECT DISTINCT client_id FROM commands")
command_clients = cur.fetchall()
print(f"\nDistinct client_ids in commands:")
for (client_id,) in command_clients:
    print(f"  {client_id}")

cur.execute("SELECT DISTINCT client_id FROM log_entries")
log_clients = cur.fetchall()
print(f"\nDistinct client_ids in log_entries:")
for (client_id,) in log_clients:
    print(f"  {client_id}")

cur.close()
conn.close()

print("\n✅ Migration complete!")

