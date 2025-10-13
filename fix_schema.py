#!/usr/bin/env python3
"""Fix PostgreSQL schema - increase VARCHAR sizes"""

import psycopg2

DB_CONFIG = {
    'host': 'localhost',
    'port': 5432,
    'database': 'lnsfirewall',
    'user': 'postgres',
    'password': 'lnsFirewall2024!',
}

try:
    conn = psycopg2.connect(**DB_CONFIG)
    cur = conn.cursor()
    
    print("Fixing log_entries table schema...")
    
    # Increase VARCHAR sizes for fields that might be too small
    alterations = [
        "ALTER TABLE log_entries ALTER COLUMN protocol TYPE VARCHAR(100);",
        "ALTER TABLE log_entries ALTER COLUMN source_ip TYPE VARCHAR(255);",
        "ALTER TABLE log_entries ALTER COLUMN dest_ip TYPE VARCHAR(255);",
        "ALTER TABLE log_entries ALTER COLUMN flags TYPE VARCHAR(255);",
        "ALTER TABLE log_entries ALTER COLUMN tcp_flags TYPE VARCHAR(255);",
        "ALTER TABLE log_entries ALTER COLUMN interface TYPE VARCHAR(100);",
        "ALTER TABLE log_entries ALTER COLUMN action TYPE VARCHAR(100);",
        "ALTER TABLE log_entries ALTER COLUMN source TYPE VARCHAR(100);",
        "ALTER TABLE log_entries ALTER COLUMN log_type TYPE VARCHAR(100);",
    ]
    
    for sql in alterations:
        try:
            cur.execute(sql)
            print(f"  ✅ {sql}")
        except Exception as e:
            print(f"  ⚠️  {sql} - {e}")
    
    conn.commit()
    print("\n✅ Schema fixed!")
    
    cur.close()
    conn.close()
    
except Exception as e:
    print(f"❌ Error: {e}")

