#!/usr/bin/env python3
"""Fix PostgreSQL integer overflow - change INTEGER to BIGINT for large values"""

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
    
    print("Fixing log_entries table integer overflow...")
    
    # Change INTEGER to BIGINT for fields that might have large values
    # Port numbers should be fine (max 65535), but data_length and rule_number might be large
    alterations = [
        "ALTER TABLE log_entries ALTER COLUMN rule_number TYPE BIGINT;",
        "ALTER TABLE log_entries ALTER COLUMN source_port TYPE BIGINT;",
        "ALTER TABLE log_entries ALTER COLUMN dest_port TYPE BIGINT;",
        "ALTER TABLE log_entries ALTER COLUMN data_length TYPE BIGINT;",
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

