#!/usr/bin/env python3
"""
Migrate log_entries table to add missing columns
"""
import sqlite3
import os

DB_PATH = "hq_database.db"

def migrate():
    print("Migrating log_entries table schema...")
    
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    
    # Get current columns
    cur.execute("PRAGMA table_info(log_entries)")
    existing_columns = {row[1] for row in cur.fetchall()}
    
    print(f"Existing columns: {existing_columns}")
    
    # Columns we need
    required_columns = {
        'ip_version': 'TEXT',
        'data_length': 'INTEGER',
        'flags': 'TEXT',
        'tcp_flags': 'TEXT'
    }
    
    # Add missing columns
    for column, column_type in required_columns.items():
        if column not in existing_columns:
            print(f"Adding column: {column} ({column_type})")
            try:
                cur.execute(f"ALTER TABLE log_entries ADD COLUMN {column} {column_type}")
                conn.commit()
                print(f"  ✅ Added {column}")
            except Exception as e:
                print(f"  ❌ Failed to add {column}: {e}")
        else:
            print(f"  ⏭️  Column {column} already exists")
    
    # Verify final schema
    cur.execute("PRAGMA table_info(log_entries)")
    final_columns = [row[1] for row in cur.fetchall()]
    
    print(f"\nFinal schema ({len(final_columns)} columns):")
    for col in final_columns:
        print(f"  - {col}")
    
    conn.close()
    print("\n✅ Migration complete!")

if __name__ == "__main__":
    migrate()

