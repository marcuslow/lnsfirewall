#!/usr/bin/env python3
"""Check all tables in database"""
import sqlite3

def check_all_tables():
    print("=" * 80)
    print("Checking All Tables in Database")
    print("=" * 80)
    
    conn = sqlite3.connect('hq_database.db')
    cursor = conn.cursor()
    
    # Get all tables
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = cursor.fetchall()
    
    print(f"📊 Found {len(tables)} tables:")
    
    for table_name, in tables:
        print(f"\n📋 Table: {table_name}")
        
        # Get row count
        cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
        count = cursor.fetchone()[0]
        print(f"   Rows: {count:,}")
        
        # Get schema
        cursor.execute(f"PRAGMA table_info({table_name})")
        columns = cursor.fetchall()
        print(f"   Columns: {', '.join([col[1] for col in columns])}")
        
        # If table has data, show sample
        if count > 0:
            cursor.execute(f"SELECT * FROM {table_name} LIMIT 1")
            sample = cursor.fetchone()
            if sample:
                print(f"   Sample: {str(sample)[:100]}...")
                
                # Check for large data columns
                for i, col in enumerate(columns):
                    col_name = col[1]
                    if sample[i] and isinstance(sample[i], str) and len(sample[i]) > 1000:
                        print(f"   Large column '{col_name}': {len(sample[i]):,} chars")
    
    conn.close()

if __name__ == "__main__":
    check_all_tables()
