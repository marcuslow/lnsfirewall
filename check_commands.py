#!/usr/bin/env python3
"""Check command history"""
import sqlite3
from datetime import datetime

def check_commands():
    print("=" * 80)
    print("Checking Command History")
    print("=" * 80)
    
    conn = sqlite3.connect('hq_database.db')
    cursor = conn.cursor()
    
    # Check recent commands
    cursor.execute('''
        SELECT id, client_id, command_type, created_at, completed_at, status
        FROM commands
        ORDER BY created_at DESC
        LIMIT 20
    ''')
    
    rows = cursor.fetchall()
    
    if not rows:
        print("❌ NO COMMANDS FOUND")
        return
    
    print(f"\n📊 Recent Commands:")
    print(f"{'ID':<10} {'Client ID':<25} {'Type':<15} {'Created':<20} {'Status':<10}")
    print("-" * 90)
    
    for row in rows:
        cmd_id, client_id, cmd_type, created_at, completed_at, status = row
        print(f"{cmd_id:<10} {client_id:<25} {cmd_type:<15} {created_at:<20} {status:<10}")
    
    # Check if any logs commands completed successfully
    cursor.execute('''
        SELECT COUNT(*) as completed_logs_commands
        FROM commands
        WHERE command_type = 'get_logs' AND status = 'completed'
    ''')
    
    row = cursor.fetchone()
    if row:
        completed_count = row[0]
        print(f"\n✅ Completed 'get_logs' commands: {completed_count}")
    
    # Check if there are any failed commands
    cursor.execute('''
        SELECT COUNT(*) as failed_commands
        FROM commands
        WHERE status = 'failed'
    ''')
    
    row = cursor.fetchone()
    if row:
        failed_count = row[0]
        print(f"❌ Failed commands: {failed_count}")
    
    conn.close()

if __name__ == "__main__":
    check_commands()
