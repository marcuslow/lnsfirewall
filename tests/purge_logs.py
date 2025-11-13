#!/usr/bin/env python3
"""
Purge logs from the database while preserving client registrations and other data
"""
import sqlite3
import os
from datetime import datetime

def purge_logs(db_path='hq_database.db'):
    """
    Purge all logs from the database while keeping:
    - Client registrations
    - Commands
    - Rules
    - Cache tables (geolocation, threat intel)
    """
    
    if not os.path.exists(db_path):
        print(f"❌ Database not found: {db_path}")
        return
    
    print("=" * 80)
    print("🗑️  DATABASE LOG PURGE")
    print("=" * 80)
    
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    
    # Get current stats before purge
    print("\n📊 Current Database Stats:")
    
    try:
        cur.execute("SELECT COUNT(*) FROM logs")
        log_count = cur.fetchone()[0]
        print(f"   Logs: {log_count:,}")
    except:
        log_count = 0
        print(f"   Logs: 0 (table doesn't exist)")
    
    try:
        cur.execute("SELECT COUNT(*) FROM clients")
        client_count = cur.fetchone()[0]
        print(f"   Clients: {client_count}")
    except:
        client_count = 0
        print(f"   Clients: 0 (table doesn't exist)")
    
    try:
        cur.execute("SELECT COUNT(*) FROM commands")
        command_count = cur.fetchone()[0]
        print(f"   Commands: {command_count}")
    except:
        command_count = 0
        print(f"   Commands: 0 (table doesn't exist)")
    
    try:
        cur.execute("SELECT COUNT(*) FROM rules")
        rules_count = cur.fetchone()[0]
        print(f"   Rules: {rules_count}")
    except:
        rules_count = 0
        print(f"   Rules: 0 (table doesn't exist)")
    
    try:
        cur.execute("SELECT COUNT(*) FROM ip_geolocation_cache")
        geo_cache_count = cur.fetchone()[0]
        print(f"   Geolocation cache: {geo_cache_count}")
    except:
        geo_cache_count = 0
        print(f"   Geolocation cache: 0 (table doesn't exist)")
    
    try:
        cur.execute("SELECT COUNT(*) FROM threat_intel_cache")
        threat_cache_count = cur.fetchone()[0]
        print(f"   Threat intel cache: {threat_cache_count}")
    except:
        threat_cache_count = 0
        print(f"   Threat intel cache: 0 (table doesn't exist)")
    
    # Confirm purge
    print("\n⚠️  WARNING: This will DELETE all log entries!")
    print("   The following will be PRESERVED:")
    print("   ✅ Client registrations")
    print("   ✅ Commands")
    print("   ✅ Rules")
    print("   ✅ Geolocation cache")
    print("   ✅ Threat intelligence cache")
    
    response = input("\n❓ Are you sure you want to purge all logs? (yes/no): ").strip().lower()
    
    if response != 'yes':
        print("\n❌ Purge cancelled.")
        conn.close()
        return
    
    # Perform purge
    print("\n🗑️  Purging logs...")
    
    try:
        # Delete all logs
        cur.execute("DELETE FROM logs")
        deleted_count = cur.rowcount
        conn.commit()
        
        # Vacuum to reclaim space
        print("🧹 Vacuuming database to reclaim space...")
        cur.execute("VACUUM")
        
        print(f"\n✅ Successfully purged {deleted_count:,} log entries!")
        
        # Show final stats
        print("\n📊 Database Stats After Purge:")
        
        cur.execute("SELECT COUNT(*) FROM logs")
        print(f"   Logs: {cur.fetchone()[0]:,}")
        
        cur.execute("SELECT COUNT(*) FROM clients")
        print(f"   Clients: {cur.fetchone()[0]}")
        
        cur.execute("SELECT COUNT(*) FROM commands")
        print(f"   Commands: {cur.fetchone()[0]}")
        
        try:
            cur.execute("SELECT COUNT(*) FROM rules")
            print(f"   Rules: {cur.fetchone()[0]}")
        except:
            print(f"   Rules: 0")
        
        try:
            cur.execute("SELECT COUNT(*) FROM ip_geolocation_cache")
            print(f"   Geolocation cache: {cur.fetchone()[0]}")
        except:
            print(f"   Geolocation cache: 0")
        
        try:
            cur.execute("SELECT COUNT(*) FROM threat_intel_cache")
            print(f"   Threat intel cache: {cur.fetchone()[0]}")
        except:
            print(f"   Threat intel cache: 0")
        
        # Show database file size
        db_size = os.path.getsize(db_path)
        db_size_mb = db_size / (1024 * 1024)
        print(f"\n💾 Database file size: {db_size_mb:.2f} MB")
        
        print("\n✅ Purge complete! Ready for fresh logs.")
        
    except Exception as e:
        print(f"\n❌ Error during purge: {e}")
        conn.rollback()
    
    finally:
        conn.close()

def purge_everything(db_path='hq_database.db'):
    """
    Nuclear option: Delete EVERYTHING including clients, commands, rules, caches
    """
    
    if not os.path.exists(db_path):
        print(f"❌ Database not found: {db_path}")
        return
    
    print("=" * 80)
    print("☢️  NUCLEAR DATABASE PURGE - DELETE EVERYTHING")
    print("=" * 80)
    
    print("\n⚠️  WARNING: This will DELETE EVERYTHING:")
    print("   ❌ All logs")
    print("   ❌ All client registrations")
    print("   ❌ All commands")
    print("   ❌ All rules")
    print("   ❌ All caches")
    
    response = input("\n❓ Are you ABSOLUTELY SURE? Type 'DELETE EVERYTHING' to confirm: ").strip()
    
    if response != 'DELETE EVERYTHING':
        print("\n❌ Nuclear purge cancelled.")
        return
    
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    
    print("\n☢️  Deleting everything...")
    
    try:
        tables = ['logs', 'clients', 'commands', 'rules', 'ip_geolocation_cache', 'threat_intel_cache']
        
        for table in tables:
            try:
                cur.execute(f"DELETE FROM {table}")
                deleted = cur.rowcount
                print(f"   Deleted {deleted:,} rows from {table}")
            except Exception as e:
                print(f"   Skipped {table}: {e}")
        
        conn.commit()
        
        print("🧹 Vacuuming database...")
        cur.execute("VACUUM")
        
        db_size = os.path.getsize(db_path)
        db_size_mb = db_size / (1024 * 1024)
        print(f"\n💾 Database file size: {db_size_mb:.2f} MB")
        
        print("\n✅ Nuclear purge complete! Database is empty.")
        
    except Exception as e:
        print(f"\n❌ Error during nuclear purge: {e}")
        conn.rollback()
    
    finally:
        conn.close()

if __name__ == '__main__':
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == '--nuclear':
        purge_everything()
    else:
        purge_logs()

