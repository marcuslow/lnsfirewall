#!/usr/bin/env python3
"""
Setup PostgreSQL database for LNS Firewall
Creates database, tables, and indexes
"""
import psycopg2
from psycopg2 import sql
import sys

# Database configuration
DB_CONFIG = {
    'host': 'localhost',
    'port': 5432,
    'user': 'postgres',
    'password': 'lnsFirewall2024!',
    'database': 'postgres'  # Connect to default database first
}

DB_NAME = 'lnsfirewall'

def create_database():
    """Create the lnsfirewall database"""
    print("=" * 60)
    print("Creating PostgreSQL Database")
    print("=" * 60)
    
    try:
        # Connect to default postgres database
        conn = psycopg2.connect(**DB_CONFIG)
        conn.autocommit = True
        cur = conn.cursor()
        
        # Check if database exists
        cur.execute("SELECT 1 FROM pg_database WHERE datname = %s", (DB_NAME,))
        exists = cur.fetchone()
        
        if exists:
            print(f"✅ Database '{DB_NAME}' already exists")
        else:
            # Create database
            cur.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(DB_NAME)))
            print(f"✅ Created database '{DB_NAME}'")
        
        cur.close()
        conn.close()
        return True
        
    except Exception as e:
        print(f"❌ Error creating database: {e}")
        return False

def create_tables():
    """Create all required tables"""
    print("\n" + "=" * 60)
    print("Creating Tables")
    print("=" * 60)
    
    try:
        # Connect to lnsfirewall database
        config = DB_CONFIG.copy()
        config['database'] = DB_NAME
        conn = psycopg2.connect(**config)
        cur = conn.cursor()
        
        # 1. Clients table
        print("\n1. Creating clients table...")
        cur.execute('''
            CREATE TABLE IF NOT EXISTS clients (
                id VARCHAR(255) PRIMARY KEY,
                client_name VARCHAR(255),
                last_seen TIMESTAMP,
                connection_mode VARCHAR(50),
                metadata JSONB
            )
        ''')
        print("   ✅ clients table created")
        
        # 2. Commands table
        print("\n2. Creating commands table...")
        cur.execute('''
            CREATE TABLE IF NOT EXISTS commands (
                id VARCHAR(255) PRIMARY KEY,
                client_id VARCHAR(255),
                command_type VARCHAR(100),
                params JSONB,
                status VARCHAR(50),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed_at TIMESTAMP,
                response_data JSONB,
                FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
            )
        ''')
        print("   ✅ commands table created")
        
        # 3. Log entries table (main table for individual log entries)
        print("\n3. Creating log_entries table...")
        cur.execute('''
            CREATE TABLE IF NOT EXISTS log_entries (
                id BIGSERIAL PRIMARY KEY,
                client_id VARCHAR(255) NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                log_timestamp TIMESTAMP,
                source VARCHAR(100),
                log_type VARCHAR(100),
                hostname VARCHAR(255),
                raw_message TEXT,
                rule_number BIGINT,
                interface VARCHAR(100),
                action VARCHAR(100),
                direction VARCHAR(10),
                ip_version VARCHAR(10),
                protocol VARCHAR(100),
                source_ip VARCHAR(255),
                dest_ip VARCHAR(255),
                source_port BIGINT,
                dest_port BIGINT,
                data_length BIGINT,
                flags VARCHAR(255),
                tcp_flags VARCHAR(255)
            )
        ''')
        print("   ✅ log_entries table created")
        
        # 4. Firewall rules table
        print("\n4. Creating firewall_rules table...")
        cur.execute('''
            CREATE TABLE IF NOT EXISTS firewall_rules (
                id SERIAL PRIMARY KEY,
                client_id VARCHAR(255) NOT NULL,
                ruleset_id VARCHAR(255),
                rules_xml TEXT,
                rule_count INTEGER,
                ingested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        print("   ✅ firewall_rules table created")
        
        # 5. IP geolocation cache
        print("\n5. Creating ip_geolocation_cache table...")
        cur.execute('''
            CREATE TABLE IF NOT EXISTS ip_geolocation_cache (
                ip VARCHAR(100) PRIMARY KEY,
                country_code VARCHAR(10),
                country_name VARCHAR(255),
                city VARCHAR(255),
                region VARCHAR(255),
                org VARCHAR(255),
                cached_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                source VARCHAR(50)
            )
        ''')
        print("   ✅ ip_geolocation_cache table created")
        
        # 6. Threat intelligence cache
        print("\n6. Creating threat_intel_cache table...")
        cur.execute('''
            CREATE TABLE IF NOT EXISTS threat_intel_cache (
                ip VARCHAR(100) PRIMARY KEY,
                source VARCHAR(50),
                abuse_confidence_score INTEGER,
                total_reports INTEGER,
                country_code VARCHAR(10),
                isp VARCHAR(255),
                usage_type VARCHAR(100),
                is_tor BOOLEAN,
                is_public_proxy BOOLEAN,
                last_reported_at TIMESTAMP,
                cached_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        print("   ✅ threat_intel_cache table created")
        
        conn.commit()
        cur.close()
        conn.close()
        
        print("\n✅ All tables created successfully")
        return True
        
    except Exception as e:
        print(f"\n❌ Error creating tables: {e}")
        import traceback
        traceback.print_exc()
        return False

def create_indexes():
    """Create indexes for performance"""
    print("\n" + "=" * 60)
    print("Creating Indexes")
    print("=" * 60)
    
    try:
        config = DB_CONFIG.copy()
        config['database'] = DB_NAME
        conn = psycopg2.connect(**config)
        cur = conn.cursor()
        
        indexes = [
            ("idx_log_entries_client_timestamp", "log_entries", "(client_id, timestamp DESC)"),
            ("idx_log_entries_client_log_timestamp", "log_entries", "(client_id, log_timestamp DESC)"),
            ("idx_log_entries_client_action", "log_entries", "(client_id, action)"),
            ("idx_log_entries_source_ip", "log_entries", "(source_ip)"),
            ("idx_log_entries_dest_ip", "log_entries", "(dest_ip)"),
            ("idx_log_entries_dest_port", "log_entries", "(dest_port)"),
            ("idx_commands_client_status", "commands", "(client_id, status)"),
            ("idx_commands_created_at", "commands", "(created_at DESC)"),
            ("idx_firewall_rules_client", "firewall_rules", "(client_id, ingested_at DESC)"),
        ]
        
        for idx_name, table, columns in indexes:
            try:
                cur.execute(f"CREATE INDEX IF NOT EXISTS {idx_name} ON {table} {columns}")
                print(f"   ✅ {idx_name}")
            except Exception as e:
                print(f"   ⚠️  {idx_name}: {e}")
        
        conn.commit()
        cur.close()
        conn.close()
        
        print("\n✅ All indexes created successfully")
        return True
        
    except Exception as e:
        print(f"\n❌ Error creating indexes: {e}")
        return False

def test_connection():
    """Test the database connection"""
    print("\n" + "=" * 60)
    print("Testing Connection")
    print("=" * 60)
    
    try:
        config = DB_CONFIG.copy()
        config['database'] = DB_NAME
        conn = psycopg2.connect(**config)
        cur = conn.cursor()
        
        cur.execute("SELECT version()")
        version = cur.fetchone()[0]
        print(f"\n✅ Connected to PostgreSQL:")
        print(f"   {version}")
        
        # Check tables
        cur.execute("""
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_schema = 'public'
            ORDER BY table_name
        """)
        tables = cur.fetchall()
        print(f"\n✅ Tables created: {len(tables)}")
        for table in tables:
            print(f"   - {table[0]}")
        
        cur.close()
        conn.close()
        return True
        
    except Exception as e:
        print(f"\n❌ Connection test failed: {e}")
        return False

def main():
    print("\n🐘 PostgreSQL Setup for LNS Firewall\n")
    
    # Step 1: Create database
    if not create_database():
        print("\n❌ Setup failed at database creation")
        sys.exit(1)
    
    # Step 2: Create tables
    if not create_tables():
        print("\n❌ Setup failed at table creation")
        sys.exit(1)
    
    # Step 3: Create indexes
    if not create_indexes():
        print("\n❌ Setup failed at index creation")
        sys.exit(1)
    
    # Step 4: Test connection
    if not test_connection():
        print("\n❌ Setup failed at connection test")
        sys.exit(1)
    
    print("\n" + "=" * 60)
    print("✅ PostgreSQL Setup Complete!")
    print("=" * 60)
    print("\nConnection details:")
    print(f"  Host: {DB_CONFIG['host']}")
    print(f"  Port: {DB_CONFIG['port']}")
    print(f"  Database: {DB_NAME}")
    print(f"  Username: {DB_CONFIG['user']}")
    print(f"  Password: {DB_CONFIG['password']}")
    print("\nNext steps:")
    print("  1. Install psycopg2: pip install psycopg2-binary")
    print("  2. Update code to use PostgreSQL")
    print("  3. Restart server")
    print()

if __name__ == "__main__":
    main()

