"""
Database configuration for LNS Firewall
Supports both PostgreSQL (production) and SQLite (legacy/testing)
"""
import os
from typing import Optional

# Database type: 'postgres' or 'sqlite'
DB_TYPE = os.getenv('DB_TYPE', 'postgres')

# PostgreSQL configuration
POSTGRES_CONFIG = {
    'host': os.getenv('POSTGRES_HOST', 'localhost'),
    'port': int(os.getenv('POSTGRES_PORT', '5432')),
    'database': os.getenv('POSTGRES_DB', 'lnsfirewall'),
    'user': os.getenv('POSTGRES_USER', 'postgres'),
    'password': os.getenv('POSTGRES_PASSWORD', 'lnsFirewall2024!'),
}

# SQLite configuration (legacy)
SQLITE_DB_PATH = 'hq_database.db'

def get_db_connection_string() -> str:
    """Get database connection string based on DB_TYPE"""
    if DB_TYPE == 'postgres':
        return f"postgresql://{POSTGRES_CONFIG['user']}:{POSTGRES_CONFIG['password']}@{POSTGRES_CONFIG['host']}:{POSTGRES_CONFIG['port']}/{POSTGRES_CONFIG['database']}"
    else:
        return f"sqlite:///{SQLITE_DB_PATH}"

def get_postgres_connection():
    """Get a psycopg2 connection to PostgreSQL"""
    import psycopg2
    return psycopg2.connect(**POSTGRES_CONFIG)

def get_sqlite_connection():
    """Get a sqlite3 connection (legacy)"""
    import sqlite3
    return sqlite3.connect(SQLITE_DB_PATH)

