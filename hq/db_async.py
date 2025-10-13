"""
Async database wrapper for PostgreSQL
Provides async interface using asyncio executor pattern
"""
import asyncio
import json
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime
import psycopg2
import psycopg2.extras
from contextlib import asynccontextmanager
from db_config import POSTGRES_CONFIG


class AsyncPostgres:
    """Async wrapper for psycopg2 using executor pattern"""
    
    def __init__(self):
        self._conn = None
        self._loop = None
    
    async def connect(self):
        """Establish database connection"""
        self._loop = asyncio.get_event_loop()
        self._conn = await self._loop.run_in_executor(
            None,
            lambda: psycopg2.connect(**POSTGRES_CONFIG)
        )
        # Set autocommit off for transaction control
        await self._loop.run_in_executor(None, lambda: setattr(self._conn, 'autocommit', False))
    
    async def close(self):
        """Close database connection"""
        if self._conn:
            await self._loop.run_in_executor(None, self._conn.close)
    
    async def execute(self, query: str, params: Optional[Tuple] = None):
        """Execute a query and return cursor"""
        # Convert SQLite ? placeholders to PostgreSQL %s
        pg_query = query.replace('?', '%s')
        
        def _execute():
            cur = self._conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cur.execute(pg_query, params or ())
            return cur
        
        return await self._loop.run_in_executor(None, _execute)
    
    async def executemany(self, query: str, params_list: List[Tuple]):
        """Execute a query with multiple parameter sets"""
        pg_query = query.replace('?', '%s')
        
        def _executemany():
            cur = self._conn.cursor()
            # Use execute_batch for better performance
            psycopg2.extras.execute_batch(cur, pg_query, params_list, page_size=1000)
            return cur
        
        return await self._loop.run_in_executor(None, _executemany)
    
    async def commit(self):
        """Commit transaction"""
        await self._loop.run_in_executor(None, self._conn.commit)
    
    async def rollback(self):
        """Rollback transaction"""
        await self._loop.run_in_executor(None, self._conn.rollback)
    
    async def fetchone(self, cursor) -> Optional[Any]:
        """Fetch one row from cursor"""
        def _fetchone():
            return cursor.fetchone()
        return await self._loop.run_in_executor(None, _fetchone)

    async def fetchall(self, cursor) -> List[Any]:
        """Fetch all rows from cursor"""
        def _fetchall():
            return cursor.fetchall()
        return await self._loop.run_in_executor(None, _fetchall)


@asynccontextmanager
async def get_db():
    """Context manager for database connections"""
    db = AsyncPostgres()
    await db.connect()
    try:
        yield db
    finally:
        await db.close()


# Helper functions for common operations

async def insert_log_entries_batch(client_id: str, log_entries: List[Dict[str, Any]], command_id: str = None) -> int:
    """
    Insert log entries in batches with progress updates
    Returns number of entries inserted
    """
    if not log_entries:
        return 0
    
    async with get_db() as db:
        BATCH_SIZE = 1000
        total_inserted = 0
        
        for i in range(0, len(log_entries), BATCH_SIZE):
            batch = log_entries[i:i + BATCH_SIZE]
            
            # Prepare batch insert
            params_list = []
            for entry in batch:
                params_list.append((
                    client_id,
                    datetime.now().isoformat(),
                    entry.get('log_timestamp'),
                    entry.get('source'),
                    entry.get('log_type'),
                    entry.get('hostname'),
                    entry.get('raw_message'),
                    entry.get('rule_number'),
                    entry.get('interface'),
                    entry.get('action'),
                    entry.get('direction'),
                    entry.get('ip_version'),
                    entry.get('protocol'),
                    entry.get('source_ip'),
                    entry.get('dest_ip'),
                    entry.get('source_port'),
                    entry.get('dest_port'),
                    entry.get('data_length'),
                    entry.get('flags'),
                    entry.get('tcp_flags'),
                ))
            
            # Insert batch
            await db.executemany('''
                INSERT INTO log_entries (
                    client_id, timestamp, log_timestamp, source, log_type, hostname,
                    raw_message, rule_number, interface, action, direction, ip_version,
                    protocol, source_ip, dest_ip, source_port, dest_port,
                    data_length, flags, tcp_flags
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ''', params_list)
            
            await db.commit()
            total_inserted += len(batch)
            
            # Progress update every 10 batches OR on final batch
            is_final_batch = (i + BATCH_SIZE >= len(log_entries))
            if (i // BATCH_SIZE) % 10 == 0 or is_final_batch:
                print(f"   Inserted {total_inserted:,}/{len(log_entries):,} entries...")
                
                # Update command progress if command_id provided
                if command_id:
                    progress_pct = int((total_inserted / len(log_entries)) * 100)
                    await update_command_progress(command_id, 'in_progress', {
                        "status": "in_progress",
                        "stage": "storing_to_database",
                        "entries_inserted": total_inserted,
                        "total_entries": len(log_entries),
                        "progress_pct": progress_pct,
                        "timestamp": datetime.now().isoformat()
                    })
        
        return total_inserted


async def update_command_progress(command_id: str, status: str, progress_data: Dict[str, Any]):
    """Update command progress in database"""
    try:
        async with get_db() as db:
            await db.execute('''
                UPDATE commands SET status=%s, response_data=%s
                WHERE id=%s
            ''', (status, json.dumps(progress_data), command_id))
            await db.commit()
    except Exception as e:
        # Don't crash if progress update fails
        print(f"   ⚠️  Failed to update command progress: {e}")


async def mark_command_complete(command_id: str, response_data: Dict[str, Any]):
    """Mark command as complete"""
    try:
        async with get_db() as db:
            await db.execute('''
                UPDATE commands SET status=%s, completed_at=%s, response_data=%s
                WHERE id=%s
            ''', ('completed', datetime.now().isoformat(), json.dumps(response_data), command_id))
            await db.commit()
    except Exception as e:
        print(f"   ⚠️  Failed to mark command complete: {e}")


async def get_command_status(command_id: str) -> Optional[Dict[str, Any]]:
    """Get command status from database"""
    try:
        async with get_db() as db:
            cur = await db.execute('''
                SELECT id, client_id, command_type, status, created_at, completed_at, response_data
                FROM commands
                WHERE id=%s
            ''', (command_id,))
            row = await db.fetchone(cur)
            
            if row:
                # PostgreSQL JSONB returns dict directly, not JSON string
                response_data = row['response_data']
                if response_data and isinstance(response_data, str):
                    response_data = json.loads(response_data)

                return {
                    'id': row['id'],
                    'client_id': row['client_id'],
                    'command_type': row['command_type'],
                    'status': row['status'],
                    'created_at': row['created_at'],
                    'completed_at': row['completed_at'],
                    'response_data': response_data
                }
            return None
    except Exception as e:
        print(f"   ⚠️  Failed to get command status: {e}")
        return None

