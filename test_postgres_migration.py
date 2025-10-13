#!/usr/bin/env python3
"""
Test PostgreSQL migration
"""
import asyncio
from hq.db_async import get_db, insert_log_entries_batch
from datetime import datetime

async def test():
    print("=" * 60)
    print("Testing PostgreSQL Migration")
    print("=" * 60)
    
    # Test 1: Connection
    print("\n1. Testing database connection...")
    try:
        async with get_db() as db:
            cur = await db.execute("SELECT version()")
            version = await db.fetchone(cur)
            print(f"   ✅ Connected: {version['version'][:50]}...")
    except Exception as e:
        print(f"   ❌ Connection failed: {e}")
        import traceback
        traceback.print_exc()
        return
    
    # Test 2: Query log entries
    print("\n2. Testing log entries query...")
    try:
        async with get_db() as db:
            cur = await db.execute("""
                SELECT client_id, COUNT(*) as count
                FROM log_entries
                GROUP BY client_id
            """)
            rows = await db.fetchall(cur)
            if rows:
                for row in rows:
                    print(f"   - {row['client_id']}: {row['count']:,} entries")
            else:
                print(f"   - No log entries found (fresh database)")
    except Exception as e:
        print(f"   ❌ Query failed: {e}")
        import traceback
        traceback.print_exc()
    
    # Test 3: Insert test entry
    print("\n3. Testing batch insert...")
    try:
        test_entries = [{
            'timestamp': datetime.now().isoformat(),
            'log_timestamp': datetime.now().isoformat(),
            'source': 'test',
            'log_type': 'filterlog',
            'hostname': 'test-host',
            'raw_message': 'test message',
            'rule_number': 1,
            'interface': 'wan',
            'action': 'block',
            'direction': 'in',
            'ip_version': '4',
            'protocol': 'tcp',
            'source_ip': '1.2.3.4',
            'dest_ip': '5.6.7.8',
            'source_port': 12345,
            'dest_port': 80,
            'data_length': 60,
            'flags': 'S',
            'tcp_flags': 'S'
        }]
        
        inserted = await insert_log_entries_batch('test-client', test_entries)
        print(f"   ✅ Inserted {inserted} test entry")
        
        # Clean up
        async with get_db() as db:
            await db.execute("DELETE FROM log_entries WHERE client_id = %s", ('test-client',))
            await db.commit()
            print(f"   ✅ Cleaned up test entry")
            
    except Exception as e:
        print(f"   ❌ Insert failed: {e}")
        import traceback
        traceback.print_exc()
    
    print("\n" + "=" * 60)
    print("✅ PostgreSQL migration test complete!")
    print("=" * 60)

if __name__ == "__main__":
    asyncio.run(test())

