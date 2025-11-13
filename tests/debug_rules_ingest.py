#!/usr/bin/env python3
"""
Debug script to test rules ingest with detailed error reporting
"""

import requests
import json
import uuid
import traceback

# Test configuration
HQ_URL = "http://localhost:8000"
TEST_CLIENT_ID = "test-client-debug"
TEST_RULES_XML = """<rule>
    <type>pass</type>
    <interface>wan</interface>
    <ipprotocol>inet</ipprotocol>
    <protocol>tcp</protocol>
    <source>
        <any/>
    </source>
    <destination>
        <any/>
    </destination>
    <descr>Test rule for debug</descr>
</rule>"""

def test_with_detailed_error():
    """Test with detailed error reporting"""
    print("=" * 60)
    print("Debug Rules Ingest Test")
    print("=" * 60)
    
    # Test payload
    payload = {
        "client_id": TEST_CLIENT_ID,
        "rules_xml": TEST_RULES_XML,
        "command_id": str(uuid.uuid4())
    }
    
    print(f"Testing /rules/ingest")
    print(f"Payload: {json.dumps(payload, indent=2)}")
    
    try:
        # Send rules ingest request with detailed error handling
        response = requests.post(f"{HQ_URL}/rules/ingest", json=payload, timeout=30)
        
        print(f"\nResponse status: {response.status_code}")
        print(f"Response headers: {dict(response.headers)}")
        
        if response.status_code == 200:
            data = response.json()
            print("✅ Success!")
            print(f"Response: {json.dumps(data, indent=2)}")
            return True
        else:
            print(f"❌ Failed with status {response.status_code}")
            print(f"Response text: {response.text}")
            
            # Try to parse as JSON for more details
            try:
                error_data = response.json()
                print(f"Error JSON: {json.dumps(error_data, indent=2)}")
            except:
                print("Response is not valid JSON")
            
            return False
            
    except Exception as e:
        print(f"❌ Exception occurred: {e}")
        traceback.print_exc()
        return False

def test_direct_db_insert():
    """Test direct database insert to isolate the issue"""
    print("\n" + "=" * 60)
    print("Testing Direct Database Insert")
    print("=" * 60)
    
    try:
        import psycopg2
        import psycopg2.extras
        from datetime import datetime
        
        # Database connection
        conn = psycopg2.connect(
            host='localhost',
            port=5432,
            database='lnsfirewall',
            user='postgres',
            password='lnsFirewall2024!'
        )
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        # Test data
        client_id = "test-direct-db"
        ruleset_id = str(uuid.uuid4())
        rules_xml = TEST_RULES_XML
        rule_count = 1
        now = datetime.now()
        
        print(f"Inserting test data:")
        print(f"  client_id: {client_id}")
        print(f"  ruleset_id: {ruleset_id}")
        print(f"  rule_count: {rule_count}")
        print(f"  timestamp: {now}")
        
        # Try the insert
        cur.execute('''
            INSERT INTO firewall_rules (client_id, ruleset_id, rules_xml, rule_count, ingested_at)
            VALUES (%s, %s, %s, %s, %s)
        ''', (client_id, ruleset_id, rules_xml, rule_count, now))
        
        conn.commit()
        print("✅ Direct database insert successful!")
        
        # Verify the insert
        cur.execute('''
            SELECT id, client_id, ruleset_id, rule_count, ingested_at
            FROM firewall_rules WHERE ruleset_id = %s
        ''', (ruleset_id,))
        
        row = cur.fetchone()
        if row:
            print(f"✅ Verification successful:")
            print(f"  Database ID: {row['id']}")
            print(f"  Client ID: {row['client_id']}")
            print(f"  Ruleset ID: {row['ruleset_id']}")
            print(f"  Rule count: {row['rule_count']}")
            print(f"  Ingested at: {row['ingested_at']}")
        else:
            print("❌ Could not find inserted record")
            
        cur.close()
        conn.close()
        return True
        
    except Exception as e:
        print(f"❌ Database test failed: {e}")
        traceback.print_exc()
        return False

if __name__ == "__main__":
    print("Debugging Rules Ingest Issue")
    
    # Test 1: HTTP endpoint
    success1 = test_with_detailed_error()
    
    # Test 2: Direct database
    success2 = test_direct_db_insert()
    
    print("\n" + "=" * 60)
    print("Summary:")
    print(f"  HTTP endpoint test: {'✅ PASS' if success1 else '❌ FAIL'}")
    print(f"  Direct DB test: {'✅ PASS' if success2 else '❌ FAIL'}")
    print("=" * 60)
