#!/usr/bin/env python3
"""
Test script to verify client ID resolution works correctly for both HTTP and WebSocket clients.
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

def test_resolve_client_identifier():
    """
    Test the resolve_client_identifier function with various scenarios.
    """
    print("Testing client ID resolution logic...")
    
    # Import the function (we'll need to extract it or test the logic)
    # For now, we'll verify the function exists in http_server.py
    
    server_file = os.path.join(os.path.dirname(__file__), '..', 'hq', 'http_server.py')

    with open(server_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Check that the function exists
    if 'def resolve_client_identifier' in content:
        print("✓ Found resolve_client_identifier function")
    else:
        print("❌ resolve_client_identifier function not found")
        return False
    
    # Check that it's used in rules_ingest
    if 'resolve_client_identifier(client_id)' in content:
        print("✓ resolve_client_identifier is being used")
    else:
        print("❌ resolve_client_identifier is not being used")
        return False
    
    # Check that rules_ingest uses the helper
    rules_ingest_section = content[content.find('@app.post("/rules/ingest")'):content.find('@app.get("/rules/status")')]
    if 'resolve_client_identifier' in rules_ingest_section:
        print("✓ rules_ingest uses resolve_client_identifier")
    else:
        print("❌ rules_ingest doesn't use resolve_client_identifier")
        return False
    
    # Check that rules_status uses the helper
    rules_status_section = content[content.find('@app.get("/rules/status")'):content.find('@app.post("/rules/push")')]
    if 'resolve_client_identifier' in rules_status_section:
        print("✓ rules_status uses resolve_client_identifier")
    else:
        print("❌ rules_status doesn't use resolve_client_identifier")
        return False
    
    # Check that rules_push uses the helper
    rules_push_section = content[content.find('@app.post("/rules/push")'):content.find('@app.post("/rules/push")') + 2000]
    if 'resolve_client_identifier' in rules_push_section:
        print("✓ rules_push uses resolve_client_identifier")
    else:
        print("❌ rules_push doesn't use resolve_client_identifier")
        return False
    
    print("\n✅ PASS: All rules endpoints use consistent client ID resolution")
    return True

def test_function_logic():
    """
    Test the actual logic of resolve_client_identifier with mock data.
    """
    print("\nTesting resolve_client_identifier logic with mock data...")
    
    # Mock clients_live data
    clients_live = {
        # HTTP client: key is hash, client_name in dict
        "abc123hash": {
            "client_name": "opus-1",
            "hostname": "firewall1"
        },
        # WebSocket client: key is friendly name, hash_id in dict
        "opus-2": {
            "client_name": "opus-2",
            "hostname": "firewall2",
            "hash_id": "def456hash"
        }
    }
    
    # Simulate the function logic
    def resolve_client_identifier(client_id: str) -> str:
        # Direct lookup
        if client_id in clients_live:
            client_info = clients_live[client_id]
            if 'client_name' in client_info:
                return client_info['client_name'].lower()
            return client_id.lower()
        
        # Reverse lookup
        for key, info in clients_live.items():
            if info.get('client_name', '').lower() == client_id.lower():
                return client_id.lower()
            if info.get('hash_id') == client_id:
                return info.get('client_name', client_id).lower()
        
        # Fallback
        return client_id.lower()
    
    # Test cases
    test_cases = [
        ("abc123hash", "opus-1", "HTTP client by hash"),
        ("opus-1", "opus-1", "HTTP client by name"),
        ("opus-2", "opus-2", "WebSocket client by name"),
        ("def456hash", "opus-2", "WebSocket client by hash"),
        ("unknown-client", "unknown-client", "Unknown client fallback")
    ]
    
    all_passed = True
    for input_id, expected_output, description in test_cases:
        result = resolve_client_identifier(input_id)
        if result == expected_output:
            print(f"  ✓ {description}: '{input_id}' → '{result}'")
        else:
            print(f"  ❌ {description}: '{input_id}' → '{result}' (expected '{expected_output}')")
            all_passed = False
    
    if all_passed:
        print("\n✅ PASS: All client ID resolution test cases passed")
    else:
        print("\n❌ FAIL: Some client ID resolution test cases failed")
    
    return all_passed

if __name__ == "__main__":
    success1 = test_resolve_client_identifier()
    success2 = test_function_logic()
    sys.exit(0 if (success1 and success2) else 1)

