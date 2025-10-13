#!/usr/bin/env python3
"""Quick test to verify LogQueryEngine import works in AI Command Center"""
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

print("Testing LogQueryEngine import...")

try:
    from hq.ai_command_center import AICommandCenter, LogQueryEngine
    
    if LogQueryEngine is None:
        print("❌ FAIL: LogQueryEngine is None")
        sys.exit(1)
    else:
        print(f"✅ SUCCESS: LogQueryEngine imported successfully")
        print(f"   Module: {LogQueryEngine.__module__}")
        print(f"   Class: {LogQueryEngine.__name__}")
        
        # Check if it has the expected methods (5 security tools)
        expected_methods = [
            'from_db',
            'get_top_blocked_ips',                    # Tool 1: Traffic Anomaly Detection
            'detect_scanning_activity',               # Tool 2: Port Scanning Detection
            'map_geographic_threats',                 # Tool 3: Geographic Threat Mapper
            'correlate_with_threat_intel',            # Tool 4: Threat Intelligence
            'monitor_outbound_connections'            # Tool 5: Outbound Anomaly Detection
        ]
        
        for method in expected_methods:
            if hasattr(LogQueryEngine, method):
                print(f"   ✓ Has method: {method}")
            else:
                print(f"   ✗ Missing method: {method}")
        
        sys.exit(0)
        
except Exception as e:
    print(f"❌ FAIL: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

