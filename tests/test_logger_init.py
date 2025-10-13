#!/usr/bin/env python3
"""
Test script to verify logger is defined before websockets import error handler.
This simulates the scenario where websockets module is not available.
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

def test_logger_before_websockets_import():
    """
    Test that logger is defined before it's used in the websockets ImportError handler.
    We'll simulate this by checking the order of definitions in the file.
    """
    print("Testing logger initialization order...")
    
    client_file = os.path.join(os.path.dirname(__file__), '..', 'client', 'pfsense_client.py')

    with open(client_file, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    logger_def_line = None
    websockets_import_line = None
    logger_usage_in_except = None
    
    for i, line in enumerate(lines, start=1):
        if 'logger = logging.getLogger' in line:
            logger_def_line = i
            print(f"✓ Found logger definition at line {i}")
        
        if 'import websockets' in line and 'try:' in lines[i-2]:
            websockets_import_line = i
            print(f"✓ Found websockets import at line {i}")
        
        if 'logger.warning("websockets not available' in line:
            logger_usage_in_except = i
            print(f"✓ Found logger usage in except block at line {i}")
    
    # Verify logger is defined before it's used
    if logger_def_line and logger_usage_in_except:
        if logger_def_line < logger_usage_in_except:
            print(f"\n✅ PASS: Logger is defined (line {logger_def_line}) before being used in except block (line {logger_usage_in_except})")
            return True
        else:
            print(f"\n❌ FAIL: Logger is used (line {logger_usage_in_except}) before being defined (line {logger_def_line})")
            return False
    else:
        print("\n⚠️  WARNING: Could not find all required elements")
        return False

if __name__ == "__main__":
    success = test_logger_before_websockets_import()
    sys.exit(0 if success else 1)

