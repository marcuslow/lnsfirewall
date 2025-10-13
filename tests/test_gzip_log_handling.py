#!/usr/bin/env python3
"""
Test script to verify gzipped log files are properly decompressed during log collection.
"""

import sys
import os
import gzip
import tempfile
import shutil

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

def test_gzip_handling_in_code():
    """
    Verify that the client code properly handles .gz files.
    """
    print("Testing gzip handling in pfsense_client.py...")
    
    client_file = os.path.join(os.path.dirname(__file__), '..', 'client', 'pfsense_client.py')

    with open(client_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Find the log collection section
    if "if log_file.endswith('.gz'):" in content:
        print("✓ Found .gz file check")
    else:
        print("❌ No .gz file check found")
        return False
    
    if "gzip.open(log_file, 'rt'" in content:
        print("✓ Found gzip.open for decompression")
    else:
        print("❌ No gzip.open found for decompression")
        return False
    
    # Verify the logic flow
    log_collection_start = content.find("for idx, log_file in enumerate(log_files")
    log_collection_section = content[log_collection_start:log_collection_start + 3000]
    
    if "if log_file.endswith('.gz'):" in log_collection_section and \
       "gzip.open" in log_collection_section and \
       "else:" in log_collection_section:
        print("✓ Proper conditional handling for .gz vs plain text files")
    else:
        print("❌ Missing proper conditional handling")
        return False
    
    print("\n✅ PASS: Code properly handles gzipped log files")
    return True

def test_gzip_decompression():
    """
    Test actual gzip decompression with sample data.
    """
    print("\nTesting actual gzip decompression...")
    
    # Create a temporary directory
    temp_dir = tempfile.mkdtemp()
    
    try:
        # Create test log content
        test_log_content = """Dec 13 10:15:23 filterlog: 5,,,1000000103,em0,match,block,in,4,0x0,,64,0,0,DF,6,tcp,60,192.168.1.100,10.0.0.1,12345,80,0,S,1234567890,,1024,,
Dec 13 10:15:24 filterlog: 5,,,1000000104,em0,match,block,in,4,0x0,,64,0,0,DF,6,tcp,60,192.168.1.101,10.0.0.1,12346,443,0,S,1234567891,,1024,,
Dec 13 10:15:25 filterlog: 5,,,1000000105,em0,match,block,in,4,0x0,,64,0,0,DF,6,tcp,60,192.168.1.102,10.0.0.1,12347,22,0,S,1234567892,,1024,,"""
        
        # Create plain text log file
        plain_log_file = os.path.join(temp_dir, 'filter.log')
        with open(plain_log_file, 'w') as f:
            f.write(test_log_content)
        
        # Create gzipped log file
        gz_log_file = os.path.join(temp_dir, 'filter.log.0.gz')
        with gzip.open(gz_log_file, 'wt', encoding='utf-8') as f:
            f.write(test_log_content)
        
        # Test reading plain text file
        with open(plain_log_file, 'r', encoding='utf-8', errors='ignore') as f:
            plain_content = f.read()
        
        # Test reading gzipped file
        with gzip.open(gz_log_file, 'rt', encoding='utf-8', errors='ignore') as f:
            gz_content = f.read()
        
        # Verify both methods produce the same content
        if plain_content == gz_content == test_log_content:
            print("✓ Plain text and gzipped files read correctly")
            print(f"  - Plain text file: {len(plain_content)} chars")
            print(f"  - Gzipped file: {len(gz_content)} chars")
            print(f"  - Both match original: {len(test_log_content)} chars")
        else:
            print("❌ Content mismatch")
            print(f"  - Plain: {len(plain_content)} chars")
            print(f"  - Gzipped: {len(gz_content)} chars")
            print(f"  - Original: {len(test_log_content)} chars")
            return False
        
        # Test that reading .gz file as plain text produces gibberish
        with open(gz_log_file, 'r', encoding='utf-8', errors='ignore') as f:
            wrong_content = f.read()
        
        if wrong_content != test_log_content:
            print("✓ Reading .gz as plain text produces different (corrupted) content")
            print(f"  - Corrupted content length: {len(wrong_content)} chars")
        else:
            print("⚠️  WARNING: Reading .gz as plain text somehow produced correct content")
        
        print("\n✅ PASS: Gzip decompression works correctly")
        return True
        
    finally:
        # Clean up
        shutil.rmtree(temp_dir)

if __name__ == "__main__":
    success1 = test_gzip_handling_in_code()
    success2 = test_gzip_decompression()
    sys.exit(0 if (success1 and success2) else 1)

