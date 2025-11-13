#!/usr/bin/env python3
"""
Investigate why 103.26.150.122 appears as top blocked IP
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'hq'))

from lqe import LogQueryEngine

def investigate_blocked_ips():
    """Investigate the blocked IP issue"""
    print("=== Investigating Blocked IP Issue ===")
    
    # Load data from database
    try:
        lqe = LogQueryEngine.from_db("hq_database.db", "8cbb62eecbb00579", since_days=7)
        print(f"Loaded {len(lqe.entries)} log entries")
        
        if not lqe.entries:
            print("No entries found!")
            return
            
        # Get blocked entries
        blocked = lqe.filter_blocked()
        print(f"Found {len(blocked)} blocked entries")
        
        # Look at entries involving 103.26.150.122
        target_ip = "103.26.150.122"
        entries_with_target = []
        
        for entry in blocked:
            if (entry.src and target_ip in entry.src) or (entry.dst and target_ip in entry.dst):
                entries_with_target.append(entry)
        
        print(f"\nFound {len(entries_with_target)} blocked entries involving {target_ip}")
        
        # Analyze the first 10 entries
        print(f"\n--- Sample Entries Involving {target_ip} ---")
        for i, entry in enumerate(entries_with_target[:10]):
            print(f"\nEntry {i+1}:")
            print(f"  Timestamp: {entry.timestamp}")
            print(f"  Action: {entry.action}")
            print(f"  Source: {entry.src}")
            print(f"  Destination: {entry.dst}")
            print(f"  Protocol: {entry.proto}")
            print(f"  Interface: {entry.interface}")
            
        # Count where 103.26.150.122 appears as source vs destination
        as_source = 0
        as_destination = 0
        
        for entry in entries_with_target:
            if entry.src and target_ip in entry.src:
                as_source += 1
            if entry.dst and target_ip in entry.dst:
                as_destination += 1
                
        print(f"\n--- Analysis ---")
        print(f"{target_ip} appears as SOURCE in {as_source} blocked entries")
        print(f"{target_ip} appears as DESTINATION in {as_destination} blocked entries")
        
        # Get top blocked IPs for comparison
        top_blocked = lqe.get_top_blocked_ips(top_n=5)
        print(f"\n--- Top Blocked Source IPs ---")
        for ip, count in top_blocked:
            print(f"  {ip}: {count} blocks")
            
        # Check if there's data corruption or field swapping
        print(f"\n--- Checking for Data Issues ---")
        suspicious_entries = []
        for entry in blocked[:100]:  # Check first 100 blocked entries
            # Look for entries where the "source" looks like it should be destination
            if entry.src == target_ip:
                suspicious_entries.append(entry)
                
        print(f"Found {len(suspicious_entries)} entries where {target_ip} is listed as SOURCE")
        
        if suspicious_entries:
            print(f"\n--- Sample Suspicious Entries ---")
            for i, entry in enumerate(suspicious_entries[:5]):
                print(f"\nSuspicious Entry {i+1}:")
                print(f"  Source: {entry.src} (this should probably be destination)")
                print(f"  Destination: {entry.dst}")
                print(f"  Action: {entry.action}")
                print(f"  Interface: {entry.interface}")
                
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    investigate_blocked_ips()
