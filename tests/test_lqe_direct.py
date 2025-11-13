#!/usr/bin/env python3
"""
Direct test of LQE with real data
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'hq'))

from lqe import LogQueryEngine

def test_lqe_direct():
    print("=" * 80)
    print("🔍 Direct LQE Test with Real Data")
    print("=" * 80)
    
    client_id = "8cbb62eecbb00579"  # opus-1
    db_path = "hq_database.db"
    days = 7
    
    print(f"\nLoading logs for client: {client_id}")
    print(f"Database: {db_path}")
    print(f"Days: {days}")
    
    # Load logs from database
    lqe = LogQueryEngine.from_db(
        db_path=db_path,
        client_id=client_id,
        since_days=days
    )
    
    print(f"\n✅ Loaded {len(lqe.entries)} log entries")
    
    # Test Tool 1: Summary
    print("\n" + "=" * 80)
    print("TOOL 1: Summary")
    print("=" * 80)
    summary = lqe.summarize(top_n=10)
    print(f"Total entries: {summary.get('total_entries', 0)}")
    print(f"Blocked count: {summary.get('blocked_count', 0)}")
    print(f"Allowed count: {summary.get('allowed_count', 0)}")
    print(f"Top source IPs: {len(summary.get('top_src_ips', []))}")
    print(f"Top destination ports: {len(summary.get('top_dst_ports', []))}")

    if summary.get('top_src_ips'):
        print("\nTop 5 source IPs:")
        for item in summary['top_src_ips'][:5]:
            print(f"  {item['value']}: {item['count']}")

    if summary.get('top_dst_ports'):
        print("\nTop 5 destination ports:")
        for item in summary['top_dst_ports'][:5]:
            print(f"  Port {item['value']}: {item['count']}")
    
    # Test Tool 2: Scanning
    print("\n" + "=" * 80)
    print("TOOL 2: Scanning Detection")
    print("=" * 80)
    scanning = lqe.detect_scanning_activity(
        port_scan_threshold=15,
        network_sweep_threshold=15
    )
    print(f"Vertical scans: {scanning.get('total_vertical_scans', 0)}")
    print(f"Horizontal scans: {scanning.get('total_horizontal_scans', 0)}")
    
    if scanning.get('vertical_scans'):
        print("\nTop 3 vertical scans:")
        for scan in scanning['vertical_scans'][:3]:
            print(f"  {scan['source_ip']} → {scan['destination_ip']}: {scan['unique_ports_scanned']} ports")
    
    # Test Tool 5: Outbound
    print("\n" + "=" * 80)
    print("TOOL 5: Outbound Monitoring")
    print("=" * 80)
    outbound = lqe.monitor_outbound_connections()
    print(f"Total allowed: {outbound.get('total_allowed_connections', 0)}")
    print(f"Total outbound: {outbound.get('total_outbound_connections', 0)}")
    print(f"Suspicious: {outbound.get('suspicious_outbound_connections', 0)}")
    print(f"Affected hosts: {outbound.get('unique_internal_hosts_affected', 0)}")
    
    if outbound.get('suspicious_connections'):
        print("\nSuspicious connections:")
        for conn in outbound['suspicious_connections'][:5]:
            print(f"  {conn['source_ip']} → {conn['destination_ip']}:{conn['destination_port']} ({conn['connection_count']} times)")

if __name__ == '__main__':
    test_lqe_direct()

