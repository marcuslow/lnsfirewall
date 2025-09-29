#!/usr/bin/env python3
"""
Test script for risk assessment functionality
"""
import json
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'hq'))
from lqe import LogQueryEngine

# Enhanced sample data with risk scenarios
RISK_SAMPLE = [
    # Normal traffic
    {"timestamp": "2025-09-25T12:00:00", "action": "pass", "proto": "tcp", "src": "192.168.1.100", "src_port": 55555, "dst": "192.168.1.10", "dst_port": 80},
    {"timestamp": "2025-09-25T12:00:05", "action": "pass", "proto": "tcp", "src": "192.168.1.100", "src_port": 55556, "dst": "192.168.1.10", "dst_port": 443},
    
    # Brute force attempts from 10.0.0.1 on SSH
    {"timestamp": "2025-09-25T12:01:00", "action": "block", "proto": "tcp", "src": "10.0.0.1", "src_port": 40001, "dst": "192.168.1.10", "dst_port": 22},
    {"timestamp": "2025-09-25T12:01:05", "action": "block", "proto": "tcp", "src": "10.0.0.1", "src_port": 40002, "dst": "192.168.1.10", "dst_port": 22},
    {"timestamp": "2025-09-25T12:01:10", "action": "block", "proto": "tcp", "src": "10.0.0.1", "src_port": 40003, "dst": "192.168.1.10", "dst_port": 22},
    {"timestamp": "2025-09-25T12:01:15", "action": "block", "proto": "tcp", "src": "10.0.0.1", "src_port": 40004, "dst": "192.168.1.10", "dst_port": 22},
    {"timestamp": "2025-09-25T12:01:20", "action": "block", "proto": "tcp", "src": "10.0.0.1", "src_port": 40005, "dst": "192.168.1.10", "dst_port": 22},
    {"timestamp": "2025-09-25T12:01:25", "action": "block", "proto": "tcp", "src": "10.0.0.1", "src_port": 40006, "dst": "192.168.1.10", "dst_port": 22},
    
    # Port scan from 10.0.0.2
    {"timestamp": "2025-09-25T12:02:00", "action": "block", "proto": "tcp", "src": "10.0.0.2", "src_port": 50001, "dst": "192.168.1.10", "dst_port": 21},
    {"timestamp": "2025-09-25T12:02:01", "action": "block", "proto": "tcp", "src": "10.0.0.2", "src_port": 50002, "dst": "192.168.1.10", "dst_port": 22},
    {"timestamp": "2025-09-25T12:02:02", "action": "block", "proto": "tcp", "src": "10.0.0.2", "src_port": 50003, "dst": "192.168.1.10", "dst_port": 23},
    {"timestamp": "2025-09-25T12:02:03", "action": "block", "proto": "tcp", "src": "10.0.0.2", "src_port": 50004, "dst": "192.168.1.10", "dst_port": 25},
    {"timestamp": "2025-09-25T12:02:04", "action": "block", "proto": "tcp", "src": "10.0.0.2", "src_port": 50005, "dst": "192.168.1.10", "dst_port": 53},
    {"timestamp": "2025-09-25T12:02:05", "action": "block", "proto": "tcp", "src": "10.0.0.2", "src_port": 50006, "dst": "192.168.1.10", "dst_port": 80},
    {"timestamp": "2025-09-25T12:02:06", "action": "block", "proto": "tcp", "src": "10.0.0.2", "src_port": 50007, "dst": "192.168.1.10", "dst_port": 110},
    {"timestamp": "2025-09-25T12:02:07", "action": "block", "proto": "tcp", "src": "10.0.0.2", "src_port": 50008, "dst": "192.168.1.10", "dst_port": 143},
    {"timestamp": "2025-09-25T12:02:08", "action": "block", "proto": "tcp", "src": "10.0.0.2", "src_port": 50009, "dst": "192.168.1.10", "dst_port": 443},
    {"timestamp": "2025-09-25T12:02:09", "action": "block", "proto": "tcp", "src": "10.0.0.2", "src_port": 50010, "dst": "192.168.1.10", "dst_port": 993},
    {"timestamp": "2025-09-25T12:02:10", "action": "block", "proto": "tcp", "src": "10.0.0.2", "src_port": 50011, "dst": "192.168.1.10", "dst_port": 995},
    {"timestamp": "2025-09-25T12:02:11", "action": "block", "proto": "tcp", "src": "10.0.0.2", "src_port": 50012, "dst": "192.168.1.10", "dst_port": 3389},
    
    # Some random blocked traffic
    {"timestamp": "2025-09-25T12:03:00", "action": "block", "proto": "udp", "src": "9.9.9.9", "src_port": 12345, "dst": "192.168.1.255", "dst_port": 53},
    {"timestamp": "2025-09-25T12:03:05", "action": "reject", "proto": "tcp", "src": "4.3.2.1", "src_port": 40000, "dst": "192.168.1.20", "dst_port": 443},
]

def main():
    print("=== Risk Assessment Test ===")
    lqe = LogQueryEngine(RISK_SAMPLE)
    
    print(f"\nTotal entries: {len(lqe.entries)}")
    
    # Test basic filters
    blocked = lqe.filter_blocked()
    allowed = lqe.filter_allowed()
    print(f"Blocked: {len(blocked)}, Allowed: {len(allowed)}")
    
    # Test new risk detection methods
    print("\n=== Brute Force Detection ===")
    brute_force = lqe.detect_brute_force(threshold=5)
    print(f"Brute force attempts detected: {len(brute_force)}")
    for entry in brute_force[:3]:  # Show first 3
        print(f"  {entry.src} -> {entry.dst}:{entry.dst_port} ({entry.action})")
    
    print("\n=== Port Scan Detection ===")
    port_scans = lqe.detect_port_scans(threshold=10)
    print(f"Port scan attempts detected: {len(port_scans)}")
    for entry in port_scans[:3]:  # Show first 3
        print(f"  {entry.src} -> {entry.dst}:{entry.dst_port} ({entry.action})")
    
    print("\n=== Top Blocked IPs ===")
    top_blocked = lqe.get_top_blocked_ips(top_n=5)
    for ip, count in top_blocked:
        print(f"  {ip}: {count} blocks")
    
    print("\n=== Risk Assessment Summary ===")
    summary = lqe.summarize(top_n=5)
    print(f"Total blocked: {summary['blocked_count']}")
    print(f"Total allowed: {summary['allowed_count']}")
    print(f"Brute force events: {len(brute_force)}")
    print(f"Port scan events: {len(port_scans)}")
    
    # Risk level calculation (similar to what's in ai_command_center.py)
    blocked_count = len(blocked)
    brute_force_count = len(brute_force)
    port_scan_count = len(port_scans)
    
    if blocked_count > 100 or brute_force_count > 10 or port_scan_count > 20:
        risk_level = 'High'
    elif blocked_count > 10 or brute_force_count > 0 or port_scan_count > 5:
        risk_level = 'Medium'
    else:
        risk_level = 'Low'
    
    print(f"\nCalculated Risk Level: {risk_level}")
    
    # Generate recommendations
    recommendations = []
    if brute_force_count > 0:
        recommendations.append('Block top suspicious IPs if recurring')
        recommendations.append('Review rules for authentication ports (SSH, RDP)')
    if port_scan_count > 0:
        recommendations.append('Investigate potential port scanning activity')
    if blocked_count > 50:
        recommendations.append('Consider rate limiting or additional blocking rules')
    if top_blocked and top_blocked[0][1] > 20:
        recommendations.append(f'Investigate top blocked IP: {top_blocked[0][0]} ({top_blocked[0][1]} blocks)')
    
    print(f"\nRecommendations:")
    for rec in recommendations:
        print(f"  - {rec}")

if __name__ == '__main__':
    main()
