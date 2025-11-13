#!/usr/bin/env python3
"""
Investigate why opus-1's own WAN IP (103.26.150.122) appears in blocked logs
"""
import sqlite3

def investigate():
    conn = sqlite3.connect('hq_database.db')
    cur = conn.cursor()
    
    # Get opus-1's WAN IP from client registration
    print("=" * 80)
    print("🔍 Checking opus-1 WAN IP")
    print("=" * 80)
    cur.execute("SELECT client_id, client_name, wan_ip FROM clients WHERE client_id = '8cbb62eecbb00579'")
    client = cur.fetchone()
    if client:
        print(f"Client ID: {client[0]}")
        print(f"Client Name: {client[1]}")
        print(f"WAN IP: {client[2]}")
        wan_ip = client[2]
    else:
        print("Client not found!")
        return
    
    print("\n" + "=" * 80)
    print(f"📊 Analyzing logs with src={wan_ip}")
    print("=" * 80)
    
    # Count total logs with this source IP
    cur.execute("""
        SELECT COUNT(*) FROM firewall_logs 
        WHERE client_id = '8cbb62eecbb00579' AND src = ?
    """, (wan_ip,))
    total = cur.fetchone()[0]
    print(f"\nTotal logs with src={wan_ip}: {total:,}")
    
    # Count by action
    cur.execute("""
        SELECT action, COUNT(*) as count 
        FROM firewall_logs 
        WHERE client_id = '8cbb62eecbb00579' AND src = ?
        GROUP BY action
        ORDER BY count DESC
    """, (wan_ip,))
    print("\nBreakdown by action:")
    for row in cur.fetchall():
        print(f"  {row[0]}: {row[1]:,}")
    
    # Sample blocked entries
    print("\n" + "=" * 80)
    print("📋 Sample BLOCKED logs (first 10):")
    print("=" * 80)
    cur.execute("""
        SELECT timestamp, action, interface, proto, src, src_port, dst, dst_port, reason
        FROM firewall_logs 
        WHERE client_id = '8cbb62eecbb00579' AND src = ? AND action IN ('block', 'blocked', 'reject')
        LIMIT 10
    """, (wan_ip,))
    
    print(f"{'Timestamp':<20} {'Action':<8} {'Interface':<10} {'Proto':<6} {'Src':<18} {'SPort':<6} {'Dst':<18} {'DPort':<6} {'Reason':<20}")
    print("-" * 140)
    for row in cur.fetchall():
        print(f"{str(row[0]):<20} {str(row[1]):<8} {str(row[2]):<10} {str(row[3]):<6} {str(row[4]):<18} {str(row[5]):<6} {str(row[6]):<18} {str(row[7]):<6} {str(row[8]):<20}")
    
    # Sample allowed entries
    print("\n" + "=" * 80)
    print("📋 Sample ALLOWED logs (first 10):")
    print("=" * 80)
    cur.execute("""
        SELECT timestamp, action, interface, proto, src, src_port, dst, dst_port
        FROM firewall_logs 
        WHERE client_id = '8cbb62eecbb00579' AND src = ? AND action IN ('pass', 'allow', 'allowed')
        LIMIT 10
    """, (wan_ip,))
    
    print(f"{'Timestamp':<20} {'Action':<8} {'Interface':<10} {'Proto':<6} {'Src':<18} {'SPort':<6} {'Dst':<18} {'DPort':<6}")
    print("-" * 120)
    for row in cur.fetchall():
        print(f"{str(row[0]):<20} {str(row[1]):<8} {str(row[2]):<10} {str(row[3]):<6} {str(row[4]):<18} {str(row[5]):<6} {str(row[6]):<18} {str(row[7]):<6}")
    
    # Check interfaces
    print("\n" + "=" * 80)
    print("🔌 Breakdown by Interface:")
    print("=" * 80)
    cur.execute("""
        SELECT interface, action, COUNT(*) as count 
        FROM firewall_logs 
        WHERE client_id = '8cbb62eecbb00579' AND src = ?
        GROUP BY interface, action
        ORDER BY count DESC
    """, (wan_ip,))
    print(f"{'Interface':<15} {'Action':<10} {'Count':<10}")
    print("-" * 40)
    for row in cur.fetchall():
        print(f"{str(row[0]):<15} {str(row[1]):<10} {row[2]:<10,}")
    
    # Check destination IPs
    print("\n" + "=" * 80)
    print("🎯 Top Destination IPs (where is this traffic going?):")
    print("=" * 80)
    cur.execute("""
        SELECT dst, action, COUNT(*) as count 
        FROM firewall_logs 
        WHERE client_id = '8cbb62eecbb00579' AND src = ?
        GROUP BY dst, action
        ORDER BY count DESC
        LIMIT 10
    """, (wan_ip,))
    print(f"{'Destination IP':<18} {'Action':<10} {'Count':<10}")
    print("-" * 40)
    for row in cur.fetchall():
        print(f"{str(row[0]):<18} {str(row[1]):<10} {row[2]:<10,}")
    
    conn.close()
    
    print("\n" + "=" * 80)
    print("💡 Analysis:")
    print("=" * 80)
    print("""
This is likely one of these scenarios:

1. **NAT Reflection / Hairpin NAT**
   - Internal devices trying to access the firewall's WAN IP
   - pfSense blocks this by default (anti-lockout rule)
   - Shows as src=WAN_IP because of NAT translation

2. **Outbound traffic being logged**
   - Traffic FROM the firewall itself (src=WAN_IP)
   - Going to external destinations
   - Should NOT be counted as "attacks"

3. **Interface confusion**
   - Check the 'interface' field above
   - If interface is LAN/internal, it's scenario #1
   - If interface is WAN, it's scenario #2

**Solution:** Filter out the firewall's own WAN IP from threat analysis!
    """)

if __name__ == "__main__":
    investigate()

