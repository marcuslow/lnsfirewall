#!/usr/bin/env python3
"""
Check why 103.26.150.122 appears in blocked logs
"""
import sqlite3

conn = sqlite3.connect('hq_database.db')
cur = conn.cursor()

print("=" * 100)
print("🔍 Investigating IP: 103.26.150.122")
print("=" * 100)

# Count total
cur.execute("""
    SELECT COUNT(*) FROM firewall_logs 
    WHERE client_id = '8cbb62eecbb00579' AND src = '103.26.150.122'
""")
total = cur.fetchone()[0]
print(f"\nTotal logs with src=103.26.150.122: {total:,}")

# Count by action
cur.execute("""
    SELECT action, COUNT(*) as count 
    FROM firewall_logs 
    WHERE client_id = '8cbb62eecbb00579' AND src = '103.26.150.122'
    GROUP BY action
    ORDER BY count DESC
""")
print("\nBreakdown by action:")
for row in cur.fetchall():
    print(f"  {row[0]}: {row[1]:,}")

# Sample blocked entries
print("\n" + "=" * 100)
print("📋 Sample BLOCKED logs (first 5):")
print("=" * 100)
cur.execute("""
    SELECT timestamp, action, interface, proto, src, src_port, dst, dst_port
    FROM firewall_logs 
    WHERE client_id = '8cbb62eecbb00579' AND src = '103.26.150.122' AND action = 'block'
    LIMIT 5
""")

rows = cur.fetchall()
if rows:
    print(f"\n{'Timestamp':<20} {'Action':<8} {'Interface':<12} {'Proto':<6} {'Src':<18} {'SPort':<8} {'Dst':<18} {'DPort':<8}")
    print("-" * 110)
    for row in rows:
        print(f"{str(row[0]):<20} {str(row[1]):<8} {str(row[2]):<12} {str(row[3]):<6} {str(row[4]):<18} {str(row[5]):<8} {str(row[6]):<18} {str(row[7]):<8}")
else:
    print("No blocked entries found")

# Check interfaces
print("\n" + "=" * 100)
print("🔌 Breakdown by Interface:")
print("=" * 100)
cur.execute("""
    SELECT interface, action, COUNT(*) as count 
    FROM firewall_logs 
    WHERE client_id = '8cbb62eecbb00579' AND src = '103.26.150.122'
    GROUP BY interface, action
    ORDER BY count DESC
    LIMIT 10
""")
print(f"\n{'Interface':<15} {'Action':<10} {'Count':<10}")
print("-" * 40)
for row in cur.fetchall():
    print(f"{str(row[0]):<15} {str(row[1]):<10} {row[2]:<10,}")

# Check destination IPs
print("\n" + "=" * 100)
print("🎯 Top Destination IPs:")
print("=" * 100)
cur.execute("""
    SELECT dst, COUNT(*) as count 
    FROM firewall_logs 
    WHERE client_id = '8cbb62eecbb00579' AND src = '103.26.150.122' AND action = 'block'
    GROUP BY dst
    ORDER BY count DESC
    LIMIT 10
""")
print(f"\n{'Destination IP':<18} {'Count':<10}")
print("-" * 30)
for row in cur.fetchall():
    print(f"{str(row[0]):<18} {row[1]:<10,}")

# Check if this is internal traffic
print("\n" + "=" * 100)
print("💡 Analysis:")
print("=" * 100)

cur.execute("""
    SELECT interface FROM firewall_logs 
    WHERE client_id = '8cbb62eecbb00579' AND src = '103.26.150.122' AND action = 'block'
    LIMIT 1
""")
interface = cur.fetchone()
if interface:
    interface = interface[0]
    print(f"\nInterface: {interface}")
    
    if interface and ('lan' in interface.lower() or 'igb' in interface.lower() or 'em' in interface.lower()):
        print("\n⚠️  PROBLEM IDENTIFIED: NAT Reflection / Hairpin NAT")
        print("   - Internal devices trying to access firewall's WAN IP")
        print("   - pfSense blocks this (shows as src=WAN_IP after NAT)")
        print("   - This is NOT an external attack!")
    elif interface and ('wan' in interface.lower() or 'pppoe' in interface.lower()):
        print("\n⚠️  PROBLEM IDENTIFIED: Outbound Traffic")
        print("   - Traffic FROM the firewall itself")
        print("   - This is NOT an inbound attack!")
    else:
        print(f"\n⚠️  Unknown interface: {interface}")

print("\n✅ SOLUTION: Exclude firewall's own WAN IP from threat analysis")

conn.close()

