#!/usr/bin/env python3
import sqlite3

conn = sqlite3.connect('hq_database.db')
cur = conn.cursor()

print("📊 Impact Analysis of Unparsed Log Entries\n")
print("=" * 60)

# Total entries
cur.execute("SELECT COUNT(*) FROM log_entries WHERE client_id = 'opus-1'")
total = cur.fetchone()[0]

# Parsed entries (have action field)
cur.execute("SELECT COUNT(*) FROM log_entries WHERE client_id = 'opus-1' AND action IS NOT NULL")
parsed = cur.fetchone()[0]

# Unparsed entries
unparsed = total - parsed

print(f"\n📈 Overall Statistics:")
print(f"   Total entries:    {total:,}")
print(f"   Parsed entries:   {parsed:,} ({parsed/total*100:.1f}%)")
print(f"   Unparsed entries: {unparsed:,} ({unparsed/total*100:.1f}%)")

# Breakdown by log type
print(f"\n📋 Breakdown by Log Type:")
cur.execute("""
    SELECT log_type, COUNT(*) as count
    FROM log_entries 
    WHERE client_id = 'opus-1'
    GROUP BY log_type
    ORDER BY count DESC
""")
for log_type, count in cur.fetchall():
    print(f"   {log_type or 'unknown':15s}: {count:,} ({count/total*100:.1f}%)")

# Breakdown by source file
print(f"\n📁 Breakdown by Source File:")
cur.execute("""
    SELECT source, COUNT(*) as count
    FROM log_entries 
    WHERE client_id = 'opus-1'
    GROUP BY source
    ORDER BY count DESC
    LIMIT 10
""")
for source, count in cur.fetchall():
    print(f"   {source or 'unknown':20s}: {count:,}")

# Check what's in the unparsed entries
print(f"\n🔍 Sample Unparsed Entry:")
cur.execute("""
    SELECT raw_message 
    FROM log_entries 
    WHERE client_id = 'opus-1' AND log_type = 'unparsed'
    LIMIT 1
""")
row = cur.fetchone()
if row:
    msg = row[0]
    print(f"   {msg[:150]}...")
    
    # Try to identify the pattern
    if 'filterlog[' in msg:
        print(f"\n   ⚠️  This is a FILTER LOG (firewall rules)")
        print(f"   ⚠️  Contains critical security data!")
        
        # Extract the CSV part after ']:' 
        if ']:' in msg:
            csv_part = msg.split(']:')[1].strip()
            fields = csv_part.split(',')
            print(f"\n   📊 CSV Fields Available: {len(fields)}")
            if len(fields) > 19:
                print(f"      Rule: {fields[0]}")
                print(f"      Interface: {fields[4]}")
                print(f"      Action: {fields[6]}")
                print(f"      Direction: {fields[7]}")
                print(f"      Protocol: {fields[16] if len(fields) > 16 else 'N/A'}")
                print(f"      Source IP: {fields[18] if len(fields) > 18 else 'N/A'}")
                print(f"      Dest IP: {fields[19] if len(fields) > 19 else 'N/A'}")

# Impact on security analysis
print(f"\n⚠️  SECURITY ANALYSIS IMPACT:")
print(f"   - Port scanning detection: Missing {unparsed/total*100:.1f}% of data")
print(f"   - Geographic threat mapping: Missing {unparsed/total*100:.1f}% of data")
print(f"   - Blocked connection counts: Off by {unparsed:,} entries")
print(f"   - Protocol analysis: Incomplete")

# What percentage of blocks are we missing?
cur.execute("""
    SELECT COUNT(*) 
    FROM log_entries 
    WHERE client_id = 'opus-1' AND action = 'block'
""")
known_blocks = cur.fetchone()[0]

print(f"\n🚨 Known Blocked Connections: {known_blocks:,}")
print(f"   Potential Total (if unparsed are blocks): ~{total:,}")
print(f"   Missing: ~{unparsed:,} potential blocks")

conn.close()

print("\n" + "=" * 60)
print("\n💡 RECOMMENDATION:")
print("   Fix the client-side log parser to handle filter logs")
print("   with double-space date formatting (e.g., 'Oct  1' vs 'Oct 1')")
print("\n   This will enable full security analysis capabilities.")

