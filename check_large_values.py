#!/usr/bin/env python3
"""Check for large integer values in parsed logs"""

import json

# Load the most recent parsed log file
with open('temp/opus-1/20251008_182223_parsed.json', 'r') as f:
    data = json.load(f)

print(f"Checking {len(data)} log entries for large integers...")
print()

# First, find all integer fields
all_fields = set()
for entry in data:
    for key, val in entry.items():
        if isinstance(val, int):
            all_fields.add(key)

print(f"Found integer fields: {sorted(all_fields)}")
print()

# Fields to check
fields = sorted(all_fields)

# Track max values
max_vals = {f: 0 for f in fields}
max_entries = {f: None for f in fields}

# Check each entry
for entry in data:
    for field in fields:
        val = entry.get(field)
        if val is not None and isinstance(val, int):
            if val > max_vals[field]:
                max_vals[field] = val
                max_entries[field] = entry

print("Max values found:")
print("-" * 60)
for field in fields:
    print(f"{field:20s}: {max_vals[field]:,}")
    if max_vals[field] > 2147483647:  # PostgreSQL INTEGER max
        print(f"  ⚠️  EXCEEDS INTEGER RANGE! (max: 2,147,483,647)")
        print(f"  Sample entry: {max_entries[field].get('raw_message', '')[:100]}")
print()

# Also check raw_message for any large numbers
print("Checking raw_message fields for large numbers...")
import re
large_numbers = []
for entry in data:
    raw = entry.get('raw_message', '')
    # Find all numbers in the raw message
    numbers = re.findall(r'\d+', raw)
    for num_str in numbers:
        num = int(num_str)
        if num > 2147483647:
            large_numbers.append((num, raw[:150]))

if large_numbers:
    print(f"Found {len(large_numbers)} instances of numbers > INTEGER max:")
    for num, raw in large_numbers[:5]:  # Show first 5
        print(f"  {num:,} in: {raw}")
else:
    print("No numbers exceeding INTEGER max found in raw_message")

