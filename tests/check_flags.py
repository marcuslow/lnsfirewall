#!/usr/bin/env python3
import json

with open('temp/opus-1/20251008_182223_parsed.json', 'r') as f:
    data = json.load(f)

print("Sample flags and tcp_flags values:")
for i, e in enumerate(data[:20]):
    print(f"{i+1}. flags: {e.get('flags')}, tcp_flags: {e.get('tcp_flags')}")

