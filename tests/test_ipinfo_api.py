#!/usr/bin/env python3
"""
Test ipinfo API to see what data it returns
"""
import ipinfo
import os
from dotenv import load_dotenv

load_dotenv()
token = os.getenv('IPINFO_TOKEN')

if not token:
    print("❌ IPINFO_TOKEN not found!")
    exit(1)

print(f"✅ Token: {token[:10]}...")

handler = ipinfo.getHandler(token)

# Test with a known IP
test_ip = "8.8.8.8"
print(f"\n🔍 Testing with IP: {test_ip}")

try:
    details = handler.getDetails(test_ip)
    print(f"\n✅ Response received!")
    print(f"Type: {type(details)}")
    print(f"\nAttributes:")
    for attr in dir(details):
        if not attr.startswith('_'):
            value = getattr(details, attr, None)
            if not callable(value):
                print(f"  {attr}: {value}")
    
    print(f"\nDetails dict:")
    print(f"  {details.all}")
    
except Exception as e:
    print(f"❌ Error: {e}")

