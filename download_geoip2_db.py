#!/usr/bin/env python3
"""
Download MaxMind GeoLite2 Country database (free)

NOTE: MaxMind now requires a free account to download GeoLite2 databases.
This script provides instructions for manual download.

For automated downloads, you'll need to:
1. Sign up at https://www.maxmind.com/en/geolite2/signup
2. Get your license key
3. Use the geoipupdate tool or API
"""

import os
import sys

def main():
    print("=" * 80)
    print("📥 GeoLite2 Database Download Instructions")
    print("=" * 80)
    
    print("\n🔑 Step 1: Create Free MaxMind Account")
    print("   Visit: https://www.maxmind.com/en/geolite2/signup")
    print("   - No credit card required")
    print("   - Verify your email")
    
    print("\n📦 Step 2: Download GeoLite2-Country Database")
    print("   Visit: https://www.maxmind.com/en/accounts/current/geoip/downloads")
    print("   - Download: GeoLite2 Country (MMDB format)")
    print("   - File: GeoLite2-Country.mmdb (~6MB)")
    print("   - Alternative: GeoLite2-City.mmdb (~70MB, includes city data)")
    
    print("\n📁 Step 3: Extract and Place Database")
    print("   - Extract the .tar.gz file")
    print("   - Copy GeoLite2-Country.mmdb to this project folder")
    print(f"   - Recommended location: {os.path.abspath('.')}")
    
    print("\n⚙️  Step 4: Update .env File")
    print("   Add this line to your .env file:")
    print("   GEOIP2_DB_PATH=./GeoLite2-Country.mmdb")
    
    print("\n✅ Step 5: Install Python Library")
    print("   Run: pip install geoip2")
    
    print("\n" + "=" * 80)
    print("📚 Alternative: Use dbip-city-lite (No Account Required)")
    print("=" * 80)
    print("\nIf you don't want to create a MaxMind account, you can use dbip-city-lite:")
    print("   1. Visit: https://db-ip.com/db/download/ip-to-city-lite")
    print("   2. Download: MMDB format")
    print("   3. Extract and rename to: dbip-city-lite.mmdb")
    print("   4. Update .env: GEOIP2_DB_PATH=./dbip-city-lite.mmdb")
    print("   5. Install: pip install geoip2")
    print("\nNote: dbip uses same .mmdb format, compatible with geoip2 library")
    
    print("\n" + "=" * 80)
    print("🧪 Step 6: Test the Database")
    print("=" * 80)
    print("   Run: python test_tool3_only.py")
    print("   You should see: '✅ GeoIP2 database: ./GeoLite2-Country.mmdb'")
    
    print("\n" + "=" * 80)
    print("💡 Expected Results After Setup")
    print("=" * 80)
    print("   Before (ipinfo API only, limit=10):")
    print("      Countries detected: 9")
    print("      API lookups: 10")
    print("\n   After (GeoIP2 + ipinfo hybrid):")
    print("      Countries detected: 45-60 ✅")
    print("      GeoIP2 offline lookups: 8,453")
    print("      ipinfo API lookups: 10 (top attackers only)")
    
    print("\n" + "=" * 80)
    
    # Check if database already exists
    possible_paths = [
        './GeoLite2-Country.mmdb',
        './GeoLite2-City.mmdb',
        './dbip-city-lite.mmdb',
        './hq/GeoLite2-Country.mmdb'
    ]
    
    found = []
    for path in possible_paths:
        if os.path.exists(path):
            size_mb = os.path.getsize(path) / (1024 * 1024)
            found.append(f"   ✅ {path} ({size_mb:.1f} MB)")
    
    if found:
        print("\n🎉 Found existing database(s):")
        for f in found:
            print(f)
        print("\nYou're all set! Run: python test_tool3_only.py")
    else:
        print("\n⚠️  No database found. Please follow the steps above.")
    
    print("\n" + "=" * 80)

if __name__ == "__main__":
    main()

