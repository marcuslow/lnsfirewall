#!/usr/bin/env python3
"""
Quick test for Tool 3 (Geographic Threat Mapper) only
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'hq'))

from lqe import LogQueryEngine
from dotenv import load_dotenv

def test_geographic_mapper():
    print("=" * 80)
    print("🌍 TESTING TOOL 3: Geographic Threat Mapper")
    print("=" * 80)
    
    # Load environment variables
    load_dotenv()
    
    # Get config from .env
    ipinfo_token = os.getenv('IPINFO_TOKEN')
    max_lookups = int(os.getenv('IPINFO_MAX_LOOKUPS', '10'))
    geoip2_db_path = os.getenv('GEOIP2_DB_PATH')

    print(f"\n📋 Configuration:")
    if ipinfo_token:
        print(f"   ✅ IPINFO_TOKEN: {ipinfo_token[:10]}...")
        print(f"   ✅ Max ipinfo API lookups: {max_lookups}")
    else:
        print(f"   ⚠️  IPINFO_TOKEN not set (will skip org/ISP details)")

    if geoip2_db_path:
        if os.path.exists(geoip2_db_path):
            print(f"   ✅ GeoIP2 database: {geoip2_db_path}")
        else:
            print(f"   ❌ GeoIP2 database not found: {geoip2_db_path}")
            geoip2_db_path = None
    else:
        print(f"   ⚠️  GEOIP2_DB_PATH not set (will use ipinfo API only)")

    if not ipinfo_token and not geoip2_db_path:
        print("\n❌ ERROR: Need either IPINFO_TOKEN or GEOIP2_DB_PATH")
        print("   Download GeoLite2: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data")
        return
    
    # Load logs for opus-1
    client_id = "8cbb62eecbb00579"
    days = 7
    
    print(f"\n📊 Loading logs for client: {client_id}")
    print(f"📅 Period: {days} days")
    
    lqe = LogQueryEngine.from_db("hq_database.db", client_id, since_days=days)
    
    print(f"✅ Loaded {len(lqe.entries)} log entries")
    
    # Run geographic analysis
    print("\n" + "=" * 80)
    print("🔍 Running Geographic Threat Analysis...")
    print("=" * 80)
    
    result = lqe.map_geographic_threats(
        ipinfo_token=ipinfo_token,
        top_n=10,  # Get top 10 countries
        cache_db_path="hq_database.db",
        blocked_only=True,
        max_api_lookups=max_lookups,
        geoip2_db_path=geoip2_db_path
    )
    
    if not result.get('success'):
        print(f"❌ Error: {result.get('error')}")
        return
    
    # Display results
    print(f"\n✅ Analysis complete!")
    print(f"   Total unique IPs: {result.get('total_unique_ips', 0):,}")
    print(f"   IPs resolved: {result.get('ips_resolved', 0):,}")
    print(f"   IPs unresolved: {result.get('ips_unresolved', 0):,}")
    print(f"   Countries detected: {result.get('countries_detected', 0)}")
    print(f"\n📊 Lookup breakdown:")
    print(f"   GeoIP2 offline lookups: {result.get('geoip2_offline_lookups', 0):,}")
    print(f"   ipinfo API lookups: {result.get('ipinfo_api_lookups', 0)}")
    print(f"   Cache hits: {result.get('cache_hits', 0):,}")
    print(f"   IPs skipped (quota limit): {result.get('ips_skipped', 0):,}")
    
    # Show top countries
    top_countries = result.get('top_source_countries', [])
    
    if top_countries:
        print(f"\n🌍 TOP {len(top_countries)} SOURCE COUNTRIES:")
        print("=" * 80)
        
        for i, country in enumerate(top_countries, 1):
            country_name = country.get('country_name', 'Unknown')
            country_code = country.get('country_code', '??')
            connections = country.get('blocked_connections', 0)
            percentage = country.get('percentage', 0)
            sample_ips = country.get('sample_ips', [])
            sample_orgs = country.get('sample_orgs', [])
            
            print(f"\n{i}. {country_name} ({country_code})")
            print(f"   Blocked connections: {connections:,} ({percentage}%)")
            print(f"   Sample IPs: {', '.join(sample_ips[:3])}")
            if sample_orgs and sample_orgs[0] != 'Unknown':
                # Filter out None values
                valid_orgs = [org for org in sample_orgs[:2] if org and org != 'Unknown']
                if valid_orgs:
                    print(f"   Organizations: {', '.join(valid_orgs)}")
    else:
        print("\n⚠️ No countries detected")
    
    print("\n" + "=" * 80)
    print("✅ Test complete!")
    print("=" * 80)

if __name__ == "__main__":
    test_geographic_mapper()

