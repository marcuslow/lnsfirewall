#!/usr/bin/env python3
"""
Test Tool 3: Geographic Threat Mapper with real data
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'hq'))

from lqe import LogQueryEngine
from dotenv import load_dotenv

def test_geographic_analysis():
    print("=" * 80)
    print("🌍 TESTING TOOL 3: Geographic Threat Mapper")
    print("=" * 80)
    
    # Load environment variables
    load_dotenv()
    ipinfo_token = os.getenv('IPINFO_TOKEN')
    
    if not ipinfo_token:
        print("❌ IPINFO_TOKEN not found in .env file!")
        return
    
    print(f"\n✅ IPINFO_TOKEN found: {ipinfo_token[:10]}...")
    
    client_id = "8cbb62eecbb00579"  # opus-1
    db_path = "hq_database.db"
    days = 7
    
    print(f"\n📊 Loading logs for client: {client_id}")
    print(f"📅 Analysis period: {days} days")
    
    # Load logs from database
    lqe = LogQueryEngine.from_db(
        db_path=db_path,
        client_id=client_id,
        since_days=days
    )
    
    print(f"✅ Loaded {len(lqe.entries):,} log entries")
    
    # Test geographic analysis
    print("\n" + "=" * 80)
    print("🌍 Running Geographic Threat Analysis...")
    print("=" * 80)
    print("⏳ This may take a moment on first run (building cache)...")
    
    geo_results = lqe.map_geographic_threats(
        ipinfo_token=ipinfo_token,
        top_n=10,
        cache_db_path=db_path,
        blocked_only=True
    )
    
    if not geo_results.get('success'):
        print(f"\n❌ Geographic analysis failed: {geo_results.get('error', 'Unknown error')}")
        return
    
    print("\n✅ Geographic Analysis Complete!")
    print("=" * 80)
    
    # Display results
    print(f"\n📊 Summary:")
    print(f"   Total unique IPs analyzed: {geo_results.get('total_unique_ips', 0):,}")
    print(f"   Countries detected: {geo_results.get('countries_detected', 0)}")
    print(f"   API lookups performed: {geo_results.get('api_lookups_performed', 0):,}")
    print(f"   Cache hits: {geo_results.get('cache_hits', 0):,}")
    
    cache_hit_rate = 0
    if geo_results.get('total_unique_ips', 0) > 0:
        cache_hit_rate = (geo_results.get('cache_hits', 0) / geo_results.get('total_unique_ips', 1)) * 100
    print(f"   Cache hit rate: {cache_hit_rate:.1f}%")
    
    # Top source countries
    if geo_results.get('top_source_countries'):
        print(f"\n🌍 Top 10 Source Countries:")
        print("=" * 80)
        
        for i, country in enumerate(geo_results['top_source_countries'][:10], 1):
            print(f"\n{i}. {country['country_name']} ({country['country_code']})")
            print(f"   Blocked connections: {country['blocked_connections']:,} ({country['percentage']:.1f}%)")
            print(f"   Unique IPs: {country['unique_ips']}")
            
            if country.get('sample_ips'):
                print(f"   Sample IPs: {', '.join(country['sample_ips'][:5])}")
            
            if country.get('top_ports'):
                ports_str = ', '.join([f"{p['port']} ({p['count']})" for p in country['top_ports'][:3]])
                print(f"   Top ports: {ports_str}")
    
    # High-risk countries
    if geo_results.get('high_risk_countries'):
        print(f"\n⚠️  High-Risk Countries (>100 blocked connections):")
        print("=" * 80)
        
        for country in geo_results['high_risk_countries'][:5]:
            print(f"   🔴 {country['country_name']}: {country['blocked_connections']:,} blocks from {country['unique_ips']} IPs")
    
    # Unknown/Private IPs
    if geo_results.get('unknown_ips', 0) > 0:
        print(f"\n⚠️  Unknown/Private IPs: {geo_results['unknown_ips']:,}")
    
    print("\n" + "=" * 80)
    print("✅ Geographic Analysis Test Complete!")
    print("=" * 80)
    
    # Show cache efficiency message
    if geo_results.get('api_lookups_performed', 0) > 0:
        print(f"\n💡 First run: Performed {geo_results['api_lookups_performed']:,} API lookups")
        print("   Next run will use cached data (7-day validity)")
    else:
        print("\n💡 All data served from cache - no API calls needed!")

if __name__ == '__main__':
    test_geographic_analysis()

