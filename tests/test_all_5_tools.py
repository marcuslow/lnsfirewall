#!/usr/bin/env python3
"""
Test all 5 security analysis tools with real data
"""
import asyncio
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'hq'))

from ai_command_center import AICommandCenter
from dotenv import load_dotenv

async def test_all_tools():
    print("=" * 80)
    print("🔥 TESTING ALL 5 SECURITY ANALYSIS TOOLS 🔥")
    print("=" * 80)
    
    # Load environment variables
    load_dotenv()
    
    # Create AI Command Center instance (without OpenAI for direct testing)
    class DirectTestCenter(AICommandCenter):
        def __init__(self):
            self.db_path = "hq_database.db"
            self.hq_url = "http://localhost:8000"
            self.last_logs_request_days = {}
            self.ipinfo_token = os.getenv('IPINFO_TOKEN')
            self.abuseipdb_key = os.getenv('ABUSEIPDB_KEY')
            self.ipinfo_max_lookups = int(os.getenv('IPINFO_MAX_LOOKUPS', '10'))
            self.abuseipdb_max_lookups = int(os.getenv('ABUSEIPDB_MAX_LOOKUPS', '10'))
            self.geoip2_db_path = os.getenv('GEOIP2_DB_PATH')
    
    ai_center = DirectTestCenter()
    
    # Use the real client ID from the database
    client_id = "8cbb62eecbb00579"  # opus-1
    days = 7
    top_n = 10
    
    print(f"\n📊 Testing with client: {client_id} (opus-1)")
    print(f"📅 Analysis period: {days} days")
    print(f"🔢 Top N results: {top_n}")
    print("=" * 80)
    
    # ========================================================================
    # TOOL 1: High-Volume Traffic Anomaly Detector
    # ========================================================================
    print("\n" + "=" * 80)
    print("🔍 TOOL 1: High-Volume Traffic Anomaly Detector")
    print("=" * 80)
    
    try:
        result = await ai_center.query_logs(client_id, "summary", days=days, top_n=top_n)
        if result['success']:
            summary = result['results']
            print(f"✅ Total entries analyzed: {summary.get('total', 0)}")
            print(f"\n📈 Top Blocked Sources:")
            for item in summary.get('top_blocked_sources', [])[:5]:
                print(f"   {item['value']}: {item['count']} blocks")
            print(f"\n🎯 Top Targeted Ports:")
            for item in summary.get('top_destination_ports', [])[:5]:
                print(f"   Port {item['value']}: {item['count']} hits")
            print(f"\n🌐 Top Protocols:")
            for item in summary.get('top_protocols', [])[:5]:
                print(f"   {item['value']}: {item['count']} packets")
        else:
            print(f"❌ Error: {result.get('error', 'Unknown error')}")
    except Exception as e:
        print(f"❌ Exception: {e}")
    
    # ========================================================================
    # TOOL 2: Port Scanning & Network Reconnaissance Detector
    # ========================================================================
    print("\n" + "=" * 80)
    print("🔍 TOOL 2: Port Scanning & Network Reconnaissance Detector")
    print("=" * 80)
    
    try:
        result = await ai_center.query_logs(client_id, "scan", days=days, top_n=top_n)
        if result['success']:
            scanning = result['results'].get('scanning_activity', {})
            print(f"✅ Total vertical scans detected: {scanning.get('total_vertical_scans', 0)}")
            print(f"✅ Total horizontal scans detected: {scanning.get('total_horizontal_scans', 0)}")
            
            if scanning.get('vertical_scans'):
                print(f"\n🔺 Top Vertical Scans (one IP → many ports on one target):")
                for scan in scanning['vertical_scans'][:3]:
                    print(f"   {scan['source_ip']} → {scan['destination_ip']}")
                    print(f"      Ports scanned: {scan['unique_ports_scanned']}")
                    print(f"      Total attempts: {scan['total_scan_attempts']}")
            
            if scanning.get('horizontal_scans'):
                print(f"\n🔻 Top Horizontal Scans (one IP → one port on many targets):")
                for scan in scanning['horizontal_scans'][:3]:
                    print(f"   {scan['source_ip']} → port {scan['destination_port']}")
                    print(f"      Hosts swept: {scan['unique_hosts_swept']}")
                    print(f"      Total attempts: {scan['total_sweep_attempts']}")
        else:
            print(f"❌ Error: {result.get('error', 'Unknown error')}")
    except Exception as e:
        print(f"❌ Exception: {e}")
    
    # ========================================================================
    # TOOL 3: Geographic Threat Mapper
    # ========================================================================
    print("\n" + "=" * 80)
    print("🔍 TOOL 3: Geographic Threat Mapper")
    print("=" * 80)
    
    if ai_center.ipinfo_token:
        print(f"✅ IPINFO_TOKEN found: {ai_center.ipinfo_token[:10]}...")
        try:
            result = await ai_center.query_logs(client_id, "geographic", days=days, top_n=top_n)
            if result['success']:
                geo = result['results'].get('geographic_analysis', {})
                if geo.get('success'):
                    print(f"✅ Total unique IPs analyzed: {geo.get('total_unique_ips', 0)}")
                    print(f"✅ Countries detected: {geo.get('countries_detected', 0)}")
                    print(f"✅ API lookups performed: {geo.get('api_lookups_performed', 0)}")
                    print(f"✅ Cache hits: {geo.get('cache_hits', 0)}")
                    
                    if geo.get('top_source_countries'):
                        print(f"\n🌍 Top Source Countries:")
                        for country in geo['top_source_countries'][:5]:
                            print(f"   {country['country_name']} ({country['country_code']})")
                            print(f"      Blocked connections: {country['blocked_connections']} ({country['percentage']:.1f}%)")
                            if country.get('sample_ips'):
                                print(f"      Sample IPs: {', '.join(country['sample_ips'][:3])}")
                else:
                    print(f"⚠️ Geographic analysis failed: {geo.get('error', 'Unknown error')}")
            else:
                print(f"❌ Error: {result.get('error', 'Unknown error')}")
        except Exception as e:
            print(f"❌ Exception: {e}")
    else:
        print("⚠️ IPINFO_TOKEN not set - skipping geographic analysis")
        print("   Set IPINFO_TOKEN in .env to enable this feature")
    
    # ========================================================================
    # TOOL 4: Threat Intelligence Correlation Engine
    # ========================================================================
    print("\n" + "=" * 80)
    print("🔍 TOOL 4: Threat Intelligence Correlation Engine")
    print("=" * 80)
    
    if ai_center.abuseipdb_key:
        print(f"✅ ABUSEIPDB_KEY found: {ai_center.abuseipdb_key[:10]}...")
        try:
            result = await ai_center.query_logs(client_id, "threat intelligence", days=days, top_n=top_n)
            if result['success']:
                threat = result['results'].get('threat_intelligence', {})
                if threat.get('success'):
                    print(f"✅ Total unique IPs analyzed: {threat.get('total_unique_ips_analyzed', 0)}")
                    print(f"✅ Total IPs checked: {threat.get('total_ips_checked', 0)}")
                    print(f"✅ Malicious IPs detected: {threat.get('malicious_ips_detected', 0)}")
                    print(f"✅ API lookups performed: {threat.get('api_lookups_performed', 0)}")
                    print(f"✅ Cache hits: {threat.get('cache_hits', 0)}")
                    if threat.get('ips_skipped_due_to_limit', 0) > 0:
                        print(f"⚠️  IPs skipped (API limit): {threat.get('ips_skipped_due_to_limit', 0)}")

                    if threat.get('threat_findings'):
                        print(f"\n⚠️ Threat Intelligence Findings:")
                        for finding in threat['threat_findings'][:5]:
                            print(f"   {finding['ip']} - Confidence: {finding['abuse_confidence_score']}%")
                            print(f"      Total reports: {finding['total_reports']}")
                            print(f"      Blocked connections: {finding['blocked_connections']}")
                            print(f"      Country: {finding['country_code']}")
                            print(f"      ISP: {finding['isp']}")
                            if finding.get('is_tor'):
                                print(f"      ⚠️ TOR EXIT NODE")
                            print(f"      Report: {finding['report_url']}")
                    else:
                        print(f"\n✅ No malicious IPs detected in top 10 most frequent attackers")
                elif threat.get('rate_limited'):
                    print(f"⚠️ RATE LIMIT EXCEEDED - Skipping threat intelligence analysis")
                    print(f"   {threat.get('error', 'Daily quota reached')}")
                    print(f"   IPs checked before limit: {threat.get('ips_checked_before_limit', 0)}")
                    print(f"   Cached results available: {threat.get('cached_results', 0)}")
                    print(f"   💡 Try again tomorrow when quota resets")
                else:
                    print(f"⚠️ Threat intelligence failed: {threat.get('error', 'Unknown error')}")
            else:
                print(f"❌ Error: {result.get('error', 'Unknown error')}")
        except Exception as e:
            print(f"❌ Exception: {e}")
    else:
        print("⚠️ ABUSEIPDB_KEY not set - skipping threat intelligence")
        print("   Set ABUSEIPDB_KEY in .env to enable this feature")
    
    # ========================================================================
    # TOOL 5: Outbound Connection Anomaly Monitor
    # ========================================================================
    print("\n" + "=" * 80)
    print("🔍 TOOL 5: Outbound Connection Anomaly Monitor")
    print("=" * 80)
    
    try:
        result = await ai_center.query_logs(client_id, "outbound", days=days, top_n=top_n)
        if result['success']:
            outbound = result['results'].get('outbound_analysis', {})
            if outbound.get('success'):
                print(f"✅ Total allowed connections: {outbound.get('total_allowed_connections', 0)}")
                print(f"✅ Total outbound connections: {outbound.get('total_outbound_connections', 0)}")
                print(f"✅ Suspicious outbound connections: {outbound.get('suspicious_outbound_connections', 0)}")
                print(f"✅ Unique internal hosts affected: {outbound.get('unique_internal_hosts_affected', 0)}")
                
                if outbound.get('suspicious_connections'):
                    print(f"\n🚨 Suspicious Outbound Connections:")
                    for conn in outbound['suspicious_connections'][:5]:
                        print(f"   {conn['source_ip']} → {conn['destination_ip']}:{conn['destination_port']}")
                        print(f"      Protocol: {conn['protocol']}")
                        print(f"      Connections: {conn['connection_count']}")
                        print(f"      First seen: {conn['first_seen']}")
                        print(f"      Last seen: {conn['last_seen']}")
                else:
                    print(f"\n✅ No suspicious outbound connections detected")
            else:
                print(f"⚠️ Outbound analysis failed: {outbound.get('error', 'Unknown error')}")
        else:
            print(f"❌ Error: {result.get('error', 'Unknown error')}")
    except Exception as e:
        print(f"❌ Exception: {e}")
    
    # ========================================================================
    # COMPREHENSIVE RISK ASSESSMENT (All Tools Combined)
    # ========================================================================
    print("\n" + "=" * 80)
    print("🔥 COMPREHENSIVE RISK ASSESSMENT (All Tools Combined)")
    print("=" * 80)
    
    try:
        result = await ai_center.query_logs(client_id, "risk assessment", days=days, top_n=top_n)
        if result['success']:
            assessment = result['results']
            print(f"\n🎯 RISK LEVEL: {assessment.get('risk_level', 'Unknown')}")
            print(f"\n📊 Summary:")
            print(f"   Blocked events: {assessment.get('blocked_events', {}).get('count', 0)}")
            print(f"   Allowed events: {assessment.get('allowed_events', {}).get('count', 0)}")
            print(f"   Brute force attempts: {assessment.get('potential_brute_force', {}).get('count', 0)}")
            
            scanning = assessment.get('scanning_activity', {})
            print(f"   Vertical scans: {scanning.get('total_vertical_scans', 0)}")
            print(f"   Horizontal scans: {scanning.get('total_horizontal_scans', 0)}")
            
            if assessment.get('geographic_analysis'):
                geo = assessment['geographic_analysis']
                if geo.get('success'):
                    print(f"   Countries detected: {geo.get('countries_detected', 0)}")
            
            if assessment.get('threat_intelligence'):
                threat = assessment['threat_intelligence']
                if threat.get('success'):
                    print(f"   Malicious IPs detected: {threat.get('malicious_ips_detected', 0)}")
            
            if assessment.get('outbound_analysis'):
                outbound = assessment['outbound_analysis']
                if outbound.get('success'):
                    print(f"   Suspicious outbound hosts: {outbound.get('unique_internal_hosts_affected', 0)}")
            
            if assessment.get('recommendations'):
                print(f"\n💡 Recommendations:")
                for rec in assessment['recommendations'][:10]:
                    print(f"   • {rec}")
        else:
            print(f"❌ Error: {result.get('error', 'Unknown error')}")
    except Exception as e:
        print(f"❌ Exception: {e}")
    
    print("\n" + "=" * 80)
    print("✅ ALL TESTS COMPLETE!")
    print("=" * 80)

if __name__ == '__main__':
    asyncio.run(test_all_tools())

