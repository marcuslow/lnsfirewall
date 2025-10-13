#!/usr/bin/env python3
"""
Test query_logs function directly for scanning detection
"""
import asyncio
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from hq.ai_command_center import AICommandCenter

async def test_query_logs_direct():
    print("=" * 60)
    print("DIRECT QUERY_LOGS TEST")
    print("=" * 60)
    
    ai_center = AICommandCenter(
        hq_url="http://localhost:8000",
        openai_api_key="test-key"  # Not used for query_logs
    )
    
    test_queries = [
        "scanning",
        "port scan", 
        "port scanning activity",
        "geographic",
        "countries",
        "threat intelligence",
        "outbound anomaly",
        "top blocked IPs"
    ]
    
    for query in test_queries:
        print(f"\n🔍 Testing query: '{query}'")
        try:
            result = await ai_center.query_logs("opus-1", query, days=7, top_n=5)
            
            if result.get('success'):
                print(f"✅ Success!")
                
                # Check what type of analysis was performed
                if 'analysis_type' in result:
                    print(f"   Analysis type: {result['analysis_type']}")
                
                if 'scanning_activity' in result:
                    scanning = result['scanning_activity']
                    print(f"   Scanning results: {scanning}")
                
                if 'geographic_analysis' in result:
                    geo = result['geographic_analysis']
                    print(f"   Geographic results: {geo.get('success', False)}")
                
                if 'threat_intel_analysis' in result:
                    threat = result['threat_intel_analysis']
                    print(f"   Threat intel results: {threat.get('success', False)}")
                
                if 'outbound_analysis' in result:
                    outbound = result['outbound_analysis']
                    print(f"   Outbound analysis: {outbound}")
                
                if 'top_blocked_ips' in result:
                    top_ips = result['top_blocked_ips']
                    print(f"   Top blocked IPs: {len(top_ips) if isinstance(top_ips, list) else 'N/A'}")
                    
            else:
                print(f"❌ Failed: {result.get('error', 'Unknown error')}")
                
        except Exception as e:
            print(f"❌ Exception: {e}")

if __name__ == "__main__":
    asyncio.run(test_query_logs_direct())
