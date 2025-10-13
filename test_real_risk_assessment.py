#!/usr/bin/env python3
"""
Test risk assessment with real data
"""
import asyncio
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'hq'))

from ai_command_center import AICommandCenter

async def test_real_risk_assessment():
    print("=== Testing Risk Assessment with Real Data ===")
    
    # Create AI Command Center instance (without OpenAI for testing)
    class MockAICenter(AICommandCenter):
        def __init__(self):
            self.db_path = "hq_database.db"
            self.hq_url = "http://localhost:8000"
            self.last_logs_request_days = {}
    
    ai_center = MockAICenter()
    
    # Test basic blocked query
    print("\n1. Testing blocked connections query...")
    result = await ai_center.query_logs("8cbb62eecbb00579", "blocked", days=7, top_n=10)
    if result['success']:
        blocked_count = result['results']['blocked_count']
        print(f"✅ Blocked connections: {blocked_count}")
        examples = result['results']['examples']
        print(f"✅ Sample blocked entries: {len(examples)}")
        if examples:
            print(f"   First blocked: {examples[0]['src']} -> {examples[0]['dst']}:{examples[0]['dst_port']} ({examples[0]['action']})")
    else:
        print(f"❌ Error: {result['error']}")
    
    # Test risk assessment query
    print("\n2. Testing risk assessment query...")
    result = await ai_center.query_logs("8cbb62eecbb00579", "risk assessment", days=7, top_n=10)
    if result['success']:
        results = result['results']
        print(f"✅ Risk Level: {results['risk_level']}")
        print(f"✅ Blocked events: {results['blocked_events']['count']}")
        print(f"✅ Brute force attempts: {results['potential_brute_force']['count']}")
        print(f"✅ Port scan attempts: {results['potential_port_scans']['count']}")
        
        print(f"\n   Top blocked IPs:")
        for ip, count in results['top_blocked_ips'][:5]:
            print(f"     {ip}: {count} blocks")
        
        print(f"\n   Recommendations:")
        for rec in results['recommendations']:
            print(f"     - {rec}")
    else:
        print(f"❌ Error: {result['error']}")
    
    # Test perform_risk_assessment function
    print("\n3. Testing perform_risk_assessment function...")
    result = await ai_center.perform_risk_assessment("8cbb62eecbb00579", days=7)
    if result['success']:
        assessment = result['assessment']
        print(f"✅ Risk Level: {assessment['risk_level']}")
        print(f"✅ Key Findings:")
        for finding in assessment['key_findings']:
            print(f"     - {finding}")
        print(f"✅ Recommendations:")
        for rec in assessment['recommendations']:
            print(f"     - {rec}")
    else:
        print(f"❌ Error: {result['error']}")
    
    # Test with opus-1 name mapping
    print("\n4. Testing with client name 'opus-1'...")
    result = await ai_center.query_logs("opus-1", "blocked", days=7, top_n=5)
    if result['success']:
        blocked_count = result['results']['blocked_count']
        print(f"✅ Blocked connections for opus-1: {blocked_count}")
    else:
        print(f"❌ Error: {result['error']}")

if __name__ == '__main__':
    asyncio.run(test_real_risk_assessment())
