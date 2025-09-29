#!/usr/bin/env python3
"""
Test script for AI Command Center risk assessment integration
"""
import asyncio
import json
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'hq'))

# Mock the dependencies that require external services
class MockAICommandCenter:
    def __init__(self):
        self.db_path = ":memory:"  # In-memory SQLite for testing
        self.last_logs_request_days = {}
        
    async def query_logs(self, client_id: str, query: str, days=None, top_n=None):
        """Mock query_logs method with risk assessment logic"""
        from lqe import LogQueryEngine
        
        # Use the same test data from risk_assessment_test.py
        RISK_SAMPLE = [
            # Normal traffic
            {"timestamp": "2025-09-25T12:00:00", "action": "pass", "proto": "tcp", "src": "192.168.1.100", "src_port": 55555, "dst": "192.168.1.10", "dst_port": 80},
            {"timestamp": "2025-09-25T12:00:05", "action": "pass", "proto": "tcp", "src": "192.168.1.100", "src_port": 55556, "dst": "192.168.1.10", "dst_port": 443},
            
            # Brute force attempts from 10.0.0.1 on SSH
            {"timestamp": "2025-09-25T12:01:00", "action": "block", "proto": "tcp", "src": "10.0.0.1", "src_port": 40001, "dst": "192.168.1.10", "dst_port": 22},
            {"timestamp": "2025-09-25T12:01:05", "action": "block", "proto": "tcp", "src": "10.0.0.1", "src_port": 40002, "dst": "192.168.1.10", "dst_port": 22},
            {"timestamp": "2025-09-25T12:01:10", "action": "block", "proto": "tcp", "src": "10.0.0.1", "src_port": 40003, "dst": "192.168.1.10", "dst_port": 22},
            {"timestamp": "2025-09-25T12:01:15", "action": "block", "proto": "tcp", "src": "10.0.0.1", "src_port": 40004, "dst": "192.168.1.10", "dst_port": 22},
            {"timestamp": "2025-09-25T12:01:20", "action": "block", "proto": "tcp", "src": "10.0.0.1", "src_port": 40005, "dst": "192.168.1.10", "dst_port": 22},
            {"timestamp": "2025-09-25T12:01:25", "action": "block", "proto": "tcp", "src": "10.0.0.1", "src_port": 40006, "dst": "192.168.1.10", "dst_port": 22},
            
            # Port scan from 10.0.0.2
            {"timestamp": "2025-09-25T12:02:00", "action": "block", "proto": "tcp", "src": "10.0.0.2", "src_port": 50001, "dst": "192.168.1.10", "dst_port": 21},
            {"timestamp": "2025-09-25T12:02:01", "action": "block", "proto": "tcp", "src": "10.0.0.2", "src_port": 50002, "dst": "192.168.1.10", "dst_port": 22},
            {"timestamp": "2025-09-25T12:02:02", "action": "block", "proto": "tcp", "src": "10.0.0.2", "src_port": 50003, "dst": "192.168.1.10", "dst_port": 23},
            {"timestamp": "2025-09-25T12:02:03", "action": "block", "proto": "tcp", "src": "10.0.0.2", "src_port": 50004, "dst": "192.168.1.10", "dst_port": 25},
            {"timestamp": "2025-09-25T12:02:04", "action": "block", "proto": "tcp", "src": "10.0.0.2", "src_port": 50005, "dst": "192.168.1.10", "dst_port": 53},
            {"timestamp": "2025-09-25T12:02:05", "action": "block", "proto": "tcp", "src": "10.0.0.2", "src_port": 50006, "dst": "192.168.1.10", "dst_port": 80},
            {"timestamp": "2025-09-25T12:02:06", "action": "block", "proto": "tcp", "src": "10.0.0.2", "src_port": 50007, "dst": "192.168.1.10", "dst_port": 110},
            {"timestamp": "2025-09-25T12:02:07", "action": "block", "proto": "tcp", "src": "10.0.0.2", "src_port": 50008, "dst": "192.168.1.10", "dst_port": 143},
            {"timestamp": "2025-09-25T12:02:08", "action": "block", "proto": "tcp", "src": "10.0.0.2", "src_port": 50009, "dst": "192.168.1.10", "dst_port": 443},
            {"timestamp": "2025-09-25T12:02:09", "action": "block", "proto": "tcp", "src": "10.0.0.2", "src_port": 50010, "dst": "192.168.1.10", "dst_port": 993},
            {"timestamp": "2025-09-25T12:02:10", "action": "block", "proto": "tcp", "src": "10.0.0.2", "src_port": 50011, "dst": "192.168.1.10", "dst_port": 995},
            {"timestamp": "2025-09-25T12:02:11", "action": "block", "proto": "tcp", "src": "10.0.0.2", "src_port": 50012, "dst": "192.168.1.10", "dst_port": 3389},
        ]
        
        effective_days = days or 7
        effective_top_n = top_n or 10
        
        lqe = LogQueryEngine(RISK_SAMPLE)
        
        def compact(entries):
            out = []
            for x in entries[:effective_top_n]:
                out.append({
                    'timestamp': getattr(x, 'timestamp', None),
                    'action': getattr(x, 'action', None),
                    'proto': getattr(x, 'proto', None),
                    'interface': getattr(x, 'interface', None),
                    'src': getattr(x, 'src', None),
                    'src_port': getattr(x, 'src_port', None),
                    'dst': getattr(x, 'dst', None),
                    'dst_port': getattr(x, 'dst_port', None),
                })
            return out
        
        q = (query or '').strip().lower()
        results = {}
        
        # Risk assessment logic (copied from ai_command_center.py)
        if any(k in q for k in ['risk', 'assessment', 'threat', 'security check', 'anomaly']):
            summary = lqe.summarize(top_n=effective_top_n)
            blocked = lqe.filter_blocked()
            allowed = lqe.filter_allowed()
            ssh_hits = lqe.filter_by_service('ssh')
            http_hits = lqe.filter_by_service('http')
            https_hits = lqe.filter_by_service('https')
            
            # Use enhanced LQE methods for better detection
            potential_brute = lqe.detect_brute_force(threshold=5)
            port_scans = lqe.detect_port_scans(threshold=10)
            top_blocked_ips = lqe.get_top_blocked_ips(top_n=effective_top_n)
            
            # Simple risk scoring heuristic
            blocked_count = len(blocked)
            brute_force_count = len(potential_brute)
            port_scan_count = len(port_scans)
            
            if blocked_count > 100 or brute_force_count > 10 or port_scan_count > 20:
                risk_level = 'High'
            elif blocked_count > 10 or brute_force_count > 0 or port_scan_count > 5:
                risk_level = 'Medium'
            else:
                risk_level = 'Low'
            
            # Generate recommendations
            recommendations = []
            if brute_force_count > 0:
                recommendations.append('Block top suspicious IPs if recurring')
                recommendations.append('Review rules for authentication ports (SSH, RDP)')
            if port_scan_count > 0:
                recommendations.append('Investigate potential port scanning activity')
            if blocked_count > 50:
                recommendations.append('Consider rate limiting or additional blocking rules')
            if top_blocked_ips and top_blocked_ips[0][1] > 20:
                recommendations.append(f'Investigate top blocked IP: {top_blocked_ips[0][0]} ({top_blocked_ips[0][1]} blocks)')
            
            results = {
                'risk_summary': summary,
                'blocked_events': {'count': len(blocked), 'examples': compact(blocked)},
                'allowed_events': {'count': len(allowed), 'examples': compact(allowed)},
                'potential_brute_force': {'count': brute_force_count, 'examples': compact(potential_brute)},
                'potential_port_scans': {'count': port_scan_count, 'examples': compact(port_scans)},
                'web_traffic': {'http_count': len(http_hits), 'https_count': len(https_hits)},
                'top_blocked_ips': top_blocked_ips,
                'risk_level': risk_level,
                'recommendations': recommendations,
                'analysis_period_days': effective_days
            }
        else:
            results = {'summary': lqe.summarize(top_n=effective_top_n)}
        
        return {
            'success': True,
            'query': query,
            'days': effective_days,
            'client_id': client_id,
            'results': results
        }

async def test_risk_assessment():
    print("=== AI Command Center Risk Assessment Integration Test ===")
    
    ai_center = MockAICommandCenter()
    
    # Test risk assessment query
    result = await ai_center.query_logs("test-client", "risk assessment", days=7, top_n=5)
    
    print(f"\nQuery successful: {result['success']}")
    print(f"Client ID: {result['client_id']}")
    print(f"Analysis period: {result['days']} days")
    
    results = result['results']
    print(f"\nRisk Level: {results['risk_level']}")
    print(f"Blocked events: {results['blocked_events']['count']}")
    print(f"Brute force attempts: {results['potential_brute_force']['count']}")
    print(f"Port scan attempts: {results['potential_port_scans']['count']}")
    
    print(f"\nTop blocked IPs:")
    for ip, count in results['top_blocked_ips'][:3]:
        print(f"  {ip}: {count} blocks")
    
    print(f"\nRecommendations:")
    for rec in results['recommendations']:
        print(f"  - {rec}")
    
    print(f"\nRisk Summary:")
    summary = results['risk_summary']
    print(f"  Total entries: {summary['total_entries']}")
    print(f"  Blocked: {summary['blocked_count']}")
    print(f"  Allowed: {summary['allowed_count']}")
    
    print("\n✅ Risk assessment integration test completed successfully!")

if __name__ == '__main__':
    asyncio.run(test_risk_assessment())
