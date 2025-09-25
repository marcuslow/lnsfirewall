import json
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'hq'))
from lqe import LogQueryEngine

# Synthetic sample entries (since DB may have none yet)
SAMPLE = [
    {"timestamp": "2025-09-25T12:00:00", "action": "pass", "proto": "tcp", "src": "1.2.3.4", "src_port": 55555, "dst": "192.168.1.10", "dst_port": 22},
    {"timestamp": "2025-09-25T12:00:05", "action": "block", "proto": "udp", "src": "9.9.9.9", "src_port": 12345, "dst": "192.168.1.255", "dst_port": 53},
    {"timestamp": "2025-09-25T12:01:00", "action": "pass", "proto": "tcp", "src": "1.2.3.4", "src_port": 55556, "dst": "192.168.1.20", "dst_port": 80},
    {"timestamp": "2025-09-25T12:02:00", "action": "reject", "proto": "tcp", "src": "4.3.2.1", "src_port": 40000, "dst": "192.168.1.20", "dst_port": 443},
]

def main():
    lqe = LogQueryEngine(SAMPLE)
    print('Summary:', json.dumps(lqe.summarize(), indent=2))
    print('\nBlocked count:', len(lqe.filter_blocked()))
    print('\nPort 22:', len(lqe.filter_by_port(22)))
    print('\nHTTPS entries:', len(lqe.filter_by_service('https')))
    print('\nIP 192.168.1.20 entries:', len(lqe.filter_by_ip_fragment('192.168.1.20')))

if __name__ == '__main__':
    main()

