"""
Offline smoke tests for Rules Query Engine (RQE)
- Runs against the local SQLite DB and uses the latest cached rules
- No network or client connection required

Run:
  python tests/rqe_smoke.py
"""
import asyncio
import json
import os
import sys
from typing import Optional, Tuple

# Make 'hq' module importable without package install
THIS_DIR = os.path.dirname(__file__)
HQ_DIR = os.path.abspath(os.path.join(THIS_DIR, '..', 'hq'))
sys.path.insert(0, HQ_DIR)

from rqe import RulesQueryEngine
import aiosqlite

DB_PATH = 'hq_database.db'
TARGET_CLIENT = 'opus-1'  # name or id


async def load_latest_rules_for_client(db_path: str, client_id_or_name: str) -> Optional[Tuple[str, str]]:
    return await RulesQueryEngine.load_latest_rules_xml(db_path, client_id_or_name)


async def main():
    data = await load_latest_rules_for_client(DB_PATH, TARGET_CLIENT)
    if not data:
        print('No cached rules found for client; run the system once to ingest rules.')
        return
    rules_xml, ruleset_id = data
    print(f'Loaded ruleset {ruleset_id} for {TARGET_CLIENT}, size={len(rules_xml)} bytes')

    rqe = RulesQueryEngine(rules_xml)
    print('Summary:', rqe.summarize())

    # 1) Port forwarding rules
    pf = [rqe._nat_to_dict(n) for n in rqe.list_port_forwarding()]
    print('\nPort forwarding rules:', json.dumps(pf[:5], indent=2))

    # 2) SSH rules
    ssh = rqe.find_rules_by_service('ssh')
    print('\nSSH rules:', json.dumps(ssh, indent=2))

    # 3) Port 80
    p80 = rqe.find_rules_by_port(80)
    print('\nPort 80 rules:', json.dumps(p80, indent=2))

    # 4) HTTPS
    https = rqe.find_rules_by_service('https')
    print('\nHTTPS rules:', json.dumps(https, indent=2))

    # 5) Blocking rules
    blocking = rqe.find_blocking_rules()
    print('\nBlocking rules:', json.dumps(blocking[:5], indent=2))

    # 6) Rules with IP addresses (search for LAN fragment)
    ip_matches = rqe.find_rules_with_ip('192.168.')
    print('\nRules with 192.168.*:', json.dumps(ip_matches[:5], indent=2))

    # 7) Allowed rules
    allowed = rqe.find_allowed_rules()
    print(f'\nAllowed rules count: {len(allowed)}')
    print('First 3 allowed rules:', json.dumps(allowed[:3], indent=2))


if __name__ == '__main__':
    asyncio.run(main())

