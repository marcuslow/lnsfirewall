#!/usr/bin/env python3

import requests

try:
    response = requests.get('http://localhost:8000/clients', timeout=10)
    print('✅ Server is running!')
    clients = response.json().get('clients', {})
    print(f'Connected clients: {len(clients)}')
    for cid, info in clients.items():
        print(f'  ID: {cid}, Name: {info.get("client_name", "unknown")}')
except Exception as e:
    print(f'❌ Server not accessible: {e}')
