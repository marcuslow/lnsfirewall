import requests
r = requests.get('http://localhost:8000/clients')
clients = r.json().get('clients', {})
print(f'Connected clients: {len(clients)}')
for k, v in clients.items():
    print(f'  {v.get("client_name")}: {k}')

