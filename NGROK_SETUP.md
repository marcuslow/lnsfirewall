# 🌐 ngrok Setup Guide for pfSense Firewall Management

Your public server URL: **https://lnsfirewall.ngrok.app/**

## 🚀 Quick Start

### 1. Start Your HQ Server
```bash
# In your project directory
cd hq
python -m uvicorn hq.http_server:app --host 0.0.0.0 --port 8000
```

### 2. Set up ngrok Tunnel
```bash
# In another terminal
ngrok http 8000 --domain=lnsfirewall.ngrok.app
```

### 3. Start AI Command Center
```bash
# In another terminal
cd hq
python3 ai_command_center.py
```

## 📱 pfSense Client Setup

### Configuration is Ready!
The client configuration is already set to connect to your ngrok URL:
- **HTTP(S) URL)**: `https://lnsfirewall.ngrok.app`
- **SSL**: Handled by ngrok automatically

### Deploy to pfSense Firewalls:

1. **Copy files to each pfSense firewall**:
   ```bash
   scp client/pfsense_client.py root@your-pfsense-ip:/usr/local/bin/
   scp config/client_config.yaml root@your-pfsense-ip:/usr/local/etc/pfsense_client.yaml
   ```

2. **Edit client name on each firewall**:
   ```bash
   # SSH to each pfSense firewall
   ssh root@your-pfsense-ip

   # Edit the config to set unique client name
   vi /usr/local/etc/pfsense_client.yaml

   # Change this line for each firewall:
   client_name: "opus-1"        # For first firewall
   client_name: "james-office"  # For second firewall
   client_name: "central-lion"  # For third firewall
   ```

3. **Install dependencies and run**:
   ```bash
   # On each pfSense firewall
   pkg install -y python39 py39-pip
   pip install websockets pyyaml psutil

   # Test the client
   python3 /usr/local/bin/pfsense_client.py
   ```

## 🎯 Testing Your Setup

### Check Server Logs
Your HQ server should show:
```
INFO - Starting HQ server on 0.0.0.0:8000
INFO - WebSocket endpoint will be available at /ws
INFO - HQ server started successfully
INFO - Clients should connect to: wss://lnsfirewall.ngrok.app/ws
```

### Check Client Connection
When a pfSense client connects, you'll see:
```
INFO - New WebSocket connection from xxx.xxx.xxx.xxx on path: /ws
INFO - Client registered: abc123 (opus-1) - pfsense-main
```

### Test AI Commands
```
🤖 AI Assistant: status of opus-1, james-office, central-lion
🤖 AI Assistant: get logs from all clients for the last 24 hours
🤖 AI Assistant: what are the top source IPs trying to connect to opus-1?
```

## 🔧 Troubleshooting

### Client Can't Connect
1. **Check ngrok tunnel is running**: Visit https://lnsfirewall.ngrok.app/ in browser
2. **Verify WebSocket path**: Should be `wss://lnsfirewall.ngrok.app/ws`
3. **Check pfSense internet access**: Ensure firewall can reach external HTTPS
4. **SSL Certificate**: ngrok handles SSL automatically

### Server Issues
1. **Port conflicts**: Make sure port 8000 is free
2. **ngrok domain**: Ensure you're using the correct domain
3. **Firewall rules**: Check local firewall allows port 8000

### Client Names
1. **Unique names**: Each pfSense client must have a unique `client_name`
2. **Name format**: Use simple names like "opus-1", "branch-2", avoid spaces
3. **Case sensitive**: "Opus-1" and "opus-1" are different

## 📊 Monitoring

### View Connected Clients
```
🤖 AI Assistant: show me all connected clients
```

### Check Logs
- **HQ Server**: Check terminal output or `hq/hq_server.log`
- **pfSense Clients**: Check `/var/log/pfsense_client.log` on each firewall

## 🔒 Security Notes

- **ngrok SSL**: All traffic is encrypted via ngrok's SSL
- **Authentication**: Consider adding API keys for production
- **Access Control**: ngrok provides basic access controls
- **Monitoring**: Monitor connection logs for unauthorized access

## 🎉 You're Ready!

Once everything is running, you can manage all your pfSense firewalls from anywhere using natural language commands through the AI interface!