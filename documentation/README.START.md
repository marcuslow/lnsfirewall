# 🚀 LNS Firewall Management System - Quick Start Guide

Welcome! This guide will help you set up and run the pfSense Firewall Management System with AI-powered command center.

## 📋 Table of Contents

1. [Prerequisites](#prerequisites)
2. [Installation Steps](#installation-steps)
3. [Configuration](#configuration)
4. [Starting the System](#starting-the-system)
5. [Deploying to pfSense Clients](#deploying-to-pfsense-clients)
6. [Using the AI Console](#using-the-ai-console)
7. [Troubleshooting](#troubleshooting)

---

## 🔧 Prerequisites

Before you begin, ensure you have the following installed:

### Required Software

1. **Python 3.8 or higher**
   - Windows: Download from [python.org](https://www.python.org/downloads/)
   - Check version: `python --version`

2. **PostgreSQL 12 or higher**
   - Windows: Download from [postgresql.org](https://www.postgresql.org/download/windows/)
   - During installation, remember your postgres password!
   - Default port: 5432

3. **OpenAI API Key**
   - Sign up at [platform.openai.com](https://platform.openai.com/)
   - Create an API key from your account dashboard
   - You'll need this for the AI features

### Optional Software

4. **ngrok** (for remote access to HQ server)
   - Download from [ngrok.com](https://ngrok.com/download)
   - Sign up for free account to get auth token
   - Needed if pfSense boxes are not on the same network

---

## 📦 Installation Steps

### Step 1: Extract the Package

Extract the ZIP file to a location on your computer, for example:
```
C:\Users\YourName\lnsfirewall\
```

### Step 2: Install Python Dependencies

Open Command Prompt or PowerShell in the extracted folder and run:

```bash
pip install -r requirements.txt
```

This will install all required Python packages (FastAPI, OpenAI, PostgreSQL drivers, etc.)

### Step 3: Set Up PostgreSQL Database

Run the database setup script:

```bash
python setup_postgres_db.py
```

This script will:
- Connect to your PostgreSQL server
- Create the `lnsfirewall` database
- Create all required tables (clients, logs, rules, commands)
- Set up indexes for performance

**Note:** If you changed the default PostgreSQL password during installation, you'll need to update it in the `.env` file (next step).

---

## ⚙️ Configuration

### Step 1: Create .env File

Copy the example file and edit it:

```bash
# Windows
copy .env.example .env

# Then edit .env with your favorite text editor
notepad .env
```

### Step 2: Configure .env File

Edit `.env` and add your credentials:

```env
# OpenAI API Key (REQUIRED - get from platform.openai.com)
OPENAI_API_KEY=sk-proj-your-actual-openai-api-key-here

# Database Configuration
DB_TYPE=postgres
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_DB=lnsfirewall
POSTGRES_USER=postgres
POSTGRES_PASSWORD=your-postgres-password-here

# Optional: Geographic analysis (ipinfo.io - 50k requests/month free)
# Sign up at https://ipinfo.io/signup
IPINFO_TOKEN=your_ipinfo_token_here

# Optional: Threat intelligence (AbuseIPDB - 1k requests/day free)
# Sign up at https://www.abuseipdb.com/register
ABUSEIPDB_KEY=your_abuseipdb_key_here
```

**Important:** Replace the placeholder values with your actual credentials!

### Step 3: Configure ngrok (Optional - for remote access)

If your pfSense boxes are remote (not on local network), set up ngrok:

1. Sign up at [ngrok.com](https://ngrok.com/)
2. Get your auth token from the dashboard
3. Edit `ngrok.yml` and add your auth token:

```yaml
version: "2"
authtoken: your_ngrok_auth_token_here
tunnels:
  lnsfirewall:
    proto: http
    addr: 8000
    domain: lnsfirewall.ngrok.app  # Or your custom domain
```

---

## 🚀 Starting the System

### Step 1: Start the HQ Server

Double-click `start_hq_server.bat` or run from command line:

```bash
start_hq_server.bat
```

This will:
1. Clean up any existing processes
2. Start ngrok tunnel (if configured)
3. Start the HQ HTTP/WebSocket server on port 8000

You should see output like:
```
✅ Starting ngrok tunnel...
🌐 Public URL: https://lnsfirewall.ngrok.app/
✅ Starting HQ HTTP/WebSocket Server on localhost:8000...
🔌 WebSocket endpoint: wss://lnsfirewall.ngrok.app/ws
```

**Keep this window open!** The server is running.

### Step 2: Verify Server is Running

Open a browser and go to:
- Local: http://localhost:8000/status
- Public: https://lnsfirewall.ngrok.app/status

You should see a JSON response with server status.

### Step 3: Start the AI Console (Optional)

Open a **new** Command Prompt/PowerShell window and run:

```bash
python hq/ai_command_center.py
```

You should see:
```
🔥 AI Firewall Command Center Started 🔥
Type 'help' for available commands, 'quit' to exit
--------------------------------------------------

🤖 AI Assistant:
```

Now you can interact with the AI to manage your firewalls!

---

## 📡 Deploying to pfSense Clients

### Step 1: Run the Distribution Script

```bash
python distribute.py
```

### Step 2: Enter Connection Details

The script will prompt you for:

```
Enter pfSense IP address: 103.26.150.122
Enter SSH username (default: root): root

Target: root@103.26.150.122

Note: You will be prompted for the SSH password 3 times
```

### Step 3: Enter Password

You'll be prompted for the SSH password 3 times:
1. When uploading the client bundle
2. When uploading the deployment script
3. When executing the deployment

### Step 4: Verify Deployment

The script will:
1. Create a client bundle (ZIP with all client files)
2. Upload to pfSense at `/tmp/pfsense-client-update.zip`
3. Upload deployment script to `/tmp/deploy_remote.sh`
4. Execute the deployment (stops old client, extracts new files, starts new client)

You should see:
```
✅ Files uploaded successfully
🔧 Executing deployment script...
✅ Deployment completed successfully!
```

### Step 5: Monitor Client Connection

Check the HQ server window - you should see the client connect:

```
INFO: WebSocket client connected: opus-1
INFO: Client opus-1 registered successfully
```

Or check via browser:
- http://localhost:8000/clients
- https://lnsfirewall.ngrok.app/clients

---

## 🤖 Using the AI Console

Once the AI console is running, you can ask questions in natural language:

### Example Commands

```
🤖 AI Assistant: show me all connected clients

🤖 AI Assistant: get firewall rules for opus-1

🤖 AI Assistant: show me blocked traffic from the last 7 days

🤖 AI Assistant: run a security assessment for opus-1

🤖 AI Assistant: what's the top blocked IP addresses?

🤖 AI Assistant: show me port scanning attempts
```

### Special Commands

- `help` - Show available commands
- `clear` - Clear conversation history
- `quit` or `exit` - Exit the AI console

### AI Console Options

Run with verbose mode to see debug information:

```bash
python hq/ai_command_center.py --verbose
```

---

## 🔍 Troubleshooting

### Server won't start

**Problem:** Port 8000 already in use

**Solution:** Kill existing process:
```bash
# Windows
netstat -ano | findstr :8000
taskkill /F /PID <PID_NUMBER>
```

### Database connection error

**Problem:** `psycopg2.OperationalError: could not connect to server`

**Solution:** 
1. Check PostgreSQL is running (Windows Services)
2. Verify password in `.env` matches PostgreSQL password
3. Check PostgreSQL is listening on port 5432

### OpenAI API errors

**Problem:** `AuthenticationError: Invalid API key`

**Solution:**
1. Verify your API key in `.env` is correct
2. Check you have credits in your OpenAI account
3. Make sure there are no extra spaces in the `.env` file

### Client won't connect

**Problem:** pfSense client can't reach HQ server

**Solution:**
1. Check ngrok is running (if using remote access)
2. Verify the WebSocket URL in client logs: `/var/log/pfsense_client.log`
3. Check firewall rules allow outbound HTTPS (port 443)
4. Verify the client has internet access

### Distribution script fails

**Problem:** SSH/SCP password prompts fail

**Solution:**
1. Verify SSH is enabled on pfSense (System > Advanced > Secure Shell)
2. Check the IP address is correct
3. Verify the username (usually `root` for pfSense)
4. Make sure you can manually SSH: `ssh root@<IP>`

---

## 📚 Additional Resources

### File Structure

```
lnsfirewall/
├── hq/                          # HQ Server code
│   ├── http_server.py           # Main server
│   ├── ai_command_center.py     # AI console
│   ├── db_config.py             # Database config
│   ├── lqe.py                   # Log Query Engine
│   └── rqe.py                   # Rules Query Engine
├── client/                      # pfSense client code
│   └── pfsense_client.py        # Client agent
├── config/                      # Configuration templates
├── dist/                        # Pre-built client bundles
├── .env                         # Your credentials (DO NOT SHARE!)
├── requirements.txt             # Python dependencies
├── distribute.py                # Client deployment script
└── start_hq_server.bat          # Server startup script
```

### Useful Commands

**Check server status:**
```bash
curl http://localhost:8000/status
```

**Check connected clients:**
```bash
curl http://localhost:8000/clients
```

**View server logs:**
- Check the HQ server window for real-time logs
- Logs are also in `hq_server.log`

**View client logs (on pfSense):**
```bash
ssh root@<PFSENSE_IP>
tail -f /var/log/pfsense_client.log
```

**Restart client (on pfSense):**
```bash
ssh root@<PFSENSE_IP>
/root/restart_client.sh
```

---

## 🎯 Next Steps

1. ✅ Start the HQ server
2. ✅ Deploy to your first pfSense client
3. ✅ Verify client connection
4. ✅ Start the AI console
5. ✅ Try some AI commands!

### Advanced Features

Once you're comfortable with the basics:

- Set up geographic threat analysis (requires ipinfo.io token)
- Enable threat intelligence correlation (requires AbuseIPDB key)
- Configure custom firewall rules via AI
- Set up automated security assessments
- Monitor outbound connections for suspicious activity

---

## 💡 Tips

1. **Keep the HQ server running** - Clients need it to connect
2. **Use the AI console** - It's much easier than manual commands
3. **Check logs regularly** - Both server and client logs are helpful
4. **Start with one client** - Get comfortable before deploying to multiple
5. **Backup your .env file** - But never commit it to git!

---

## 🆘 Getting Help

If you run into issues:

1. Check the troubleshooting section above
2. Review the server logs in the HQ server window
3. Check client logs: `ssh root@<IP> 'tail -100 /var/log/pfsense_client.log'`
4. Verify all prerequisites are installed correctly
5. Make sure `.env` file has correct credentials

---

## 🎉 You're Ready!

You now have a fully functional AI-powered pfSense firewall management system!

Start exploring with the AI console and see what insights you can discover about your network traffic.

**Happy firewall managing! 🔥**

