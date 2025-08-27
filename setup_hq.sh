#!/bin/bash
# HQ Server Setup Script for pfSense Firewall Management System

set -e

echo "🔥 Setting up pfSense Firewall Management HQ Server..."

# Check if Python 3.8+ is installed
python_version=$(python3 --version 2>&1 | awk '{print $2}' | cut -d. -f1,2)
required_version="3.8"

if [ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" != "$required_version" ]; then
    echo "❌ Python 3.8 or higher is required. Found: $python_version"
    exit 1
fi

echo "✅ Python version check passed: $python_version"

# Install Python dependencies
echo "📦 Installing Python dependencies..."
pip3 install -r requirements.txt

# Create .env file if it doesn't exist
if [ ! -f .env ]; then
    echo "📝 Creating .env file from template..."
    cp config/.env.example .env
    echo "⚠️  Please edit .env file with your OpenAI API key and other settings"
else
    echo "✅ .env file already exists"
fi

# Create logs directory
mkdir -p logs
echo "✅ Created logs directory"

# Set up database directory
mkdir -p data
echo "✅ Created data directory"

# Make scripts executable
chmod +x hq/server.py
chmod +x hq/ai_command_center.py
echo "✅ Made scripts executable"

# Create systemd service files (optional)
if command -v systemctl &> /dev/null; then
    echo "🔧 Creating systemd service files..."

    cat > /tmp/pfsense-hq-server.service << EOF
[Unit]
Description=pfSense HQ Server
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$(pwd)
ExecStart=$(which python3) hq/server.py --host 0.0.0.0 --port 8000
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

    echo "📋 Systemd service file created at /tmp/pfsense-hq-server.service"
    echo "   To install: sudo cp /tmp/pfsense-hq-server.service /etc/systemd/system/"
    echo "   To enable: sudo systemctl enable pfsense-hq-server"
    echo "   To start: sudo systemctl start pfsense-hq-server"
fi

echo ""
echo "🎉 HQ Server setup complete!"
echo ""
echo "Next steps:"
echo "1. Edit .env file with your OpenAI API key"
echo "2. Start the HQ server: cd hq && python3 server.py"
echo "3. Start the AI Command Center: cd hq && python3 ai_command_center.py --openai-key YOUR_KEY"
echo ""
echo "For more information, see README.md"