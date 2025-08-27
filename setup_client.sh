#!/bin/bash
# pfSense Client Setup Script
# Run this script on your pfSense firewall

set -e

echo "🔥 Setting up pfSense Firewall Client..."

# Check if running on FreeBSD (pfSense)
if [ "$(uname)" != "FreeBSD" ]; then
    echo "⚠️  This script is designed for pfSense (FreeBSD). Proceeding anyway..."
fi

# Install required packages
echo "📦 Installing required packages..."
pkg install -y python39 py39-pip

# Install Python dependencies
echo "📦 Installing Python dependencies..."
pip install requests pyyaml psutil

# Create directories
mkdir -p /usr/local/bin
mkdir -p /usr/local/etc
mkdir -p /var/log

# Copy client script
echo "📋 Installing client script..."
cp client/pfsense_client.py /usr/local/bin/
chmod +x /usr/local/bin/pfsense_client.py

# Copy configuration
echo "📋 Installing configuration..."
if [ ! -f /usr/local/etc/pfsense_client.yaml ]; then
    cp config/client_config.yaml /usr/local/etc/pfsense_client.yaml
    echo "⚠️  Please edit /usr/local/etc/pfsense_client.yaml with your HQ server URL"
else
    echo "✅ Configuration file already exists"
fi

# Create service script for pfSense
echo "🔧 Creating service script..."
cat > /usr/local/etc/rc.d/pfsense_client << 'EOF'
#!/bin/sh

# PROVIDE: pfsense_client
# REQUIRE: NETWORKING
# KEYWORD: shutdown

. /etc/rc.subr

name="pfsense_client"
rcvar="pfsense_client_enable"

command="/usr/local/bin/python3"
command_args="/usr/local/bin/pfsense_client.py --daemon"
pidfile="/var/run/pfsense_client.pid"

start_cmd="pfsense_client_start"
stop_cmd="pfsense_client_stop"

pfsense_client_start()
{
    echo "Starting pfSense client..."
    /usr/sbin/daemon -p ${pidfile} ${command} ${command_args}
}

pfsense_client_stop()
{
    echo "Stopping pfSense client..."
    if [ -f ${pidfile} ]; then
        kill `cat ${pidfile}`
        rm -f ${pidfile}
    fi
}

load_rc_config $name
run_rc_command "$1"
EOF

chmod +x /usr/local/etc/rc.d/pfsense_client

# Add to rc.conf
echo "🔧 Configuring service..."
if ! grep -q "pfsense_client_enable" /etc/rc.conf; then
    echo 'pfsense_client_enable="YES"' >> /etc/rc.conf
    echo "✅ Added service to rc.conf"
else
    echo "✅ Service already configured in rc.conf"
fi

echo ""
echo "🎉 pfSense Client setup complete!"
echo ""
echo "Next steps:"
echo "1. Edit /usr/local/etc/pfsense_client.yaml with your HQ server URL"
echo "2. Test the client: python3 /usr/local/bin/pfsense_client.py"
echo "3. Start the service: service pfsense_client start"
echo "4. Check status: service pfsense_client status"
echo ""
echo "Logs will be written to /var/log/pfsense_client.log"