#!/bin/bash
# SSH Honeypot Setup Script
# Sets up the environment, installs dependencies, and configures iptables

set -e

echo "========================================="
echo "SSH Honeypot Setup Script"
echo "========================================="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root (sudo)"
    exit 1
fi

# Update system
echo "[*] Updating system packages..."
apt-get update -qq

# Install Python and dependencies
echo "[*] Installing Python dependencies..."
apt-get install -y python3 python3-pip iptables

# Install Python packages
echo "[*] Installing Python packages (paramiko)..."
pip3 install paramiko --quiet

# Create honeypot directory
HONEYPOT_DIR="/opt/ssh-honeypot"
echo "[*] Creating honeypot directory at $HONEYPOT_DIR..."
mkdir -p $HONEYPOT_DIR
cd $HONEYPOT_DIR

# Copy honeypot script (assumes script is in current directory)
if [ -f "honeypot.py" ]; then
    cp honeypot.py $HONEYPOT_DIR/
    chmod +x $HONEYPOT_DIR/honeypot.py
else
    echo "[!] Warning: honeypot.py not found in current directory"
fi

# Configure iptables to redirect SSH traffic to honeypot
echo "[*] Configuring iptables rules..."
echo ""
echo "This will redirect external SSH traffic (port 22) to the honeypot (port 2222)"
echo "Your current SSH session will remain safe on port 22"
echo ""

read -p "Configure iptables redirection? (y/n): " -n 1 -r
echo ""

if [[ $REPLY =~ ^[Yy]$ ]]; then
    # Allow established connections (keeps your current SSH session alive)
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    
    # Redirect incoming traffic on port 22 to honeypot port 2222
    # Only for NEW connections from external sources
    iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
    
    # Save iptables rules
    iptables-save > /etc/iptables/rules.v4
    
    echo "[✓] iptables configured successfully"
else
    echo "[!] Skipping iptables configuration"
    echo "    You can manually redirect traffic with:"
    echo "    iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222"
fi

# Create systemd service
echo "[*] Creating systemd service..."
cat > /etc/systemd/system/ssh-honeypot.service << EOF
[Unit]
Description=SSH Honeypot Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$HONEYPOT_DIR
ExecStart=/usr/bin/python3 $HONEYPOT_DIR/honeypot.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd
systemctl daemon-reload

echo ""
echo "========================================="
echo "Setup Complete!"
echo "========================================="
echo ""
echo "To start the honeypot:"
echo "  sudo systemctl start ssh-honeypot"
echo ""
echo "To enable on boot:"
echo "  sudo systemctl enable ssh-honeypot"
echo ""
echo "To view logs:"
echo "  sudo journalctl -u ssh-honeypot -f"
echo ""
echo "Log files location:"
echo "  $HONEYPOT_DIR/honeypot_logs.json"
echo "  $HONEYPOT_DIR/honeypot.log"
echo ""
echo "========================================="
echo ""

# Offer to start immediately
read -p "Start honeypot now? (y/n): " -n 1 -r
echo ""
if [[ $REPLY =~ ^[Yy]$ ]]; then
    systemctl start ssh-honeypot
    echo "[✓] Honeypot started!"
    echo ""
    systemctl status ssh-honeypot --no-pager
fi
