#!/bin/bash

# Soteria IDS Installation Script

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                  SOTERIA IDS INSTALLER                        ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Error: This installer must be run as root${NC}"
    exit 1
fi

# Check Python version
echo -e "${YELLOW}Checking Python version...${NC}"
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Error: Python 3 is not installed${NC}"
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
REQUIRED_VERSION="3.8"

if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$PYTHON_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]; then
    echo -e "${RED}Error: Python $REQUIRED_VERSION or higher is required (found $PYTHON_VERSION)${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Python $PYTHON_VERSION found${NC}"

# Install system dependencies
echo -e "${YELLOW}Installing system dependencies...${NC}"
apt-get update
apt-get install -y \
    python3-pip \
    python3-dev \
    python3-venv \
    libpcap-dev \
    libssl-dev \
    libffi-dev \
    build-essential \
    tcpdump

# Create installation directories
echo -e "${YELLOW}Creating directories...${NC}"
mkdir -p /opt/soteria
mkdir -p /etc/soteria
mkdir -p /var/log/soteria
mkdir -p /var/lib/soteria
mkdir -p /var/lib/soteria/rules/yara
mkdir -p /var/lib/soteria/data

# Copy files
echo -e "${YELLOW}Copying files...${NC}"
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cp -r "$SCRIPT_DIR"/* /opt/soteria/
chmod +x /opt/soteria/main.py

# Create virtual environment
echo -e "${YELLOW}Creating Python virtual environment...${NC}"
cd /opt/soteria
python3 -m venv venv

# Install Python dependencies
echo -e "${YELLOW}Installing Python dependencies...${NC}"
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# Download GeoIP database (optional)
echo -e "${YELLOW}Setting up GeoIP database...${NC}"
mkdir -p /var/lib/soteria/data
echo -e "${YELLOW}Note: GeoIP database requires MaxMind license key${NC}"
echo -e "${YELLOW}Visit https://www.maxmind.com to obtain a free license${NC}"

# Setup configuration
echo -e "${YELLOW}Setting up configuration...${NC}"
if [ ! -f /etc/soteria/soteria.yaml ]; then
    cp /opt/soteria/config/soteria.yaml /etc/soteria/
    echo -e "${YELLOW}Default configuration copied to /etc/soteria/soteria.yaml${NC}"
    echo -e "${YELLOW}Please edit this file to add your API keys and customize settings${NC}"
fi

# Create wrapper script
echo -e "${YELLOW}Creating wrapper script...${NC}"
cat > /usr/local/bin/soteria << 'EOF'
#!/bin/bash
cd /opt/soteria
source venv/bin/activate
export SOTERIA_CONFIG=${SOTERIA_CONFIG:-/etc/soteria/soteria.yaml}
python3 main.py "$@"
EOF
chmod +x /usr/local/bin/soteria

# Install systemd service
echo -e "${YELLOW}Installing systemd service...${NC}"
cp /opt/soteria/soteria.service /etc/systemd/system/
systemctl daemon-reload

# Create log rotation config
echo -e "${YELLOW}Setting up log rotation...${NC}"
cat > /etc/logrotate.d/soteria << EOF
/var/log/soteria/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root root
    sharedscripts
    postrotate
        systemctl reload soteria > /dev/null 2>&1 || true
    endscript
}
EOF

# Set permissions
echo -e "${YELLOW}Setting permissions...${NC}"
chown -R root:root /opt/soteria
chown -R root:root /etc/soteria
chown -R root:root /var/log/soteria
chown -R root:root /var/lib/soteria
chmod 600 /etc/soteria/soteria.yaml

# Enable service
echo -e "${YELLOW}Enabling service...${NC}"
systemctl enable soteria

echo
echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║            INSTALLATION COMPLETED SUCCESSFULLY!               ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo
echo -e "${YELLOW}Next steps:${NC}"
echo -e "1. Edit configuration: ${GREEN}nano /etc/soteria/soteria.yaml${NC}"
echo -e "2. Add your API keys to the configuration file"
echo -e "3. Start Soteria: ${GREEN}systemctl start soteria${NC}"
echo -e "4. Check status: ${GREEN}systemctl status soteria${NC}"
echo -e "5. View logs: ${GREEN}journalctl -u soteria -f${NC}"
echo -e "6. Access dashboard: ${GREEN}http://localhost:8080${NC}"
echo -e "7. Use CLI: ${GREEN}soteria cli${NC}"
echo
echo -e "${YELLOW}For more information, see the documentation.${NC}"