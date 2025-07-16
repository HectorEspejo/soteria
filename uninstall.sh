#!/bin/bash

# Soteria IDS Uninstallation Script

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${RED}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${RED}║                SOTERIA IDS UNINSTALLER                        ║${NC}"
echo -e "${RED}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Error: This uninstaller must be run as root${NC}"
    exit 1
fi

# Confirmation prompt
echo -e "${YELLOW}This will completely remove Soteria IDS from your system.${NC}"
echo -e "${YELLOW}This action cannot be undone!${NC}"
echo
read -p "Are you sure you want to continue? (yes/no): " confirmation

if [ "$confirmation" != "yes" ]; then
    echo -e "${GREEN}Uninstallation cancelled.${NC}"
    exit 0
fi

echo
echo -e "${YELLOW}Starting uninstallation process...${NC}"

# Step 1: Stop and disable the service
echo -e "${YELLOW}Stopping Soteria service...${NC}"
if systemctl is-active --quiet soteria; then
    systemctl stop soteria
    echo -e "${GREEN}✓ Service stopped${NC}"
else
    echo -e "${GREEN}✓ Service was not running${NC}"
fi

if systemctl is-enabled --quiet soteria 2>/dev/null; then
    systemctl disable soteria
    echo -e "${GREEN}✓ Service disabled${NC}"
fi

# Step 2: Remove systemd service file
echo -e "${YELLOW}Removing systemd service...${NC}"
if [ -f /etc/systemd/system/soteria.service ]; then
    rm -f /etc/systemd/system/soteria.service
    systemctl daemon-reload
    echo -e "${GREEN}✓ Systemd service removed${NC}"
fi

# Step 3: Remove PID file
echo -e "${YELLOW}Removing PID file...${NC}"
rm -f /run/soteria.pid
rm -f /var/run/soteria.pid
echo -e "${GREEN}✓ PID file removed${NC}"

# Step 4: Backup important data before removal
echo -e "${YELLOW}Backing up data...${NC}"
BACKUP_DIR="/tmp/soteria_backup_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"

# Backup configuration if exists
if [ -f /etc/soteria/soteria.yaml ]; then
    cp /etc/soteria/soteria.yaml "$BACKUP_DIR/"
    echo -e "${GREEN}✓ Configuration backed up to $BACKUP_DIR/soteria.yaml${NC}"
fi

# Backup database if exists
if [ -f /var/log/soteria/soteria.db ] || [ -f /var/lib/soteria/logs/soteria.db ]; then
    mkdir -p "$BACKUP_DIR/data"
    find /var/log/soteria /var/lib/soteria -name "*.db" -exec cp {} "$BACKUP_DIR/data/" \; 2>/dev/null || true
    echo -e "${GREEN}✓ Database backed up to $BACKUP_DIR/data/${NC}"
fi

# Step 5: Remove installation directories
echo -e "${YELLOW}Removing installation directories...${NC}"

# Remove main installation directory
if [ -d /opt/soteria ]; then
    rm -rf /opt/soteria
    echo -e "${GREEN}✓ Removed /opt/soteria${NC}"
fi

# Remove configuration directory
if [ -d /etc/soteria ]; then
    rm -rf /etc/soteria
    echo -e "${GREEN}✓ Removed /etc/soteria${NC}"
fi

# Remove log directory
if [ -d /var/log/soteria ]; then
    rm -rf /var/log/soteria
    echo -e "${GREEN}✓ Removed /var/log/soteria${NC}"
fi

# Remove data directory
if [ -d /var/lib/soteria ]; then
    rm -rf /var/lib/soteria
    echo -e "${GREEN}✓ Removed /var/lib/soteria${NC}"
fi

# Step 6: Remove wrapper script
echo -e "${YELLOW}Removing wrapper script...${NC}"
if [ -f /usr/local/bin/soteria ]; then
    rm -f /usr/local/bin/soteria
    echo -e "${GREEN}✓ Removed /usr/local/bin/soteria${NC}"
fi

# Step 7: Remove logrotate configuration
echo -e "${YELLOW}Removing logrotate configuration...${NC}"
if [ -f /etc/logrotate.d/soteria ]; then
    rm -f /etc/logrotate.d/soteria
    echo -e "${GREEN}✓ Removed logrotate configuration${NC}"
fi

# Step 8: Clean up any remaining processes
echo -e "${YELLOW}Cleaning up processes...${NC}"
# Kill any remaining python processes related to soteria
pkill -f "soteria" 2>/dev/null || true
pkill -f "main.py" 2>/dev/null || true
echo -e "${GREEN}✓ Cleaned up remaining processes${NC}"

# Step 9: Remove any cron jobs (if any were created)
echo -e "${YELLOW}Checking for cron jobs...${NC}"
crontab -l 2>/dev/null | grep -v "soteria" | crontab - 2>/dev/null || true
echo -e "${GREEN}✓ Cron jobs cleaned${NC}"

# Step 10: Optional - Remove Python packages
echo
echo -e "${YELLOW}Do you want to remove Python packages installed for Soteria?${NC}"
echo -e "${YELLOW}Note: This might affect other Python applications${NC}"
read -p "Remove Python packages? (yes/no): " remove_packages

if [ "$remove_packages" = "yes" ]; then
    echo -e "${YELLOW}Removing Python packages...${NC}"
    
    # List of packages specific to Soteria
    PACKAGES=(
        "scapy"
        "yara-python"
        "python-daemon"
        "flask-socketio"
        "geoip2"
        "virustotal-python"
        "slack-sdk"
        "twilio"
        "python-whois"
    )
    
    for package in "${PACKAGES[@]}"; do
        pip3 uninstall -y "$package" 2>/dev/null || true
    done
    
    echo -e "${GREEN}✓ Python packages removed${NC}"
fi

# Step 11: Clean up any temporary files
echo -e "${YELLOW}Cleaning up temporary files...${NC}"
rm -f /tmp/soteria*
rm -rf /tmp/pip-*-soteria*
echo -e "${GREEN}✓ Temporary files cleaned${NC}"

echo
echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║           SOTERIA IDS UNINSTALLED SUCCESSFULLY!               ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo
echo -e "${YELLOW}Important notes:${NC}"
echo -e "- Configuration and database backed up to: ${GREEN}$BACKUP_DIR${NC}"
echo -e "- System dependencies (libpcap-dev, etc.) were NOT removed"
echo -e "- Python3 and pip were NOT removed"
echo
echo -e "${YELLOW}To completely remove the backup, run:${NC}"
echo -e "${GREEN}rm -rf $BACKUP_DIR${NC}"
echo
echo -e "${YELLOW}Thank you for using Soteria IDS!${NC}"