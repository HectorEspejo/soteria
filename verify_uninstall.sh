#!/bin/bash

# Soteria IDS Uninstallation Verification Script

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}Verifying Soteria IDS uninstallation...${NC}"
echo

FOUND_ITEMS=0

# Check systemd service
if systemctl list-unit-files | grep -q soteria; then
    echo -e "${RED}✗ Systemd service still exists${NC}"
    FOUND_ITEMS=$((FOUND_ITEMS + 1))
else
    echo -e "${GREEN}✓ Systemd service removed${NC}"
fi

# Check directories
DIRS=(
    "/opt/soteria"
    "/etc/soteria"
    "/var/log/soteria"
    "/var/lib/soteria"
)

for dir in "${DIRS[@]}"; do
    if [ -d "$dir" ]; then
        echo -e "${RED}✗ Directory still exists: $dir${NC}"
        FOUND_ITEMS=$((FOUND_ITEMS + 1))
    else
        echo -e "${GREEN}✓ Directory removed: $dir${NC}"
    fi
done

# Check files
FILES=(
    "/usr/local/bin/soteria"
    "/etc/systemd/system/soteria.service"
    "/etc/logrotate.d/soteria"
    "/run/soteria.pid"
    "/var/run/soteria.pid"
)

for file in "${FILES[@]}"; do
    if [ -f "$file" ]; then
        echo -e "${RED}✗ File still exists: $file${NC}"
        FOUND_ITEMS=$((FOUND_ITEMS + 1))
    else
        echo -e "${GREEN}✓ File removed: $file${NC}"
    fi
done

# Check running processes
if pgrep -f "soteria" > /dev/null 2>&1; then
    echo -e "${RED}✗ Soteria processes still running${NC}"
    FOUND_ITEMS=$((FOUND_ITEMS + 1))
else
    echo -e "${GREEN}✓ No Soteria processes found${NC}"
fi

# Check cron jobs
if crontab -l 2>/dev/null | grep -q "soteria"; then
    echo -e "${RED}✗ Cron jobs still exist${NC}"
    FOUND_ITEMS=$((FOUND_ITEMS + 1))
else
    echo -e "${GREEN}✓ No cron jobs found${NC}"
fi

echo
if [ $FOUND_ITEMS -eq 0 ]; then
    echo -e "${GREEN}Soteria IDS has been completely removed from the system!${NC}"
else
    echo -e "${RED}Found $FOUND_ITEMS items that were not removed.${NC}"
    echo -e "${YELLOW}You may need to manually remove these items.${NC}"
fi