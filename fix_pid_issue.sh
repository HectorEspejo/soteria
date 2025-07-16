#!/bin/bash

# Fix PID file location issue for Soteria

echo "Fixing Soteria PID file configuration..."

# Stop the service if running
echo "Stopping Soteria service..."
systemctl stop soteria 2>/dev/null

# Remove any existing PID files
rm -f /var/run/soteria.pid /run/soteria.pid

# Update main.py
echo "Updating main.py..."
sed -i 's|/var/run/soteria.pid|/run/soteria.pid|g' /opt/soteria/main.py

# Update systemd service file
echo "Updating systemd service..."
sed -i 's|PIDFile=/var/run/soteria.pid|PIDFile=/run/soteria.pid|g' /etc/systemd/system/soteria.service

# Add /run to ReadWritePaths if not already present
if ! grep -q "ReadWritePaths=.*\/run" /etc/systemd/system/soteria.service; then
    sed -i '/ReadWritePaths=/s|$| /run|' /etc/systemd/system/soteria.service
fi

# Update the wrapper script
echo "Updating wrapper script..."
sed -i 's|/var/run/soteria.pid|/run/soteria.pid|g' /usr/local/bin/soteria 2>/dev/null

# Reload systemd
echo "Reloading systemd daemon..."
systemctl daemon-reload

# Start the service
echo "Starting Soteria service..."
systemctl start soteria

# Wait a moment
sleep 2

# Check status
echo ""
echo "Checking service status..."
systemctl status soteria --no-pager

echo ""
echo "Fix applied. If the service is still failing, check:"
echo "1. Permissions: ls -la /run/soteria.pid"
echo "2. Logs: journalctl -u soteria -n 50"