#!/bin/bash

# Hotfix script for Soteria runtime errors

echo "Applying Soteria hotfixes..."

# Fix 1: Dashboard Werkzeug error
echo "Fixing dashboard server..."
sed -i '/log_output=False/a\            allow_unsafe_werkzeug=True  # Required for production use' /opt/soteria/ui/dashboard.py

# Fix 2: Program detector connections error
echo "Fixing program detector..."
sed -i "s/'memory_percent', 'connections'/'memory_percent'/" /opt/soteria/detection/program_detector.py
sed -i "s/connections = info.get('connections', \[\])/connections = proc.connections()/" /opt/soteria/detection/program_detector.py

# Restart service
echo "Restarting Soteria service..."
systemctl restart soteria

echo "Hotfixes applied!"
echo "Check status: systemctl status soteria"
echo "View logs: journalctl -u soteria -f"