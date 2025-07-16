#!/bin/bash

# Hotfix script for Soteria runtime errors - Part 2

echo "Applying Soteria hotfixes (Part 2)..."

# Stop service
echo "Stopping Soteria service..."
systemctl stop soteria

# Fix 1: API key validation in api_clients.py
echo "Fixing API key validation..."
cat > /tmp/api_fix.py << 'EOF'
import re

# Read the file
with open('/opt/soteria/utils/api_clients.py', 'r') as f:
    content = f.read()

# Add validation to VirusTotalClient
if 'self.is_valid = self._validate_api_key()' not in content:
    content = re.sub(
        r'(class VirusTotalClient:.*?self\.cache = APICache\(ttl=3600\))',
        r'\1\n        self.is_valid = self._validate_api_key()\n    \n    def _validate_api_key(self) -> bool:\n        """Check if API key is valid (not a placeholder)"""\n        if not self.api_key or self.api_key.startswith("YOUR_") or len(self.api_key) < 10:\n            logger.warning("VirusTotal API key not configured or invalid")\n            return False\n        return True',
        content,
        flags=re.DOTALL
    )
    
    # Add check in scan_url
    content = re.sub(
        r'def scan_url\(self, url: str\) -> Dict\[str, Any\]:\n(        cache_key)',
        r'def scan_url(self, url: str) -> Dict[str, Any]:\n        if not self.is_valid:\n            return {"error": "API key not configured", "malicious": False, "score": 0}\n        \n\1',
        content
    )
    
    # Add check in scan_file_hash
    content = re.sub(
        r'def scan_file_hash\(self, file_hash: str\) -> Dict\[str, Any\]:\n(        cache_key)',
        r'def scan_file_hash(self, file_hash: str) -> Dict[str, Any]:\n        if not self.is_valid:\n            return {"error": "API key not configured", "malicious": False, "score": 0}\n        \n\1',
        content
    )

# Add validation to GoogleSafeBrowsingClient
if 'class GoogleSafeBrowsingClient:' in content:
    content = re.sub(
        r'(class GoogleSafeBrowsingClient:.*?self\.cache = APICache\(ttl=1800\))',
        r'\1\n        self.is_valid = self._validate_api_key()\n    \n    def _validate_api_key(self) -> bool:\n        """Check if API key is valid (not a placeholder)"""\n        if not self.api_key or self.api_key.startswith("YOUR_") or len(self.api_key) < 10:\n            logger.warning("Google Safe Browsing API key not configured or invalid")\n            return False\n        return True',
        content,
        flags=re.DOTALL
    )
    
    # Add check in check_url
    content = re.sub(
        r'def check_url\(self, url: str\) -> Dict\[str, Any\]:\n(        cache_key)',
        r'def check_url(self, url: str) -> Dict[str, Any]:\n        if not self.is_valid:\n            return {"error": "API key not configured", "malicious": False, "score": 0}\n        \n\1',
        content
    )

# Write back
with open('/opt/soteria/utils/api_clients.py', 'w') as f:
    f.write(content)
EOF

python3 /tmp/api_fix.py

# Fix 2: zscore error in traffic_detector.py
echo "Fixing zscore calculation..."
sed -i 's/def _detect_statistical_anomaly(self, ip: str, stats: Dict, current_time: float):/def _detect_statistical_anomaly(self, ip: str, ip_stats: Dict, current_time: float):/' /opt/soteria/detection/traffic_detector.py
sed -i "s/recent_times = \[t for t in stats\['packets'\]/recent_times = [t for t in ip_stats['packets']/" /opt/soteria/detection/traffic_detector.py
sed -i "s/recent_bytes = sum(size for t, size in stats\['bytes'\]/recent_bytes = sum(size for t, size in ip_stats['bytes']/" /opt/soteria/detection/traffic_detector.py
sed -i "s/zscore = np.abs(stats.zscore(intervals))/zscore_values = np.abs(stats.zscore(intervals))/" /opt/soteria/detection/traffic_detector.py
sed -i "s/max_zscore = np.max(zscore)/max_zscore = np.max(zscore_values)/" /opt/soteria/detection/traffic_detector.py

# Fix 3: JSON serialization in dashboard.py
echo "Fixing JSON serialization..."
cat > /tmp/dashboard_fix.py << 'EOF'
import re

with open('/opt/soteria/ui/dashboard.py', 'r') as f:
    content = f.read()

# Add json_serializer function if not exists
if 'def json_serializer' not in content:
    content = re.sub(
        r'(logger = logging.getLogger\(__name__\))',
        r'\1\n\ndef json_serializer(obj):\n    """JSON serializer for objects not serializable by default"""\n    if isinstance(obj, datetime):\n        return obj.isoformat()\n    raise TypeError(f"Type {type(obj)} not serializable")',
        content
    )

# Update Flask and SocketIO initialization
content = re.sub(
    r"self\.socketio = SocketIO\(self\.app, cors_allowed_origins=\"\*\"\)",
    r"self.socketio = SocketIO(self.app, cors_allowed_origins=\"*\", json=json, json_kwargs={'default': json_serializer})",
    content
)

with open('/opt/soteria/ui/dashboard.py', 'w') as f:
    f.write(content)
EOF

python3 /tmp/dashboard_fix.py

# Clean up
rm -f /tmp/api_fix.py /tmp/dashboard_fix.py

# Restart service
echo "Restarting Soteria service..."
systemctl start soteria

echo "Hotfixes applied!"
echo "Check status: systemctl status soteria"
echo "View logs: journalctl -u soteria -f"
echo ""
echo "Note: API errors will now be silent unless you configure valid API keys in /etc/soteria/soteria.yaml"