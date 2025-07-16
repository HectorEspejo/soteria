#!/bin/bash

# Patch script for daemon compatibility issue

echo "Patching Soteria daemon compatibility..."

# Create a temporary Python script to apply the patch
cat > /tmp/patch_soteria.py << 'EOF'
import sys
import re

# Read the main.py file
with open('/opt/soteria/main.py', 'r') as f:
    content = f.read()

# Check if already patched
if 'inspect.signature' in content:
    print("Already patched!")
    sys.exit(0)

# Add inspect import if not present
if 'import inspect' not in content:
    content = content.replace('import argparse', 'import argparse\nimport inspect')

# Replace the daemon context creation
old_pattern = r'context = daemon\.DaemonContext\([^)]+\)'
new_code = '''# Create daemon context with compatibility for different versions
        context_args = {
            'working_directory': os.getcwd(),
            'pidfile': daemon.pidfile.PIDLockFile(self.pidfile_path),
            'signal_map': {
                signal.SIGTERM: self._signal_handler,
                signal.SIGINT: self._signal_handler,
                signal.SIGHUP: self._reload_config,
            }
        }
        
        # Check if preserve_files is supported
        import inspect
        if 'preserve_files' in inspect.signature(daemon.DaemonContext.__init__).parameters:
            context_args['preserve_files'] = [sys.stdout, sys.stderr]
        
        context = daemon.DaemonContext(**context_args)'''

# Find and replace
if 'preserve_files' in content:
    # Find the full context block
    start = content.find('context = daemon.DaemonContext(')
    end = content.find(')', start) + 1
    old_block = content[start:end]
    
    # Get indentation
    line_start = content.rfind('\n', 0, start) + 1
    indent = ' ' * (start - line_start)
    
    # Add proper indentation to new code
    new_code_indented = '\n'.join(indent + line if line.strip() else line 
                                  for line in new_code.split('\n'))
    
    # Replace
    content = content.replace(old_block, new_code_indented.strip())

# Write back
with open('/opt/soteria/main.py', 'w') as f:
    f.write(content)

print("Patch applied successfully!")
EOF

# Run the patch
python3 /tmp/patch_soteria.py

# Clean up
rm -f /tmp/patch_soteria.py

echo "Restarting Soteria service..."
systemctl daemon-reload
systemctl restart soteria

echo "Done! Check status with: systemctl status soteria"