#!/usr/bin/env python3
"""Test daemon functionality without full daemon mode"""

import os
import sys
import tempfile
import signal
import time

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.engine import SoteriaEngine
from config.config_parser import ConfigParser

def test_basic_startup():
    """Test basic startup without daemon"""
    print("Testing basic startup...")
    
    # Test configuration
    try:
        parser = ConfigParser('config/soteria.yaml')
        config = parser.load()
        print("✓ Configuration loaded successfully")
    except Exception as e:
        print(f"✗ Configuration error: {e}")
        return False
    
    # Test engine initialization
    try:
        engine = SoteriaEngine('config/soteria.yaml')
        print("✓ Engine initialized successfully")
    except Exception as e:
        print(f"✗ Engine initialization error: {e}")
        return False
    
    return True

def test_pid_file():
    """Test PID file operations"""
    print("\nTesting PID file operations...")
    
    # Test with temp directory
    temp_dir = tempfile.gettempdir()
    pid_file = os.path.join(temp_dir, 'soteria_test.pid')
    
    # Write PID
    try:
        with open(pid_file, 'w') as f:
            f.write(str(os.getpid()))
        print(f"✓ PID file written to {pid_file}")
    except Exception as e:
        print(f"✗ Failed to write PID file: {e}")
        return False
    
    # Read PID
    try:
        with open(pid_file, 'r') as f:
            pid = int(f.read().strip())
        print(f"✓ PID read successfully: {pid}")
    except Exception as e:
        print(f"✗ Failed to read PID file: {e}")
        return False
    
    # Cleanup
    try:
        os.remove(pid_file)
        print("✓ PID file cleaned up")
    except Exception as e:
        print(f"✗ Failed to remove PID file: {e}")
    
    return True

def test_daemon_import():
    """Test daemon module import"""
    print("\nTesting daemon module...")
    
    try:
        import daemon
        print("✓ daemon module imported")
        
        import daemon.pidfile
        print("✓ daemon.pidfile imported")
        
        # Check DaemonContext
        context = daemon.DaemonContext()
        print("✓ DaemonContext created")
        
        # Check parameters
        import inspect
        sig = inspect.signature(daemon.DaemonContext.__init__)
        params = list(sig.parameters.keys())
        print(f"  DaemonContext parameters: {params}")
        
        if 'preserve_files' in params:
            print("  ✓ preserve_files parameter supported")
        else:
            print("  ⚠ preserve_files parameter NOT supported")
        
    except Exception as e:
        print(f"✗ Daemon module error: {e}")
        return False
    
    return True

def test_run_directory():
    """Test /run directory access"""
    print("\nTesting /run directory access...")
    
    # Check if /run exists
    if os.path.exists('/run'):
        print("✓ /run directory exists")
        
        # Check permissions
        stat_info = os.stat('/run')
        print(f"  Permissions: {oct(stat_info.st_mode)}")
        print(f"  Owner: {stat_info.st_uid}")
        
        # Test write (will fail without root)
        test_file = '/run/soteria_test.tmp'
        try:
            with open(test_file, 'w') as f:
                f.write('test')
            os.remove(test_file)
            print("✓ Can write to /run")
        except PermissionError:
            print("⚠ Cannot write to /run (need root)")
        except Exception as e:
            print(f"✗ /run write error: {e}")
    else:
        print("✗ /run directory does not exist")
        
    # Alternative locations
    print("\nAlternative PID file locations:")
    for path in ['/tmp', '/var/tmp', os.path.expanduser('~/.soteria')]:
        if os.path.exists(path):
            print(f"  ✓ {path} (writable: {os.access(path, os.W_OK)})")

def main():
    print("Soteria Daemon Test Suite")
    print("=" * 50)
    
    # Run tests
    test_daemon_import()
    test_pid_file()
    test_run_directory()
    test_basic_startup()
    
    print("\n" + "=" * 50)
    print("Test complete!")
    
    # Recommendations
    print("\nRecommendations:")
    print("1. For testing without root: use --pidfile /tmp/soteria.pid")
    print("2. For production: ensure systemd manages PID file")
    print("3. Consider using Type=simple instead of Type=forking in systemd")

if __name__ == '__main__':
    main()