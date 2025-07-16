#!/usr/bin/env python3
"""
Basic test script for Soteria IDS
"""

import sys
import os

def test_imports():
    print("Testing imports...")
    try:
        import scapy
        print("✓ Scapy")
    except ImportError:
        print("✗ Scapy - Install with: pip install scapy")
    
    try:
        import flask
        print("✓ Flask")
    except ImportError:
        print("✗ Flask - Install with: pip install flask")
    
    try:
        import psutil
        print("✓ psutil")
    except ImportError:
        print("✗ psutil - Install with: pip install psutil")
    
    try:
        import yara
        print("✓ YARA")
    except ImportError:
        print("✗ YARA - Install with: pip install yara-python")
    
    try:
        import pandas
        print("✓ pandas")
    except ImportError:
        print("✗ pandas - Install with: pip install pandas")
    
    try:
        import numpy
        print("✓ numpy")
    except ImportError:
        print("✗ numpy - Install with: pip install numpy")
    
    print()

def test_modules():
    print("Testing Soteria modules...")
    
    try:
        from config.config_parser import ConfigParser
        print("✓ Config Parser")
    except Exception as e:
        print(f"✗ Config Parser: {e}")
    
    try:
        from core.engine import SoteriaEngine
        print("✓ Core Engine")
    except Exception as e:
        print(f"✗ Core Engine: {e}")
    
    try:
        from capture.sniffer import PacketSniffer
        print("✓ Packet Sniffer")
    except Exception as e:
        print(f"✗ Packet Sniffer: {e}")
    
    try:
        from detection.url_detector import URLDetector
        print("✓ URL Detector")
    except Exception as e:
        print(f"✗ URL Detector: {e}")
    
    try:
        from detection.program_detector import ProgramDetector
        print("✓ Program Detector")
    except Exception as e:
        print(f"✗ Program Detector: {e}")
    
    try:
        from detection.traffic_detector import TrafficDetector
        print("✓ Traffic Detector")
    except Exception as e:
        print(f"✗ Traffic Detector: {e}")
    
    try:
        from logs_management.database import DatabaseLogger
        print("✓ Database Logger")
    except Exception as e:
        print(f"✗ Database Logger: {e}")
    
    try:
        from logs_management.alerting import AlertManager
        print("✓ Alert Manager")
    except Exception as e:
        print(f"✗ Alert Manager: {e}")
    
    try:
        from ui.dashboard import DashboardServer
        print("✓ Dashboard Server")
    except Exception as e:
        print(f"✗ Dashboard Server: {e}")
    
    try:
        from cli.interface import CLIHandler
        print("✓ CLI Interface")
    except Exception as e:
        print(f"✗ CLI Interface: {e}")
    
    print()

def test_directories():
    print("Checking directories...")
    
    dirs = ['config', 'core', 'capture', 'detection', 'logs_management', 'ui', 'cli', 'utils', 'logs', 'rules/yara']
    for d in dirs:
        if os.path.exists(d):
            print(f"✓ {d}")
        else:
            print(f"✗ {d} - Missing")
    
    print()

def test_config():
    print("Testing configuration...")
    
    if os.path.exists('config/soteria.yaml'):
        print("✓ Default configuration exists")
        
        try:
            from config.config_parser import ConfigParser
            parser = ConfigParser('config/soteria.yaml')
            config = parser.load()
            print("✓ Configuration loads successfully")
        except Exception as e:
            print(f"✗ Configuration error: {e}")
    else:
        print("✗ Configuration file missing")
    
    print()

def main():
    print("╔═══════════════════════════════════════════════════════════════╗")
    print("║                  SOTERIA IDS - BASIC TEST                     ║")
    print("╚═══════════════════════════════════════════════════════════════╝")
    print()
    
    test_imports()
    test_directories()
    test_modules()
    test_config()
    
    print("Test complete!")
    print("\nNext steps:")
    print("1. Install any missing dependencies: pip install -r requirements.txt")
    print("2. Run as root for packet capture: sudo python3 main.py run")
    print("3. Check the web dashboard at http://localhost:8080")

if __name__ == '__main__':
    main()