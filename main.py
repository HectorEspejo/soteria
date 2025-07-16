#!/usr/bin/env python3
import os
import sys
import signal
import logging
import argparse
import inspect
from pathlib import Path
import daemon
import daemon.pidfile

from core.engine import SoteriaEngine
from cli.interface import CLIHandler

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class SoteriaDaemon:
    def __init__(self, config_path: str, pidfile_path: str = '/run/soteria.pid'):
        self.config_path = config_path
        self.pidfile_path = pidfile_path
        self.engine = None
        
    def start(self):
        logger.info("Starting Soteria IDS daemon...")
        
        if os.path.exists(self.pidfile_path):
            with open(self.pidfile_path, 'r') as f:
                pid = int(f.read().strip())
                try:
                    os.kill(pid, 0)
                    logger.error(f"Soteria is already running with PID {pid}")
                    sys.exit(1)
                except ProcessLookupError:
                    os.remove(self.pidfile_path)
        
        # Create daemon context with compatibility for different versions
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
        
        context = daemon.DaemonContext(**context_args)
        
        with context:
            self._run()
    
    def _run(self):
        try:
            self.engine = SoteriaEngine(self.config_path)
            self.engine.start()
            logger.info("Soteria IDS daemon started successfully")
            
            signal.pause()
            
        except Exception as e:
            logger.error(f"Fatal error in daemon: {e}", exc_info=True)
            sys.exit(1)
    
    def stop(self):
        if not os.path.exists(self.pidfile_path):
            logger.error("Soteria is not running")
            return
        
        try:
            with open(self.pidfile_path, 'r') as f:
                pid = int(f.read().strip())
            
            os.kill(pid, signal.SIGTERM)
            logger.info(f"Sent SIGTERM to Soteria daemon (PID {pid})")
            
        except Exception as e:
            logger.error(f"Failed to stop Soteria: {e}")
    
    def status(self):
        if not os.path.exists(self.pidfile_path):
            print("Soteria is not running")
            return False
        
        try:
            with open(self.pidfile_path, 'r') as f:
                pid = int(f.read().strip())
            
            os.kill(pid, 0)
            print(f"Soteria is running (PID {pid})")
            return True
            
        except ProcessLookupError:
            print("Soteria is not running (stale PID file)")
            os.remove(self.pidfile_path)
            return False
    
    def _signal_handler(self, signum, frame):
        logger.info(f"Received signal {signum}, shutting down...")
        if self.engine:
            self.engine.stop()
        sys.exit(0)
    
    def _reload_config(self, signum, frame):
        logger.info("Received SIGHUP, reloading configuration...")
        if self.engine:
            self.engine.reload_config()

def main():
    parser = argparse.ArgumentParser(description='Soteria IDS - Network Intrusion Detection System')
    
    parser.add_argument('command', 
                       choices=['start', 'stop', 'restart', 'status', 'run', 'cli'],
                       help='Command to execute')
    
    parser.add_argument('-c', '--config',
                       default='config/soteria.yaml',
                       help='Path to configuration file')
    
    parser.add_argument('-p', '--pidfile',
                       default='/run/soteria.pid',
                       help='Path to PID file')
    
    parser.add_argument('-d', '--debug',
                       action='store_true',
                       help='Enable debug logging')
    
    parser.add_argument('--cli-args',
                       nargs=argparse.REMAINDER,
                       help='Arguments for CLI mode')
    
    args = parser.parse_args()
    
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    
    if os.geteuid() != 0 and args.command in ['start', 'stop', 'restart', 'run']:
        logger.error("Soteria requires root privileges for packet capture")
        sys.exit(1)
    
    daemon = SoteriaDaemon(args.config, args.pidfile)
    
    if args.command == 'start':
        daemon.start()
    
    elif args.command == 'stop':
        daemon.stop()
    
    elif args.command == 'restart':
        daemon.stop()
        import time
        time.sleep(2)
        daemon.start()
    
    elif args.command == 'status':
        daemon.status()
    
    elif args.command == 'run':
        try:
            engine = SoteriaEngine(args.config)
            engine.start()
            
            def signal_handler(signum, frame):
                logger.info(f"Received signal {signum}, shutting down...")
                engine.stop()
                sys.exit(0)
            
            signal.signal(signal.SIGTERM, signal_handler)
            signal.signal(signal.SIGINT, signal_handler)
            
            signal.pause()
            
        except KeyboardInterrupt:
            logger.info("Interrupted by user")
            engine.stop()
        except Exception as e:
            logger.error(f"Fatal error: {e}", exc_info=True)
            sys.exit(1)
    
    elif args.command == 'cli':
        cli = CLIHandler(args.config)
        if args.cli_args:
            cli.execute(args.cli_args)
        else:
            cli.interactive()

if __name__ == '__main__':
    main()