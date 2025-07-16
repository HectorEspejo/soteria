import cmd
import logging
import requests
import json
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import subprocess
from tabulate import tabulate

from config.config_parser import ConfigParser
from logs_management.database import DatabaseLogger

logger = logging.getLogger(__name__)

class CLIHandler(cmd.Cmd):
    intro = """
    ╔═══════════════════════════════════════════════════════════════╗
    ║                      SOTERIA IDS CLI                          ║
    ║            Network Intrusion Detection System                 ║
    ╚═══════════════════════════════════════════════════════════════╝
    
    Type 'help' or '?' to list commands.
    """
    
    prompt = 'soteria> '
    
    def __init__(self, config_path: str):
        super().__init__()
        self.config_path = config_path
        self.config = None
        self.db_logger = None
        self._load_config()
        self._init_database()
    
    def _load_config(self):
        try:
            parser = ConfigParser(self.config_path)
            self.config = parser.load()
        except Exception as e:
            print(f"Error loading configuration: {e}")
    
    def _init_database(self):
        try:
            if self.config:
                db_path = self.config.get('logging', {}).get('database', 'logs/soteria.db')
                self.db_logger = DatabaseLogger(db_path)
                self.db_logger.start()
        except Exception as e:
            print(f"Error initializing database: {e}")
    
    def do_status(self, arg):
        """Check the status of Soteria IDS daemon"""
        try:
            result = subprocess.run(['python3', 'main.py', 'status'], 
                                  capture_output=True, text=True)
            print(result.stdout)
            
            if "is running" in result.stdout and self.config:
                try:
                    dashboard_config = self.config.get('dashboard', {})
                    host = dashboard_config.get('host', '0.0.0.0')
                    port = dashboard_config.get('port', 8080)
                    
                    response = requests.get(f"http://localhost:{port}/api/status", timeout=2)
                    if response.ok:
                        status = response.json()
                        self._print_detailed_status(status)
                except:
                    pass
                    
        except Exception as e:
            print(f"Error checking status: {e}")
    
    def _print_detailed_status(self, status: Dict):
        print("\n═══ System Status ═══")
        print(f"Running: {status.get('is_running', False)}")
        
        if status.get('start_time'):
            start = datetime.fromisoformat(status['start_time'])
            uptime = datetime.now() - start
            hours = int(uptime.total_seconds() // 3600)
            minutes = int((uptime.total_seconds() % 3600) // 60)
            print(f"Uptime: {hours}h {minutes}m")
        
        if threads := status.get('threads'):
            print("\n═══ Thread Status ═══")
            thread_data = []
            for name, info in threads.items():
                thread_data.append([
                    name,
                    "Running" if info['alive'] else "Stopped",
                    info.get('errors', 0),
                    f"{info.get('uptime', 0):.0f}s"
                ])
            print(tabulate(thread_data, 
                         headers=['Thread', 'Status', 'Errors', 'Uptime'],
                         tablefmt='simple'))
        
        if components := status.get('components'):
            print("\n═══ Component Statistics ═══")
            if sniffer := components.get('packet_sniffer'):
                print(f"\nPacket Sniffer:")
                print(f"  Packets captured: {sniffer.get('packets_captured', 0):,}")
                print(f"  Packets/second: {sniffer.get('packets_per_second', 0):.1f}")
                print(f"  Queue size: {sniffer.get('queue_size', 0)}")
    
    def do_threats(self, arg):
        """List recent threats. Usage: threats [hours=24] [severity=all]"""
        args = self._parse_args(arg)
        hours = int(args.get('hours', 24))
        severity = args.get('severity')
        
        if not self.db_logger:
            print("Database not available")
            return
        
        start_time = datetime.now() - timedelta(hours=hours)
        threats = self.db_logger.get_threat_events(
            start_time=start_time,
            severity=severity,
            limit=50
        )
        
        if not threats:
            print(f"No threats found in the last {hours} hours")
            return
        
        print(f"\n═══ Threats (last {hours} hours) ═══\n")
        
        threat_data = []
        for threat in threats:
            threat_data.append([
                threat['timestamp'][:19],
                threat['type'].replace('_', ' ').title(),
                threat['severity'].upper(),
                f"{threat.get('score', 0):.0f}",
                threat.get('source_ip', 'N/A'),
                self._truncate(threat.get('url', threat.get('process_name', 'N/A')), 30)
            ])
        
        print(tabulate(threat_data,
                      headers=['Time', 'Type', 'Severity', 'Score', 'Source IP', 'Target'],
                      tablefmt='grid'))
    
    def do_stats(self, arg):
        """Show statistics. Usage: stats [hours=24]"""
        args = self._parse_args(arg)
        hours = int(args.get('hours', 24))
        
        if not self.db_logger:
            print("Database not available")
            return
        
        stats = self.db_logger.get_statistics(hours=hours)
        
        print(f"\n═══ Statistics (last {hours} hours) ═══\n")
        
        if threat_stats := stats.get('threat_stats'):
            print("Threat Summary:")
            print(f"  Total threats: {threat_stats.get('total_threats', 0)}")
            print(f"  Critical: {threat_stats.get('critical', 0)}")
            print(f"  High: {threat_stats.get('high', 0)}")
            print(f"  Medium: {threat_stats.get('medium', 0)}")
            print(f"  Low: {threat_stats.get('low', 0)}")
        
        if threat_types := stats.get('threat_types'):
            print("\nThreat Types:")
            for threat_type, count in threat_types.items():
                print(f"  {threat_type.replace('_', ' ').title()}: {count}")
        
        if network_stats := stats.get('network_stats'):
            print("\nNetwork Statistics:")
            print(f"  Avg packets: {network_stats.get('avg_packets', 0):,.0f}")
            print(f"  Avg bytes: {network_stats.get('avg_bytes', 0):,.0f}")
            print(f"  Max connections: {network_stats.get('max_connections', 0)}")
    
    def do_config(self, arg):
        """Show or edit configuration. Usage: config [show|edit|validate]"""
        if not arg or arg == 'show':
            self._show_config()
        elif arg == 'edit':
            self._edit_config()
        elif arg == 'validate':
            self._validate_config()
        else:
            print("Usage: config [show|edit|validate]")
    
    def _show_config(self):
        if not self.config:
            print("No configuration loaded")
            return
        
        config_copy = self.config.copy()
        if 'api_keys' in config_copy:
            config_copy['api_keys'] = {k: '***' for k in config_copy['api_keys']}
        
        print("\n═══ Current Configuration ═══\n")
        print(json.dumps(config_copy, indent=2))
    
    def _edit_config(self):
        editor = os.environ.get('EDITOR', 'nano')
        try:
            subprocess.call([editor, self.config_path])
            print("Configuration file edited. Run 'config validate' to check for errors.")
        except Exception as e:
            print(f"Error editing configuration: {e}")
    
    def _validate_config(self):
        try:
            parser = ConfigParser(self.config_path)
            parser.load()
            print("Configuration is valid")
        except Exception as e:
            print(f"Configuration error: {e}")
    
    def do_alert(self, arg):
        """Test alert system. Usage: alert test"""
        if arg != 'test':
            print("Usage: alert test")
            return
        
        print("Testing alert system...")
        
        test_event = {
            'id': 'test-' + datetime.now().strftime('%Y%m%d%H%M%S'),
            'timestamp': datetime.now(),
            'type': 'test_alert',
            'severity': 'medium',
            'score': 50,
            'details': {
                'message': 'This is a test alert from Soteria CLI'
            },
            'api_responses': {},
            'resolved': False
        }
        
        if self.db_logger:
            self.db_logger.log_threat_event(test_event)
            print("Test alert sent successfully")
        else:
            print("Database not available")
    
    def do_search(self, arg):
        """Search threat logs. Usage: search <query>"""
        if not arg:
            print("Usage: search <query>")
            return
        
        if not self.db_logger:
            print("Database not available")
            return
        
        threats = self.db_logger.get_threat_events(limit=100)
        
        results = []
        query = arg.lower()
        
        for threat in threats:
            if (query in str(threat).lower() or
                query in threat.get('source_ip', '').lower() or
                query in threat.get('url', '').lower() or
                query in threat.get('process_name', '').lower()):
                results.append(threat)
        
        if not results:
            print(f"No results found for '{arg}'")
            return
        
        print(f"\n═══ Search Results ({len(results)} found) ═══\n")
        
        for threat in results[:20]:
            print(f"ID: {threat['id']}")
            print(f"Time: {threat['timestamp']}")
            print(f"Type: {threat['type']} | Severity: {threat['severity']}")
            print(f"Score: {threat.get('score', 'N/A')}")
            if threat.get('source_ip'):
                print(f"Source: {threat['source_ip']}")
            if threat.get('url'):
                print(f"URL: {threat['url']}")
            if threat.get('process_name'):
                print(f"Process: {threat['process_name']}")
            print("-" * 50)
    
    def do_dashboard(self, arg):
        """Open web dashboard in browser"""
        if self.config:
            dashboard_config = self.config.get('dashboard', {})
            port = dashboard_config.get('port', 8080)
            url = f"http://localhost:{port}"
            
            try:
                import webbrowser
                webbrowser.open(url)
                print(f"Opening dashboard at {url}")
            except Exception as e:
                print(f"Error opening browser: {e}")
                print(f"Please open {url} manually")
    
    def do_export(self, arg):
        """Export threat data. Usage: export <filename.csv> [hours=24]"""
        parts = arg.split()
        if not parts:
            print("Usage: export <filename.csv> [hours=24]")
            return
        
        filename = parts[0]
        args = self._parse_args(' '.join(parts[1:]))
        hours = int(args.get('hours', 24))
        
        if not self.db_logger:
            print("Database not available")
            return
        
        start_time = datetime.now() - timedelta(hours=hours)
        threats = self.db_logger.get_threat_events(start_time=start_time, limit=10000)
        
        try:
            import csv
            with open(filename, 'w', newline='') as csvfile:
                if threats:
                    fieldnames = ['timestamp', 'type', 'severity', 'score', 
                                'source_ip', 'destination_ip', 'url', 'process_name']
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames, extrasaction='ignore')
                    writer.writeheader()
                    writer.writerows(threats)
                    print(f"Exported {len(threats)} threats to {filename}")
                else:
                    print("No threats to export")
        except Exception as e:
            print(f"Error exporting data: {e}")
    
    def do_clear(self, arg):
        """Clear the screen"""
        os.system('clear' if os.name == 'posix' else 'cls')
    
    def do_exit(self, arg):
        """Exit the CLI"""
        if self.db_logger:
            self.db_logger.stop()
        print("Goodbye!")
        return True
    
    def do_quit(self, arg):
        """Exit the CLI"""
        return self.do_exit(arg)
    
    def _parse_args(self, arg: str) -> Dict[str, str]:
        args = {}
        for pair in arg.split():
            if '=' in pair:
                key, value = pair.split('=', 1)
                args[key] = value
        return args
    
    def _truncate(self, text: str, length: int) -> str:
        if len(text) <= length:
            return text
        return text[:length-3] + '...'
    
    def execute(self, args: List[str]):
        """Execute a single command from command line arguments"""
        if args:
            line = ' '.join(args)
            self.onecmd(line)
    
    def interactive(self):
        """Start interactive mode"""
        self.cmdloop()