import yaml
import os
import logging
from typing import Dict, Any, Optional
from pathlib import Path
import json

logger = logging.getLogger(__name__)

class ConfigParser:
    def __init__(self, config_path: str):
        self.config_path = Path(config_path)
        self.config = {}
        self._defaults = self._get_defaults()
    
    def load(self) -> Dict[str, Any]:
        if not self.config_path.exists():
            logger.warning(f"Configuration file not found: {self.config_path}")
            logger.info("Creating default configuration...")
            self._create_default_config()
        
        try:
            with open(self.config_path, 'r') as f:
                self.config = yaml.safe_load(f)
            
            self._validate_config()
            self._merge_with_defaults()
            self._process_env_vars()
            
            logger.info("Configuration loaded successfully")
            return self.config
            
        except yaml.YAMLError as e:
            logger.error(f"Failed to parse YAML configuration: {e}")
            raise
        except Exception as e:
            logger.error(f"Failed to load configuration: {e}")
            raise
    
    def _get_defaults(self) -> Dict[str, Any]:
        return {
            'interfaces': ['eth0'],
            'api_keys': {
                'virustotal': '',
                'abuseipdb': '',
                'google_safe_browsing': ''
            },
            'thresholds': {
                'url_threat_score': 70,
                'traffic_anomaly_zscore': 2.5,
                'process_cpu_threshold': 80,
                'process_memory_threshold': 80,
                'connection_rate_threshold': 100,
                'packet_rate_threshold': 10000
            },
            'alerting': {
                'email': {
                    'enabled': False,
                    'smtp_server': 'smtp.gmail.com',
                    'smtp_port': 587,
                    'username': '',
                    'password': '',
                    'recipients': []
                },
                'slack': {
                    'enabled': False,
                    'webhook_url': ''
                },
                'sms': {
                    'enabled': False,
                    'twilio_sid': '',
                    'twilio_token': '',
                    'from_number': '',
                    'to_numbers': []
                }
            },
            'logging': {
                'database': 'logs/soteria.db',
                'max_log_size': '100MB',
                'retention_days': 30,
                'log_level': 'INFO'
            },
            'dashboard': {
                'host': '0.0.0.0',
                'port': 8080,
                'debug': False,
                'secret_key': None,
                'ssl_cert': None,
                'ssl_key': None
            },
            'detection': {
                'url': {
                    'enabled': True,
                    'whitelist': [],
                    'blacklist': [],
                    'cache_ttl': 3600
                },
                'program': {
                    'enabled': True,
                    'scan_interval': 60,
                    'yara_rules_path': 'rules/yara',
                    'process_whitelist': []
                },
                'traffic': {
                    'enabled': True,
                    'window_size': 300,
                    'min_packets': 100
                }
            },
            'performance': {
                'packet_sampling_rate': 1.0,
                'max_packet_queue_size': 10000,
                'worker_threads': 4
            }
        }
    
    def _create_default_config(self):
        os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
        
        default_config = self._defaults.copy()
        default_config['api_keys']['virustotal'] = 'YOUR_VIRUSTOTAL_API_KEY'
        default_config['api_keys']['abuseipdb'] = 'YOUR_ABUSEIPDB_API_KEY'
        default_config['api_keys']['google_safe_browsing'] = 'YOUR_GOOGLE_SAFE_BROWSING_API_KEY'
        
        with open(self.config_path, 'w') as f:
            yaml.dump(default_config, f, default_flow_style=False, sort_keys=False)
        
        logger.info(f"Created default configuration at {self.config_path}")
    
    def _validate_config(self):
        required_sections = ['interfaces', 'api_keys', 'thresholds', 'alerting', 'logging', 'dashboard']
        
        for section in required_sections:
            if section not in self.config:
                raise ValueError(f"Missing required configuration section: {section}")
        
        if not self.config.get('interfaces'):
            raise ValueError("At least one network interface must be specified")
        
        thresholds = self.config.get('thresholds', {})
        if thresholds.get('url_threat_score', 0) < 0 or thresholds.get('url_threat_score', 0) > 100:
            raise ValueError("url_threat_score must be between 0 and 100")
        
        dashboard = self.config.get('dashboard', {})
        if dashboard.get('port', 8080) < 1 or dashboard.get('port', 8080) > 65535:
            raise ValueError("Dashboard port must be between 1 and 65535")
    
    def _merge_with_defaults(self):
        def deep_merge(base: Dict, update: Dict) -> Dict:
            for key, value in update.items():
                if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                    base[key] = deep_merge(base[key], value)
                else:
                    base[key] = value
            return base
        
        self.config = deep_merge(self._defaults.copy(), self.config)
    
    def _process_env_vars(self):
        env_mappings = {
            'SOTERIA_VT_API_KEY': ['api_keys', 'virustotal'],
            'SOTERIA_ABUSEIPDB_API_KEY': ['api_keys', 'abuseipdb'],
            'SOTERIA_GSB_API_KEY': ['api_keys', 'google_safe_browsing'],
            'SOTERIA_EMAIL_USERNAME': ['alerting', 'email', 'username'],
            'SOTERIA_EMAIL_PASSWORD': ['alerting', 'email', 'password'],
            'SOTERIA_SLACK_WEBHOOK': ['alerting', 'slack', 'webhook_url'],
            'SOTERIA_TWILIO_SID': ['alerting', 'sms', 'twilio_sid'],
            'SOTERIA_TWILIO_TOKEN': ['alerting', 'sms', 'twilio_token'],
            'SOTERIA_DASHBOARD_SECRET': ['dashboard', 'secret_key']
        }
        
        for env_var, config_path in env_mappings.items():
            value = os.environ.get(env_var)
            if value:
                self._set_nested_value(self.config, config_path, value)
                logger.debug(f"Loaded {env_var} from environment")
    
    def _set_nested_value(self, d: Dict, path: list, value: Any):
        for key in path[:-1]:
            d = d.setdefault(key, {})
        d[path[-1]] = value
    
    def save(self, path: Optional[str] = None):
        save_path = path or self.config_path
        
        try:
            with open(save_path, 'w') as f:
                yaml.dump(self.config, f, default_flow_style=False, sort_keys=False)
            logger.info(f"Configuration saved to {save_path}")
        except Exception as e:
            logger.error(f"Failed to save configuration: {e}")
            raise
    
    def get(self, *path: str, default: Any = None) -> Any:
        value = self.config
        for key in path:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default
        return value