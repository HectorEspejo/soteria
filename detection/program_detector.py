import logging
import psutil
import os
import time
import hashlib
import yara
import threading
import re
from typing import Dict, List, Optional, Any, Set
from datetime import datetime
import uuid
import subprocess

from utils.api_clients import VirusTotalClient, get_file_hash

logger = logging.getLogger(__name__)

class ProgramDetector:
    def __init__(self, config: Dict, db_logger, alert_manager):
        self.config = config.get('detection', {}).get('program', {})
        self.db_logger = db_logger
        self.alert_manager = alert_manager
        
        self.enabled = self.config.get('enabled', True)
        self.scan_interval = self.config.get('scan_interval', 60)
        self.process_whitelist = set(self.config.get('process_whitelist', []))
        self.yara_rules_path = self.config.get('yara_rules_path', 'rules/yara')
        
        self.cpu_threshold = config.get('thresholds', {}).get('process_cpu_threshold', 80)
        self.memory_threshold = config.get('thresholds', {}).get('process_memory_threshold', 80)
        
        api_keys = config.get('api_keys', {})
        self.vt_client = None
        if vt_key := api_keys.get('virustotal'):
            self.vt_client = VirusTotalClient(vt_key)
        
        self.yara_rules = self._load_yara_rules()
        
        self.stats = {
            'processes_scanned': 0,
            'threats_detected': 0,
            'yara_matches': 0,
            'behavior_anomalies': 0
        }
        
        self.is_running = True
        self.process_history = {}
        self.suspicious_processes = set()
        
        self._scan_thread = None
    
    def _load_yara_rules(self) -> Optional[yara.Rules]:
        if not os.path.exists(self.yara_rules_path):
            os.makedirs(self.yara_rules_path, exist_ok=True)
            self._create_default_rules()
        
        try:
            rule_files = []
            for filename in os.listdir(self.yara_rules_path):
                if filename.endswith('.yar') or filename.endswith('.yara'):
                    filepath = os.path.join(self.yara_rules_path, filename)
                    rule_files.append(filepath)
            
            if rule_files:
                return yara.compile(filepaths={
                    os.path.basename(f): f for f in rule_files
                })
            else:
                logger.warning("No YARA rules found")
                return None
                
        except Exception as e:
            logger.error(f"Failed to load YARA rules: {e}")
            return None
    
    def _create_default_rules(self):
        default_rule = """
rule suspicious_process_behavior
{
    meta:
        description = "Detects suspicious process behavior patterns"
        author = "Soteria IDS"
        
    strings:
        $s1 = "netcat" nocase
        $s2 = "nc.exe" nocase
        $s3 = "mimikatz" nocase
        $s4 = "procdump" nocase
        $s5 = "pwdump" nocase
        $s6 = "metasploit" nocase
        
    condition:
        any of them
}

rule crypto_miner
{
    meta:
        description = "Detects cryptocurrency mining indicators"
        
    strings:
        $s1 = "stratum+tcp://" nocase
        $s2 = "xmrig" nocase
        $s3 = "monero" nocase
        $s4 = "nicehash" nocase
        
    condition:
        any of them
}
"""
        
        try:
            with open(os.path.join(self.yara_rules_path, 'default.yara'), 'w') as f:
                f.write(default_rule)
            logger.info("Created default YARA rules")
        except Exception as e:
            logger.error(f"Failed to create default YARA rules: {e}")
    
    def start_monitoring(self):
        if not self.enabled:
            return
        
        self._scan_thread = threading.Thread(
            target=self._monitoring_loop,
            daemon=True
        )
        self._scan_thread.start()
        logger.info("Process monitoring started")
    
    def _monitoring_loop(self):
        while self.is_running:
            try:
                self._scan_processes()
                time.sleep(self.scan_interval)
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                time.sleep(self.scan_interval)
    
    def _scan_processes(self):
        current_pids = set()
        
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 
                                       'create_time', 'cpu_percent', 
                                       'memory_percent']):
            try:
                if not self.is_running:
                    break
                
                info = proc.info
                pid = info['pid']
                name = info['name']
                
                if name in self.process_whitelist:
                    continue
                
                current_pids.add(pid)
                
                if pid not in self.process_history:
                    self._analyze_new_process(proc, info)
                
                self._monitor_process_behavior(proc, info)
                
                self.stats['processes_scanned'] += 1
                
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            except Exception as e:
                logger.error(f"Error scanning process {pid}: {e}")
        
        terminated_pids = set(self.process_history.keys()) - current_pids
        for pid in terminated_pids:
            del self.process_history[pid]
    
    def _analyze_new_process(self, proc: psutil.Process, info: Dict):
        pid = info['pid']
        self.process_history[pid] = {
            'name': info['name'],
            'exe': info['exe'],
            'create_time': info['create_time'],
            'first_seen': datetime.now(),
            'cpu_history': [],
            'memory_history': []
        }
        
        threat_score = 0
        threat_reasons = []
        api_responses = {}
        
        if info['exe'] and os.path.exists(info['exe']):
            file_analysis = self._analyze_executable(info['exe'])
            if file_analysis['suspicious']:
                threat_score = max(threat_score, file_analysis['score'])
                threat_reasons.extend(file_analysis['reasons'])
                if file_analysis.get('api_response'):
                    api_responses['virustotal'] = file_analysis['api_response']
        
        suspicious_patterns = [
            ('powershell.*-enc', 50, 'Encoded PowerShell command'),
            ('cmd.*\/c.*&', 40, 'Chained command execution'),
            ('wmic.*process.*call.*create', 60, 'WMI process creation'),
            ('schtasks.*\/create', 40, 'Scheduled task creation'),
            ('reg.*add.*CurrentVersion\\\\Run', 50, 'Registry persistence'),
        ]
        
        cmdline = ' '.join(info.get('cmdline', []))
        for pattern, score, reason in suspicious_patterns:
            if re.search(pattern, cmdline, re.IGNORECASE):
                threat_score = max(threat_score, score)
                threat_reasons.append(reason)
        
        try:
            parent = proc.parent()
            if parent:
                parent_name = parent.name()
                suspicious_parents = {
                    'winword.exe': ('explorer.exe', 'outlook.exe'),
                    'excel.exe': ('explorer.exe', 'outlook.exe'),
                    'powershell.exe': ('explorer.exe', 'cmd.exe'),
                }
                
                if info['name'] in suspicious_parents:
                    expected_parents = suspicious_parents[info['name']]
                    if parent_name not in expected_parents:
                        threat_score = max(threat_score, 60)
                        threat_reasons.append(f"Suspicious parent process: {parent_name}")
        except:
            pass
        
        if threat_score >= 50:
            self._create_threat_event(proc, info, threat_score, threat_reasons, api_responses)
    
    def _analyze_executable(self, exe_path: str) -> Dict[str, Any]:
        result = {
            'suspicious': False,
            'score': 0,
            'reasons': [],
            'api_response': None
        }
        
        try:
            if self.yara_rules:
                matches = self.yara_rules.match(exe_path)
                if matches:
                    result['suspicious'] = True
                    result['score'] = 70
                    result['reasons'].append(f"YARA match: {', '.join([m.rule for m in matches])}")
                    self.stats['yara_matches'] += 1
            
            if self.vt_client and os.path.getsize(exe_path) < 32 * 1024 * 1024:
                file_hash = get_file_hash(exe_path)
                vt_result = self.vt_client.scan_file_hash(file_hash)
                
                if not vt_result.get('error'):
                    result['api_response'] = vt_result
                    if vt_result.get('malicious'):
                        result['suspicious'] = True
                        result['score'] = max(result['score'], vt_result.get('score', 80))
                        result['reasons'].append(f"VirusTotal: {vt_result.get('detections')}")
            
            file_stat = os.stat(exe_path)
            if file_stat.st_mode & 0o111 == 0:
                result['suspicious'] = True
                result['score'] = max(result['score'], 30)
                result['reasons'].append("Non-executable file being executed")
            
            suspicious_locations = ['/tmp/', '/var/tmp/', '/dev/shm/']
            for location in suspicious_locations:
                if exe_path.startswith(location):
                    result['suspicious'] = True
                    result['score'] = max(result['score'], 50)
                    result['reasons'].append(f"Executed from suspicious location: {location}")
            
        except Exception as e:
            logger.error(f"Error analyzing executable {exe_path}: {e}")
        
        return result
    
    def _monitor_process_behavior(self, proc: psutil.Process, info: Dict):
        pid = info['pid']
        history = self.process_history.get(pid)
        if not history:
            return
        
        cpu_percent = info.get('cpu_percent', 0)
        memory_percent = info.get('memory_percent', 0)
        
        history['cpu_history'].append(cpu_percent)
        history['memory_history'].append(memory_percent)
        
        if len(history['cpu_history']) > 10:
            history['cpu_history'].pop(0)
            history['memory_history'].pop(0)
        
        threat_score = 0
        threat_reasons = []
        
        avg_cpu = sum(history['cpu_history']) / len(history['cpu_history'])
        if avg_cpu > self.cpu_threshold:
            threat_score = 60
            threat_reasons.append(f"High CPU usage: {avg_cpu:.1f}%")
        
        avg_memory = sum(history['memory_history']) / len(history['memory_history'])
        if avg_memory > self.memory_threshold:
            threat_score = max(threat_score, 50)
            threat_reasons.append(f"High memory usage: {avg_memory:.1f}%")
        
        if info['name'] not in ['chrome', 'firefox', 'edge'] and cpu_percent > 90:
            if self._is_crypto_miner(proc):
                threat_score = 80
                threat_reasons.append("Possible cryptocurrency miner")
        
        try:
            connections = proc.connections()
            suspicious_ports = [22, 23, 445, 3389, 4444, 5555, 6666, 7777, 8888, 9999]
            
            for conn in connections:
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    if conn.raddr.port in suspicious_ports:
                        threat_score = max(threat_score, 70)
                        threat_reasons.append(f"Connection to suspicious port: {conn.raddr.port}")
        except:
            pass
        
        if threat_score >= 50 and pid not in self.suspicious_processes:
            self.suspicious_processes.add(pid)
            self._create_threat_event(proc, info, threat_score, threat_reasons, {})
            self.stats['behavior_anomalies'] += 1
    
    def _is_crypto_miner(self, proc: psutil.Process) -> bool:
        try:
            cmdline = ' '.join(proc.cmdline())
            miner_indicators = ['stratum', 'pool.', 'mining', 'xmrig', 'nicehash']
            
            for indicator in miner_indicators:
                if indicator in cmdline.lower():
                    return True
            
            connections = proc.connections()
            for conn in connections:
                if conn.raddr and conn.raddr.port in [3333, 4444, 5555, 8333, 14444]:
                    return True
        except:
            pass
        
        return False
    
    def _create_threat_event(self, proc: psutil.Process, info: Dict, 
                           score: float, reasons: List[str], api_responses: Dict):
        threat_event = {
            'id': str(uuid.uuid4()),
            'timestamp': datetime.now(),
            'type': 'suspicious_process',
            'severity': self._get_severity(score),
            'score': score,
            'process_name': info['name'],
            'details': {
                'pid': info['pid'],
                'exe': info['exe'],
                'cmdline': ' '.join(info.get('cmdline', [])),
                'create_time': datetime.fromtimestamp(info['create_time']).isoformat(),
                'reasons': reasons
            },
            'api_responses': api_responses,
            'resolved': False
        }
        
        self.db_logger.log_threat_event(threat_event)
        self.alert_manager.send_alert(threat_event)
        self.stats['threats_detected'] += 1
        
        logger.warning(f"Suspicious process detected: {info['name']} (PID: {info['pid']}, score: {score})")
    
    def _get_severity(self, score: float) -> str:
        if score >= 80:
            return 'critical'
        elif score >= 60:
            return 'high'
        elif score >= 40:
            return 'medium'
        else:
            return 'low'
    
    def stop(self):
        self.is_running = False
        if self._scan_thread:
            self._scan_thread.join(timeout=5)
    
    def update_config(self, config: Dict):
        self.config = config.get('detection', {}).get('program', {})
        self.scan_interval = self.config.get('scan_interval', 60)
        self.process_whitelist = set(self.config.get('process_whitelist', []))
        self.cpu_threshold = config.get('thresholds', {}).get('process_cpu_threshold', 80)
        self.memory_threshold = config.get('thresholds', {}).get('process_memory_threshold', 80)
    
    def get_stats(self) -> Dict[str, Any]:
        return self.stats.copy()