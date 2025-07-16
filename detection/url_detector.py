import logging
import re
import socket
import ssl
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from urllib.parse import urlparse
import uuid
import whois
import dns.resolver

from utils.api_clients import VirusTotalClient, GoogleSafeBrowsingClient
from capture.sniffer import PacketData

logger = logging.getLogger(__name__)

class URLDetector:
    def __init__(self, config: Dict, db_logger, alert_manager):
        self.config = config.get('detection', {}).get('url', {})
        self.db_logger = db_logger
        self.alert_manager = alert_manager
        
        self.enabled = self.config.get('enabled', True)
        self.whitelist = self._compile_patterns(self.config.get('whitelist', []))
        self.blacklist = self._compile_patterns(self.config.get('blacklist', []))
        self.threat_threshold = config.get('thresholds', {}).get('url_threat_score', 70)
        
        api_keys = config.get('api_keys', {})
        self.vt_client = None
        self.gsb_client = None
        
        if vt_key := api_keys.get('virustotal'):
            self.vt_client = VirusTotalClient(vt_key)
        
        if gsb_key := api_keys.get('google_safe_browsing'):
            self.gsb_client = GoogleSafeBrowsingClient(gsb_key)
        
        self.stats = {
            'urls_analyzed': 0,
            'threats_detected': 0,
            'api_errors': 0
        }
        
        self.is_running = True
    
    def _compile_patterns(self, patterns: List[str]) -> List[re.Pattern]:
        compiled = []
        for pattern in patterns:
            try:
                regex = pattern.replace('*', '.*')
                compiled.append(re.compile(regex, re.IGNORECASE))
            except re.error as e:
                logger.error(f"Invalid pattern '{pattern}': {e}")
        return compiled
    
    def analyze(self, packets: List[PacketData]):
        if not self.enabled:
            return
        
        urls_to_check = set()
        
        for packet in packets:
            if packet.url:
                urls_to_check.add((packet.url, packet))
            elif packet.dns_query:
                urls_to_check.add((f"http://{packet.dns_query}", packet))
            elif packet.sni:
                urls_to_check.add((f"https://{packet.sni}", packet))
        
        for url, packet in urls_to_check:
            try:
                self._analyze_url(url, packet)
                self.stats['urls_analyzed'] += 1
            except Exception as e:
                logger.error(f"Error analyzing URL {url}: {e}")
                self.stats['api_errors'] += 1
    
    def _analyze_url(self, url: str, packet: PacketData):
        if self._is_whitelisted(url):
            logger.debug(f"URL {url} is whitelisted")
            return
        
        threat_score = 0
        threat_reasons = []
        api_responses = {}
        
        if self._is_blacklisted(url):
            threat_score = 100
            threat_reasons.append("URL matches blacklist")
        
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path
        
        domain_analysis = self._analyze_domain(domain)
        if domain_analysis['suspicious']:
            threat_score = max(threat_score, domain_analysis['score'])
            threat_reasons.extend(domain_analysis['reasons'])
        
        ssl_analysis = self._check_ssl_validity(domain)
        if ssl_analysis and not ssl_analysis['valid']:
            threat_score = max(threat_score, 50)
            threat_reasons.append(f"SSL issue: {ssl_analysis['reason']}")
        
        if self.vt_client:
            vt_result = self.vt_client.scan_url(url)
            api_responses['virustotal'] = vt_result
            if not vt_result.get('error'):
                vt_score = vt_result.get('score', 0)
                if vt_score > 0:
                    threat_score = max(threat_score, vt_score)
                    threat_reasons.append(f"VirusTotal: {vt_result.get('detections')}")
        
        if self.gsb_client:
            gsb_result = self.gsb_client.check_url(url)
            api_responses['google_safe_browsing'] = gsb_result
            if not gsb_result.get('error') and gsb_result.get('malicious'):
                threat_score = max(threat_score, gsb_result.get('score', 80))
                threat_reasons.append(f"Google Safe Browsing: {', '.join(gsb_result.get('threat_types', []))}")
        
        if threat_score >= self.threat_threshold:
            self._create_threat_event(url, packet, threat_score, threat_reasons, api_responses)
    
    def _is_whitelisted(self, url: str) -> bool:
        for pattern in self.whitelist:
            if pattern.match(url):
                return True
        return False
    
    def _is_blacklisted(self, url: str) -> bool:
        for pattern in self.blacklist:
            if pattern.match(url):
                return True
        return False
    
    def _analyze_domain(self, domain: str) -> Dict[str, Any]:
        result = {
            'suspicious': False,
            'score': 0,
            'reasons': []
        }
        
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain):
            result['suspicious'] = True
            result['score'] = 30
            result['reasons'].append("Direct IP access")
            return result
        
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.top', '.click', '.download']
        for tld in suspicious_tlds:
            if domain.endswith(tld):
                result['suspicious'] = True
                result['score'] = 40
                result['reasons'].append(f"Suspicious TLD: {tld}")
        
        if len(domain.split('.')) > 4:
            result['suspicious'] = True
            result['score'] = max(result['score'], 30)
            result['reasons'].append("Excessive subdomains")
        
        if re.search(r'[0-9]{4,}', domain):
            result['suspicious'] = True
            result['score'] = max(result['score'], 25)
            result['reasons'].append("Long number sequence in domain")
        
        lookalike_chars = {'0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's'}
        common_domains = ['google', 'facebook', 'amazon', 'microsoft', 'apple', 'paypal']
        for common in common_domains:
            for char, replacement in lookalike_chars.items():
                if common.replace(replacement, char) in domain:
                    result['suspicious'] = True
                    result['score'] = max(result['score'], 70)
                    result['reasons'].append(f"Possible {common} lookalike")
        
        try:
            domain_info = whois.whois(domain)
            if domain_info.creation_date:
                if isinstance(domain_info.creation_date, list):
                    creation_date = domain_info.creation_date[0]
                else:
                    creation_date = domain_info.creation_date
                
                age_days = (datetime.now() - creation_date).days
                if age_days < 30:
                    result['suspicious'] = True
                    result['score'] = max(result['score'], 50)
                    result['reasons'].append(f"Newly registered domain ({age_days} days old)")
        except:
            pass
        
        return result
    
    def _check_ssl_validity(self, domain: str) -> Optional[Dict[str, Any]]:
        if not domain or domain.startswith('http://'):
            return None
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    if not_after < datetime.now():
                        return {'valid': False, 'reason': 'Certificate expired'}
                    
                    san = cert.get('subjectAltName', [])
                    valid_names = [name[1] for name in san if name[0] == 'DNS']
                    
                    if not any(self._match_hostname(domain, name) for name in valid_names):
                        return {'valid': False, 'reason': 'Hostname mismatch'}
                    
                    return {'valid': True}
                    
        except ssl.SSLError as e:
            return {'valid': False, 'reason': f'SSL error: {str(e)}'}
        except Exception as e:
            logger.debug(f"SSL check failed for {domain}: {e}")
            return None
    
    def _match_hostname(self, hostname: str, pattern: str) -> bool:
        if pattern.startswith('*.'):
            return hostname.endswith(pattern[1:]) or hostname == pattern[2:]
        return hostname == pattern
    
    def _create_threat_event(self, url: str, packet: PacketData, 
                           score: float, reasons: List[str], api_responses: Dict):
        threat_event = {
            'id': str(uuid.uuid4()),
            'timestamp': packet.timestamp,
            'type': 'malicious_url',
            'severity': self._get_severity(score),
            'score': score,
            'source_ip': packet.src_ip,
            'destination_ip': packet.dst_ip,
            'port': packet.dst_port,
            'protocol': packet.protocol,
            'url': url,
            'details': {
                'reasons': reasons,
                'packet_flags': packet.flags
            },
            'api_responses': api_responses,
            'resolved': False
        }
        
        self.db_logger.log_threat_event(threat_event)
        self.alert_manager.send_alert(threat_event)
        self.stats['threats_detected'] += 1
        
        logger.warning(f"Malicious URL detected: {url} (score: {score})")
    
    def _get_severity(self, score: float) -> str:
        if score >= 90:
            return 'critical'
        elif score >= 70:
            return 'high'
        elif score >= 50:
            return 'medium'
        else:
            return 'low'
    
    def stop(self):
        self.is_running = False
    
    def update_config(self, config: Dict):
        self.config = config.get('detection', {}).get('url', {})
        self.whitelist = self._compile_patterns(self.config.get('whitelist', []))
        self.blacklist = self._compile_patterns(self.config.get('blacklist', []))
        self.threat_threshold = config.get('thresholds', {}).get('url_threat_score', 70)
    
    def get_stats(self) -> Dict[str, Any]:
        return self.stats.copy()