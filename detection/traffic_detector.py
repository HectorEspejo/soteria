import logging
import time
import os
from collections import defaultdict, deque
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta
import numpy as np
from scipy import stats
import uuid
import geoip2.database
import requests

from utils.api_clients import AbuseIPDBClient
from capture.sniffer import PacketData

logger = logging.getLogger(__name__)

class TrafficDetector:
    def __init__(self, config: Dict, db_logger, alert_manager):
        self.config = config.get('detection', {}).get('traffic', {})
        self.db_logger = db_logger
        self.alert_manager = alert_manager
        
        self.enabled = self.config.get('enabled', True)
        self.window_size = self.config.get('window_size', 300)
        self.min_packets = self.config.get('min_packets', 100)
        
        self.zscore_threshold = config.get('thresholds', {}).get('traffic_anomaly_zscore', 2.5)
        self.connection_rate_threshold = config.get('thresholds', {}).get('connection_rate_threshold', 100)
        self.packet_rate_threshold = config.get('thresholds', {}).get('packet_rate_threshold', 10000)
        
        api_keys = config.get('api_keys', {})
        self.abuseipdb_client = None
        if abuseipdb_key := api_keys.get('abuseipdb'):
            self.abuseipdb_client = AbuseIPDBClient(abuseipdb_key)
        
        self.geoip_reader = self._init_geoip()
        
        self.traffic_stats = defaultdict(lambda: {
            'packets': deque(maxlen=self.window_size),
            'bytes': deque(maxlen=self.window_size),
            'connections': defaultdict(set),
            'syn_packets': 0,
            'ack_packets': 0,
            'last_seen': time.time()
        })
        
        self.baseline_stats = {
            'packets_per_second': [],
            'bytes_per_second': [],
            'unique_destinations': []
        }
        
        self.stats = {
            'packets_analyzed': 0,
            'anomalies_detected': 0,
            'ddos_attempts': 0,
            'suspicious_connections': 0
        }
        
        self.is_running = True
        self._cleanup_interval = 60
        self._last_cleanup = time.time()
    
    def _init_geoip(self) -> Optional[geoip2.database.Reader]:
        try:
            geoip_path = 'data/GeoLite2-City.mmdb'
            if not os.path.exists(geoip_path):
                logger.info("Downloading GeoIP database...")
                self._download_geoip(geoip_path)
            
            return geoip2.database.Reader(geoip_path)
            
        except Exception as e:
            logger.warning(f"Failed to initialize GeoIP: {e}")
            return None
    
    def _download_geoip(self, path: str):
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            logger.info("GeoIP download would require MaxMind license key")
        except Exception as e:
            logger.error(f"Failed to download GeoIP database: {e}")
    
    def analyze(self, packets: List[PacketData]):
        if not self.enabled:
            return
        
        current_time = time.time()
        
        for packet in packets:
            self._update_traffic_stats(packet, current_time)
            self.stats['packets_analyzed'] += 1
        
        if current_time - self._last_cleanup > self._cleanup_interval:
            self._cleanup_old_stats(current_time)
            self._last_cleanup = current_time
        
        self._detect_anomalies(current_time)
    
    def _update_traffic_stats(self, packet: PacketData, current_time: float):
        if not packet.src_ip:
            return
        
        stats = self.traffic_stats[packet.src_ip]
        stats['packets'].append(current_time)
        stats['bytes'].append((current_time, packet.payload_size))
        stats['last_seen'] = current_time
        
        if packet.dst_ip and packet.dst_port:
            stats['connections'][packet.dst_ip].add(packet.dst_port)
        
        if 'SYN' in packet.flags and 'ACK' not in packet.flags:
            stats['syn_packets'] += 1
        elif 'ACK' in packet.flags:
            stats['ack_packets'] += 1
    
    def _cleanup_old_stats(self, current_time: float):
        stale_ips = []
        for ip, stats in self.traffic_stats.items():
            if current_time - stats['last_seen'] > self.window_size * 2:
                stale_ips.append(ip)
        
        for ip in stale_ips:
            del self.traffic_stats[ip]
    
    def _detect_anomalies(self, current_time: float):
        for ip, stats in self.traffic_stats.items():
            recent_packets = [t for t in stats['packets'] if current_time - t < 60]
            
            if len(recent_packets) < 10:
                continue
            
            self._detect_ddos(ip, stats, recent_packets)
            
            self._detect_port_scan(ip, stats)
            
            self._detect_statistical_anomaly(ip, stats, current_time)
            
            if self.abuseipdb_client:
                self._check_ip_reputation(ip, stats)
            
            if self.geoip_reader:
                self._check_geo_anomaly(ip, stats)
    
    def _detect_ddos(self, ip: str, stats: Dict, recent_packets: List[float]):
        packets_per_second = len(recent_packets) / 60.0
        
        if packets_per_second > self.packet_rate_threshold:
            self._create_threat_event(
                ip, 'ddos_attack', 80,
                [f"Excessive packet rate: {packets_per_second:.1f} pps"],
                {'packet_rate': packets_per_second}
            )
            self.stats['ddos_attempts'] += 1
            return
        
        syn_flood_ratio = stats['syn_packets'] / (stats['ack_packets'] + 1)
        if syn_flood_ratio > 10 and stats['syn_packets'] > 100:
            self._create_threat_event(
                ip, 'syn_flood', 90,
                [f"SYN flood detected: {stats['syn_packets']} SYN packets"],
                {'syn_packets': stats['syn_packets'], 'syn_ack_ratio': syn_flood_ratio}
            )
            self.stats['ddos_attempts'] += 1
    
    def _detect_port_scan(self, ip: str, stats: Dict):
        unique_ports = sum(len(ports) for ports in stats['connections'].values())
        unique_hosts = len(stats['connections'])
        
        if unique_ports > 50 and unique_hosts < 5:
            self._create_threat_event(
                ip, 'port_scan', 70,
                [f"Port scan detected: {unique_ports} ports on {unique_hosts} hosts"],
                {'ports_scanned': unique_ports, 'hosts_scanned': unique_hosts}
            )
            self.stats['suspicious_connections'] += 1
        
        elif unique_hosts > 100 and unique_ports < 5:
            self._create_threat_event(
                ip, 'network_scan', 70,
                [f"Network scan detected: {unique_hosts} hosts on {unique_ports} ports"],
                {'hosts_scanned': unique_hosts, 'ports_scanned': unique_ports}
            )
            self.stats['suspicious_connections'] += 1
    
    def _detect_statistical_anomaly(self, ip: str, ip_stats: Dict, current_time: float):
        recent_times = [t for t in ip_stats['packets'] if current_time - t < self.window_size]
        if len(recent_times) < self.min_packets:
            return
        
        intervals = np.diff(sorted(recent_times))
        if len(intervals) < 2:
            return
        
        mean_interval = np.mean(intervals)
        std_interval = np.std(intervals)
        
        if std_interval == 0:
            return
        
        zscore_values = np.abs(stats.zscore(intervals))
        max_zscore = np.max(zscore_values)
        
        if max_zscore > self.zscore_threshold:
            recent_bytes = sum(size for t, size in ip_stats['bytes'] if current_time - t < 60)
            bytes_per_second = recent_bytes / 60.0
            
            self._create_threat_event(
                ip, 'traffic_anomaly', 60,
                [f"Statistical anomaly detected: Z-score {max_zscore:.2f}"],
                {
                    'zscore': float(max_zscore),
                    'mean_interval': float(mean_interval),
                    'std_interval': float(std_interval),
                    'bytes_per_second': bytes_per_second
                }
            )
            self.stats['anomalies_detected'] += 1
    
    def _check_ip_reputation(self, ip: str, stats: Dict):
        try:
            result = self.abuseipdb_client.check_ip(ip)
            
            if not result.get('error') and result.get('malicious'):
                self._create_threat_event(
                    ip, 'malicious_ip', result.get('score', 70),
                    [f"Known malicious IP: {result.get('total_reports')} reports"],
                    {'abuseipdb': result}
                )
                self.stats['suspicious_connections'] += 1
                
        except Exception as e:
            logger.error(f"Failed to check IP reputation for {ip}: {e}")
    
    def _check_geo_anomaly(self, ip: str, stats: Dict):
        if not self.geoip_reader:
            return
        
        try:
            response = self.geoip_reader.city(ip)
            country = response.country.iso_code
            
            high_risk_countries = ['CN', 'RU', 'KP', 'IR']
            if country in high_risk_countries:
                connections = sum(len(ports) for ports in stats['connections'].values())
                if connections > 10:
                    self._create_threat_event(
                        ip, 'geo_anomaly', 50,
                        [f"Suspicious activity from high-risk country: {country}"],
                        {'country': country, 'connections': connections}
                    )
                    
        except Exception as e:
            logger.debug(f"GeoIP lookup failed for {ip}: {e}")
    
    def _create_threat_event(self, ip: str, threat_type: str, score: float,
                           reasons: List[str], details: Dict[str, Any]):
        threat_event = {
            'id': str(uuid.uuid4()),
            'timestamp': datetime.now(),
            'type': threat_type,
            'severity': self._get_severity(score),
            'score': score,
            'source_ip': ip,
            'details': {
                'reasons': reasons,
                **details
            },
            'api_responses': {},
            'resolved': False
        }
        
        self.db_logger.log_threat_event(threat_event)
        self.alert_manager.send_alert(threat_event)
        
        logger.warning(f"Traffic anomaly detected from {ip}: {threat_type} (score: {score})")
    
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
        if self.geoip_reader:
            self.geoip_reader.close()
    
    def update_config(self, config: Dict):
        self.config = config.get('detection', {}).get('traffic', {})
        self.window_size = self.config.get('window_size', 300)
        self.min_packets = self.config.get('min_packets', 100)
        self.zscore_threshold = config.get('thresholds', {}).get('traffic_anomaly_zscore', 2.5)
        self.connection_rate_threshold = config.get('thresholds', {}).get('connection_rate_threshold', 100)
        self.packet_rate_threshold = config.get('thresholds', {}).get('packet_rate_threshold', 10000)
    
    def get_stats(self) -> Dict[str, Any]:
        active_ips = len(self.traffic_stats)
        total_connections = sum(
            len(stats['connections']) for stats in self.traffic_stats.values()
        )
        
        return {
            **self.stats,
            'active_ips': active_ips,
            'total_connections': total_connections
        }