import logging
import threading
import time
from typing import Dict, List, Optional
from datetime import datetime
import os

from config.config_parser import ConfigParser
from core.thread_manager import ThreadManager
from capture.sniffer import PacketSniffer
from detection.url_detector import URLDetector
from detection.program_detector import ProgramDetector
from detection.traffic_detector import TrafficDetector
from logs_management.database import DatabaseLogger
from logs_management.alerting import AlertManager
from ui.dashboard import DashboardServer

logger = logging.getLogger(__name__)

class SoteriaEngine:
    def __init__(self, config_path: str):
        self.config_path = config_path
        self.config = None
        self.is_running = False
        self.start_time = None
        
        self.thread_manager = ThreadManager()
        
        self.packet_sniffer = None
        self.url_detector = None
        self.program_detector = None
        self.traffic_detector = None
        self.db_logger = None
        self.alert_manager = None
        self.dashboard_server = None
        
        self._load_config()
        self._initialize_components()
    
    def _load_config(self):
        try:
            parser = ConfigParser(self.config_path)
            self.config = parser.load()
            logger.info(f"Configuration loaded from {self.config_path}")
        except Exception as e:
            logger.error(f"Failed to load configuration: {e}")
            raise
    
    def _initialize_components(self):
        try:
            self.db_logger = DatabaseLogger(self.config.get('logging', {}).get('database', 'logs/soteria.db'))
            
            self.alert_manager = AlertManager(
                self.config.get('alerting', {}),
                self.config.get('api_keys', {})
            )
            
            self.packet_sniffer = PacketSniffer(
                interfaces=self.config.get('interfaces', ['eth0']),
                config=self.config
            )
            
            self.url_detector = URLDetector(
                config=self.config,
                db_logger=self.db_logger,
                alert_manager=self.alert_manager
            )
            
            self.program_detector = ProgramDetector(
                config=self.config,
                db_logger=self.db_logger,
                alert_manager=self.alert_manager
            )
            
            self.traffic_detector = TrafficDetector(
                config=self.config,
                db_logger=self.db_logger,
                alert_manager=self.alert_manager
            )
            
            dashboard_config = self.config.get('dashboard', {})
            self.dashboard_server = DashboardServer(
                host=dashboard_config.get('host', '0.0.0.0'),
                port=dashboard_config.get('port', 8080),
                debug=dashboard_config.get('debug', False),
                db_logger=self.db_logger,
                engine=self
            )
            
            logger.info("All components initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize components: {e}")
            raise
    
    def start(self):
        if self.is_running:
            logger.warning("Engine is already running")
            return
        
        try:
            logger.info("Starting Soteria IDS engine...")
            self.start_time = datetime.now()
            self.is_running = True
            
            self.db_logger.start()
            
            self.thread_manager.start_thread(
                "packet_sniffer",
                self.packet_sniffer.start,
                daemon=True
            )
            
            self.thread_manager.start_thread(
                "url_detector",
                self._run_detector_loop,
                args=(self.url_detector, self.packet_sniffer),
                daemon=True
            )
            
            self.thread_manager.start_thread(
                "program_detector",
                self.program_detector.start_monitoring,
                daemon=True
            )
            
            self.thread_manager.start_thread(
                "traffic_detector",
                self._run_detector_loop,
                args=(self.traffic_detector, self.packet_sniffer),
                daemon=True
            )
            
            self.thread_manager.start_thread(
                "alert_manager",
                self.alert_manager.start_processing,
                daemon=True
            )
            
            self.thread_manager.start_thread(
                "dashboard_server",
                self.dashboard_server.start,
                daemon=True
            )
            
            self._drop_privileges()
            
            logger.info("Soteria IDS engine started successfully")
            
        except Exception as e:
            logger.error(f"Failed to start engine: {e}")
            self.stop()
            raise
    
    def stop(self):
        if not self.is_running:
            return
        
        logger.info("Stopping Soteria IDS engine...")
        self.is_running = False
        
        if self.packet_sniffer:
            self.packet_sniffer.stop()
        
        if self.url_detector:
            self.url_detector.stop()
        
        if self.program_detector:
            self.program_detector.stop()
        
        if self.traffic_detector:
            self.traffic_detector.stop()
        
        if self.alert_manager:
            self.alert_manager.stop()
        
        if self.dashboard_server:
            self.dashboard_server.stop()
        
        self.thread_manager.stop_all()
        
        if self.db_logger:
            self.db_logger.stop()
        
        logger.info("Soteria IDS engine stopped")
    
    def reload_config(self):
        logger.info("Reloading configuration...")
        try:
            old_config = self.config
            self._load_config()
            
            if self.alert_manager:
                self.alert_manager.update_config(self.config.get('alerting', {}))
            
            if self.url_detector:
                self.url_detector.update_config(self.config)
            
            if self.program_detector:
                self.program_detector.update_config(self.config)
            
            if self.traffic_detector:
                self.traffic_detector.update_config(self.config)
            
            logger.info("Configuration reloaded successfully")
            
        except Exception as e:
            logger.error(f"Failed to reload configuration: {e}")
            self.config = old_config
    
    def get_status(self) -> Dict:
        uptime = None
        if self.start_time:
            uptime = (datetime.now() - self.start_time).total_seconds()
        
        return {
            'is_running': self.is_running,
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'uptime_seconds': uptime,
            'threads': self.thread_manager.get_status(),
            'components': {
                'packet_sniffer': self.packet_sniffer.get_stats() if self.packet_sniffer else None,
                'url_detector': self.url_detector.get_stats() if self.url_detector else None,
                'program_detector': self.program_detector.get_stats() if self.program_detector else None,
                'traffic_detector': self.traffic_detector.get_stats() if self.traffic_detector else None,
                'alert_manager': self.alert_manager.get_stats() if self.alert_manager else None,
            }
        }
    
    def _run_detector_loop(self, detector, packet_source):
        while self.is_running:
            try:
                packets = packet_source.get_packets(timeout=1.0)
                if packets:
                    detector.analyze(packets)
            except Exception as e:
                logger.error(f"Error in detector loop: {e}")
                time.sleep(1)
    
    def _drop_privileges(self):
        if os.geteuid() != 0:
            return
        
        try:
            import pwd
            import grp
            
            nobody_user = pwd.getpwnam('nobody')
            nobody_group = grp.getgrnam('nogroup')
            
            os.setgroups([])
            os.setgid(nobody_group.gr_gid)
            os.setuid(nobody_user.pw_uid)
            
            logger.info("Dropped root privileges")
            
        except Exception as e:
            logger.warning(f"Failed to drop privileges: {e}")