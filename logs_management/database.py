import sqlite3
import logging
import threading
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import json
import queue

logger = logging.getLogger(__name__)

class DatabaseLogger:
    def __init__(self, db_path: str = 'logs/soteria.db'):
        self.db_path = db_path
        self.is_running = False
        
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        
        self._write_queue = queue.Queue()
        self._write_thread = None
        self._lock = threading.Lock()
        
        self._init_database()
    
    def _init_database(self):
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS threat_events (
                        id TEXT PRIMARY KEY,
                        timestamp DATETIME NOT NULL,
                        event_type TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        score REAL,
                        source_ip TEXT,
                        destination_ip TEXT,
                        port INTEGER,
                        protocol TEXT,
                        url TEXT,
                        process_name TEXT,
                        details TEXT,
                        api_responses TEXT,
                        resolved BOOLEAN DEFAULT 0,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                cursor.execute('''
                    CREATE INDEX IF NOT EXISTS idx_timestamp 
                    ON threat_events(timestamp DESC)
                ''')
                
                cursor.execute('''
                    CREATE INDEX IF NOT EXISTS idx_event_type 
                    ON threat_events(event_type)
                ''')
                
                cursor.execute('''
                    CREATE INDEX IF NOT EXISTS idx_severity 
                    ON threat_events(severity)
                ''')
                
                cursor.execute('''
                    CREATE INDEX IF NOT EXISTS idx_source_ip 
                    ON threat_events(source_ip)
                ''')
                
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS network_stats (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp DATETIME NOT NULL,
                        packets_total INTEGER,
                        bytes_total INTEGER,
                        connections_active INTEGER,
                        threats_detected INTEGER,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS alert_history (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        threat_event_id TEXT,
                        alert_type TEXT NOT NULL,
                        recipient TEXT,
                        status TEXT,
                        error_message TEXT,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (threat_event_id) REFERENCES threat_events(id)
                    )
                ''')
                
                conn.commit()
                logger.info("Database initialized successfully")
                
        except sqlite3.Error as e:
            logger.error(f"Database initialization error: {e}")
            raise
    
    def start(self):
        if self.is_running:
            return
        
        self.is_running = True
        self._write_thread = threading.Thread(
            target=self._write_worker,
            daemon=True
        )
        self._write_thread.start()
        logger.info("Database logger started")
    
    def stop(self):
        if not self.is_running:
            return
        
        self.is_running = False
        
        self._write_queue.put(None)
        
        if self._write_thread:
            self._write_thread.join(timeout=5)
        
        logger.info("Database logger stopped")
    
    def _write_worker(self):
        while self.is_running:
            try:
                item = self._write_queue.get(timeout=1)
                if item is None:
                    break
                
                operation, args = item
                
                if operation == 'log_threat':
                    self._write_threat_event(*args)
                elif operation == 'log_stats':
                    self._write_network_stats(*args)
                elif operation == 'log_alert':
                    self._write_alert_history(*args)
                
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Database write error: {e}")
    
    def log_threat_event(self, event: Dict[str, Any]):
        self._write_queue.put(('log_threat', (event,)))
    
    def _write_threat_event(self, event: Dict[str, Any]):
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT INTO threat_events (
                        id, timestamp, event_type, severity, score,
                        source_ip, destination_ip, port, protocol,
                        url, process_name, details, api_responses, resolved
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    event['id'],
                    event['timestamp'],
                    event['type'],
                    event['severity'],
                    event.get('score', 0),
                    event.get('source_ip'),
                    event.get('destination_ip'),
                    event.get('port'),
                    event.get('protocol'),
                    event.get('url'),
                    event.get('process_name'),
                    json.dumps(event.get('details', {})),
                    json.dumps(event.get('api_responses', {})),
                    event.get('resolved', False)
                ))
                
                conn.commit()
                
        except sqlite3.Error as e:
            logger.error(f"Failed to log threat event: {e}")
    
    def log_network_stats(self, stats: Dict[str, Any]):
        self._write_queue.put(('log_stats', (stats,)))
    
    def _write_network_stats(self, stats: Dict[str, Any]):
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT INTO network_stats (
                        timestamp, packets_total, bytes_total,
                        connections_active, threats_detected
                    ) VALUES (?, ?, ?, ?, ?)
                ''', (
                    datetime.now(),
                    stats.get('packets_total', 0),
                    stats.get('bytes_total', 0),
                    stats.get('connections_active', 0),
                    stats.get('threats_detected', 0)
                ))
                
                conn.commit()
                
        except sqlite3.Error as e:
            logger.error(f"Failed to log network stats: {e}")
    
    def log_alert(self, threat_id: str, alert_type: str, recipient: str, 
                  status: str, error: Optional[str] = None):
        self._write_queue.put(('log_alert', 
                              (threat_id, alert_type, recipient, status, error)))
    
    def _write_alert_history(self, threat_id: str, alert_type: str, 
                           recipient: str, status: str, error: Optional[str]):
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT INTO alert_history (
                        threat_event_id, alert_type, recipient, status, error_message
                    ) VALUES (?, ?, ?, ?, ?)
                ''', (threat_id, alert_type, recipient, status, error))
                
                conn.commit()
                
        except sqlite3.Error as e:
            logger.error(f"Failed to log alert history: {e}")
    
    def get_threat_events(self, start_time: Optional[datetime] = None,
                         end_time: Optional[datetime] = None,
                         event_type: Optional[str] = None,
                         severity: Optional[str] = None,
                         limit: int = 100) -> List[Dict[str, Any]]:
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                query = "SELECT * FROM threat_events WHERE 1=1"
                params = []
                
                if start_time:
                    query += " AND timestamp >= ?"
                    params.append(start_time)
                
                if end_time:
                    query += " AND timestamp <= ?"
                    params.append(end_time)
                
                if event_type:
                    query += " AND event_type = ?"
                    params.append(event_type)
                
                if severity:
                    query += " AND severity = ?"
                    params.append(severity)
                
                query += " ORDER BY timestamp DESC LIMIT ?"
                params.append(limit)
                
                cursor.execute(query, params)
                
                events = []
                for row in cursor.fetchall():
                    event = dict(row)
                    event['details'] = json.loads(event['details'])
                    event['api_responses'] = json.loads(event['api_responses'])
                    events.append(event)
                
                return events
                
        except sqlite3.Error as e:
            logger.error(f"Failed to retrieve threat events: {e}")
            return []
    
    def get_statistics(self, hours: int = 24) -> Dict[str, Any]:
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                since = datetime.now() - timedelta(hours=hours)
                
                cursor.execute('''
                    SELECT 
                        COUNT(*) as total_threats,
                        SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as critical,
                        SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high,
                        SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END) as medium,
                        SUM(CASE WHEN severity = 'low' THEN 1 ELSE 0 END) as low
                    FROM threat_events
                    WHERE timestamp >= ?
                ''', (since,))
                
                threat_stats = dict(zip(
                    ['total_threats', 'critical', 'high', 'medium', 'low'],
                    cursor.fetchone()
                ))
                
                cursor.execute('''
                    SELECT event_type, COUNT(*) as count
                    FROM threat_events
                    WHERE timestamp >= ?
                    GROUP BY event_type
                ''', (since,))
                
                threat_types = dict(cursor.fetchall())
                
                cursor.execute('''
                    SELECT 
                        AVG(packets_total) as avg_packets,
                        AVG(bytes_total) as avg_bytes,
                        MAX(connections_active) as max_connections
                    FROM network_stats
                    WHERE timestamp >= ?
                ''', (since,))
                
                network_stats = dict(zip(
                    ['avg_packets', 'avg_bytes', 'max_connections'],
                    cursor.fetchone()
                ))
                
                return {
                    'threat_stats': threat_stats,
                    'threat_types': threat_types,
                    'network_stats': network_stats,
                    'time_period_hours': hours
                }
                
        except sqlite3.Error as e:
            logger.error(f"Failed to get statistics: {e}")
            return {}
    
    def cleanup_old_records(self, days: int = 30):
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cutoff_date = datetime.now() - timedelta(days=days)
                
                cursor.execute('''
                    DELETE FROM threat_events WHERE created_at < ?
                ''', (cutoff_date,))
                
                cursor.execute('''
                    DELETE FROM network_stats WHERE created_at < ?
                ''', (cutoff_date,))
                
                cursor.execute('''
                    DELETE FROM alert_history WHERE created_at < ?
                ''', (cutoff_date,))
                
                conn.commit()
                
                deleted = cursor.rowcount
                logger.info(f"Cleaned up {deleted} old records")
                
        except sqlite3.Error as e:
            logger.error(f"Failed to cleanup old records: {e}")