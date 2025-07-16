import logging
import json
import secrets
from datetime import datetime, timedelta
from flask import Flask, render_template, jsonify, request, session
from flask_socketio import SocketIO, emit
from functools import wraps
import threading
import time

logger = logging.getLogger(__name__)

class DashboardServer:
    def __init__(self, host: str, port: int, debug: bool, db_logger, engine):
        self.host = host
        self.port = port
        self.debug = debug
        self.db_logger = db_logger
        self.engine = engine
        
        self.app = Flask(__name__)
        self.app.config['SECRET_KEY'] = secrets.token_hex(32)
        self.socketio = SocketIO(self.app, cors_allowed_origins="*")
        
        self.is_running = False
        self._setup_routes()
        self._setup_socketio()
        
        self._update_thread = None
    
    def _setup_routes(self):
        @self.app.route('/')
        def index():
            return render_template('index.html')
        
        @self.app.route('/api/status')
        def api_status():
            return jsonify(self.engine.get_status())
        
        @self.app.route('/api/threats')
        def api_threats():
            hours = request.args.get('hours', 24, type=int)
            limit = request.args.get('limit', 100, type=int)
            severity = request.args.get('severity')
            event_type = request.args.get('type')
            
            start_time = datetime.now() - timedelta(hours=hours)
            
            threats = self.db_logger.get_threat_events(
                start_time=start_time,
                event_type=event_type,
                severity=severity,
                limit=limit
            )
            
            return jsonify(threats)
        
        @self.app.route('/api/statistics')
        def api_statistics():
            hours = request.args.get('hours', 24, type=int)
            stats = self.db_logger.get_statistics(hours=hours)
            return jsonify(stats)
        
        @self.app.route('/api/threat/<threat_id>')
        def api_threat_detail(threat_id):
            threats = self.db_logger.get_threat_events(limit=1)
            threat = next((t for t in threats if t['id'] == threat_id), None)
            if threat:
                return jsonify(threat)
            return jsonify({'error': 'Threat not found'}), 404
        
        @self.app.route('/api/config')
        def api_config():
            config = self.engine.config.copy()
            if 'api_keys' in config:
                config['api_keys'] = {k: '***' for k in config['api_keys']}
            return jsonify(config)
    
    def _setup_socketio(self):
        @self.socketio.on('connect')
        def handle_connect():
            logger.info(f"Dashboard client connected: {request.sid}")
            emit('connected', {'status': 'Connected to Soteria IDS'})
        
        @self.socketio.on('disconnect')
        def handle_disconnect():
            logger.info(f"Dashboard client disconnected: {request.sid}")
        
        @self.socketio.on('request_update')
        def handle_update_request():
            self._send_update()
    
    def start(self):
        if self.is_running:
            return
        
        self.is_running = True
        
        self._update_thread = threading.Thread(
            target=self._update_loop,
            daemon=True
        )
        self._update_thread.start()
        
        logger.info(f"Starting dashboard server on {self.host}:{self.port}")
        
        self.socketio.run(
            self.app,
            host=self.host,
            port=self.port,
            debug=self.debug,
            use_reloader=False,
            log_output=False
        )
    
    def stop(self):
        self.is_running = False
        logger.info("Dashboard server stopped")
    
    def _update_loop(self):
        while self.is_running:
            try:
                self._send_update()
                time.sleep(5)
            except Exception as e:
                logger.error(f"Error in update loop: {e}")
    
    def _send_update(self):
        try:
            status = self.engine.get_status()
            recent_threats = self.db_logger.get_threat_events(
                start_time=datetime.now() - timedelta(minutes=5),
                limit=10
            )
            stats = self.db_logger.get_statistics(hours=1)
            
            update_data = {
                'timestamp': datetime.now().isoformat(),
                'status': status,
                'recent_threats': recent_threats,
                'statistics': stats
            }
            
            self.socketio.emit('status_update', update_data)
            
        except Exception as e:
            logger.error(f"Error sending update: {e}")