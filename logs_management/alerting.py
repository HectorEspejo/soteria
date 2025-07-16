import logging
import smtplib
import ssl
import threading
import queue
import time
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import requests
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
from twilio.rest import Client as TwilioClient

logger = logging.getLogger(__name__)

class AlertManager:
    def __init__(self, config: Dict[str, Any], api_keys: Dict[str, str]):
        self.config = config
        self.api_keys = api_keys
        self.is_running = False
        
        self._alert_queue = queue.Queue()
        self._alert_thread = None
        
        self._rate_limits = {}
        self._alert_cache = {}
        
        self._init_clients()
    
    def _init_clients(self):
        email_config = self.config.get('email', {})
        if email_config.get('enabled'):
            self.email_config = email_config
        else:
            self.email_config = None
        
        slack_config = self.config.get('slack', {})
        if slack_config.get('enabled') and slack_config.get('webhook_url'):
            self.slack_webhook_url = slack_config['webhook_url']
        else:
            self.slack_webhook_url = None
        
        sms_config = self.config.get('sms', {})
        if (sms_config.get('enabled') and 
            sms_config.get('twilio_sid') and 
            sms_config.get('twilio_token')):
            try:
                self.twilio_client = TwilioClient(
                    sms_config['twilio_sid'],
                    sms_config['twilio_token']
                )
                self.sms_from = sms_config.get('from_number')
                self.sms_to_numbers = sms_config.get('to_numbers', [])
            except Exception as e:
                logger.error(f"Failed to initialize Twilio client: {e}")
                self.twilio_client = None
        else:
            self.twilio_client = None
    
    def start_processing(self):
        if self.is_running:
            return
        
        self.is_running = True
        self._alert_thread = threading.Thread(
            target=self._process_alerts,
            daemon=True
        )
        self._alert_thread.start()
        logger.info("Alert manager started")
    
    def stop(self):
        if not self.is_running:
            return
        
        self.is_running = False
        self._alert_queue.put(None)
        
        if self._alert_thread:
            self._alert_thread.join(timeout=5)
        
        logger.info("Alert manager stopped")
    
    def send_alert(self, threat_event: Dict[str, Any]):
        if self._should_rate_limit(threat_event):
            logger.debug(f"Rate limiting alert for {threat_event['id']}")
            return
        
        self._alert_queue.put(threat_event)
    
    def _process_alerts(self):
        while self.is_running:
            try:
                threat_event = self._alert_queue.get(timeout=1)
                if threat_event is None:
                    break
                
                severity = threat_event.get('severity', 'medium')
                
                if severity in ['critical', 'high']:
                    self._send_all_alerts(threat_event)
                elif severity == 'medium':
                    self._send_email_and_slack(threat_event)
                else:
                    self._send_slack_only(threat_event)
                
                self._update_cache(threat_event)
                
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Error processing alert: {e}")
    
    def _should_rate_limit(self, threat_event: Dict[str, Any]) -> bool:
        key = f"{threat_event['type']}:{threat_event.get('source_ip', 'unknown')}"
        
        now = time.time()
        last_sent = self._rate_limits.get(key, 0)
        
        if severity := threat_event.get('severity'):
            if severity == 'critical':
                min_interval = 60
            elif severity == 'high':
                min_interval = 300
            else:
                min_interval = 600
        else:
            min_interval = 600
        
        if now - last_sent < min_interval:
            return True
        
        self._rate_limits[key] = now
        return False
    
    def _send_all_alerts(self, threat_event: Dict[str, Any]):
        self._send_email_alert(threat_event)
        self._send_slack_alert(threat_event)
        self._send_sms_alert(threat_event)
    
    def _send_email_and_slack(self, threat_event: Dict[str, Any]):
        self._send_email_alert(threat_event)
        self._send_slack_alert(threat_event)
    
    def _send_slack_only(self, threat_event: Dict[str, Any]):
        self._send_slack_alert(threat_event)
    
    def _send_email_alert(self, threat_event: Dict[str, Any]):
        if not self.email_config or not self.email_config.get('recipients'):
            return
        
        try:
            subject = f"[Soteria IDS] {threat_event['severity'].upper()} - {threat_event['type']}"
            
            body = self._format_alert_message(threat_event, 'email')
            
            message = MIMEMultipart('alternative')
            message['Subject'] = subject
            message['From'] = self.email_config['username']
            message['To'] = ', '.join(self.email_config['recipients'])
            
            text_part = MIMEText(body, 'plain')
            message.attach(text_part)
            
            context = ssl.create_default_context()
            
            with smtplib.SMTP(self.email_config['smtp_server'], 
                             self.email_config['smtp_port']) as server:
                server.starttls(context=context)
                server.login(self.email_config['username'], 
                           self.email_config['password'])
                server.send_message(message)
            
            logger.info(f"Email alert sent for threat {threat_event['id']}")
            
        except Exception as e:
            logger.error(f"Failed to send email alert: {e}")
    
    def _send_slack_alert(self, threat_event: Dict[str, Any]):
        if not self.slack_webhook_url:
            return
        
        try:
            message = self._format_alert_message(threat_event, 'slack')
            
            severity_colors = {
                'critical': '#ff0000',
                'high': '#ff9900',
                'medium': '#ffcc00',
                'low': '#00ff00'
            }
            
            color = severity_colors.get(threat_event['severity'], '#808080')
            
            payload = {
                'attachments': [{
                    'color': color,
                    'title': f"{threat_event['severity'].upper()} - {threat_event['type']}",
                    'text': message,
                    'fields': [
                        {
                            'title': 'Threat ID',
                            'value': threat_event['id'],
                            'short': True
                        },
                        {
                            'title': 'Score',
                            'value': str(threat_event.get('score', 'N/A')),
                            'short': True
                        }
                    ],
                    'footer': 'Soteria IDS',
                    'ts': int(datetime.now().timestamp())
                }]
            }
            
            response = requests.post(self.slack_webhook_url, json=payload, timeout=10)
            response.raise_for_status()
            
            logger.info(f"Slack alert sent for threat {threat_event['id']}")
            
        except Exception as e:
            logger.error(f"Failed to send Slack alert: {e}")
    
    def _send_sms_alert(self, threat_event: Dict[str, Any]):
        if not self.twilio_client or not self.sms_to_numbers:
            return
        
        try:
            message = self._format_alert_message(threat_event, 'sms')
            
            for to_number in self.sms_to_numbers:
                self.twilio_client.messages.create(
                    body=message[:160],
                    from_=self.sms_from,
                    to=to_number
                )
            
            logger.info(f"SMS alerts sent for threat {threat_event['id']}")
            
        except Exception as e:
            logger.error(f"Failed to send SMS alert: {e}")
    
    def _format_alert_message(self, threat_event: Dict[str, Any], 
                            format_type: str) -> str:
        timestamp = threat_event['timestamp']
        if isinstance(timestamp, str):
            timestamp = datetime.fromisoformat(timestamp)
        
        if format_type == 'email':
            message = f"""
Soteria IDS Alert

Threat Detected: {threat_event['type']}
Severity: {threat_event['severity'].upper()}
Time: {timestamp.strftime('%Y-%m-%d %H:%M:%S')}
Score: {threat_event.get('score', 'N/A')}

Details:
"""
            if threat_event.get('source_ip'):
                message += f"Source IP: {threat_event['source_ip']}\n"
            if threat_event.get('destination_ip'):
                message += f"Destination IP: {threat_event['destination_ip']}\n"
            if threat_event.get('url'):
                message += f"URL: {threat_event['url']}\n"
            if threat_event.get('process_name'):
                message += f"Process: {threat_event['process_name']}\n"
            
            if details := threat_event.get('details'):
                message += f"\nAdditional Information:\n"
                for key, value in details.items():
                    message += f"- {key}: {value}\n"
            
        elif format_type == 'slack':
            message = f"*{threat_event['type']}* detected at {timestamp.strftime('%H:%M:%S')}\n"
            
            if threat_event.get('source_ip'):
                message += f"• Source: `{threat_event['source_ip']}`\n"
            if threat_event.get('url'):
                message += f"• URL: `{threat_event['url']}`\n"
            if threat_event.get('process_name'):
                message += f"• Process: `{threat_event['process_name']}`\n"
            
        elif format_type == 'sms':
            message = f"SOTERIA: {threat_event['severity'].upper()} {threat_event['type']} "
            if threat_event.get('source_ip'):
                message += f"from {threat_event['source_ip']}"
        
        return message
    
    def _update_cache(self, threat_event: Dict[str, Any]):
        key = f"{threat_event['type']}:{threat_event.get('source_ip', 'unknown')}"
        self._alert_cache[key] = {
            'last_seen': datetime.now(),
            'count': self._alert_cache.get(key, {}).get('count', 0) + 1
        }
    
    def update_config(self, new_config: Dict[str, Any]):
        self.config = new_config
        self._init_clients()
        logger.info("Alert configuration updated")
    
    def get_stats(self) -> Dict[str, Any]:
        total_alerts = sum(cache['count'] for cache in self._alert_cache.values())
        
        return {
            'total_alerts_sent': total_alerts,
            'alert_queue_size': self._alert_queue.qsize(),
            'rate_limited_keys': len(self._rate_limits),
            'channels_enabled': {
                'email': bool(self.email_config),
                'slack': bool(self.slack_webhook_url),
                'sms': bool(self.twilio_client)
            }
        }