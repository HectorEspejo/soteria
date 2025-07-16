# Soteria IDS - Network Intrusion Detection System

Soteria is a comprehensive, Python-based Network Intrusion Detection System (IDS) designed to monitor network traffic, detect malicious activities, and provide real-time alerts through multiple channels.

## Features

### Core Capabilities
- **Real-time Packet Capture**: Uses Scapy for efficient network packet capture and analysis
- **Multi-threaded Architecture**: Event-driven design with dedicated threads for each component
- **Daemon Mode**: Runs as a background service on Linux systems
- **Web Dashboard**: Real-time monitoring interface with charts and statistics
- **CLI Interface**: Comprehensive command-line tool for management and analysis

### Detection Modules

#### 1. URL/Website Detection
- Extracts and analyzes URLs from HTTP/HTTPS traffic
- TLS SNI parsing for encrypted connections
- Domain age and SSL certificate validation
- Integration with VirusTotal and Google Safe Browsing APIs
- Heuristic analysis for suspicious domains
- Customizable blacklist/whitelist support

#### 2. Program/Malware Detection
- Process monitoring using psutil
- YARA rule-based file scanning
- Behavioral analysis (CPU/memory anomalies)
- VirusTotal file hash checking
- Parent process relationship analysis
- Cryptocurrency miner detection

#### 3. Traffic Anomaly Detection
- Statistical anomaly detection using Z-score analysis
- DDoS and SYN flood detection
- Port and network scan detection
- IP reputation checking via AbuseIPDB
- Geolocation-based anomaly detection

### Alerting System
- **Email**: SMTP-based email notifications
- **Slack**: Webhook integration for team notifications
- **SMS**: Twilio integration for critical alerts
- **Rate Limiting**: Intelligent alert throttling
- **Severity-based Routing**: Different channels for different threat levels

### Data Management
- SQLite database for event storage
- Structured logging with retention policies
- CSV/PDF report generation
- Real-time statistics and analytics

## Requirements

- Linux operating system (Ubuntu 20.04+ recommended)
- Python 3.8 or higher
- Root privileges for packet capture
- Network interface in promiscuous mode

## Installation

### Quick Install

```bash
sudo bash install.sh
```

### Manual Installation

1. Install system dependencies:
```bash
sudo apt-get update
sudo apt-get install -y python3-pip python3-dev libpcap-dev
```

2. Create virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate
```

3. Install Python dependencies:
```bash
pip install -r requirements.txt
```

4. Configure the system:
```bash
sudo cp config/soteria.yaml /etc/soteria/
sudo nano /etc/soteria/soteria.yaml  # Add your API keys
```

5. Install as systemd service:
```bash
sudo cp soteria.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable soteria
```

## Configuration

Edit `/etc/soteria/soteria.yaml` to configure:

- Network interfaces to monitor
- API keys for external services
- Detection thresholds
- Alert settings
- Dashboard configuration

### Required API Keys

1. **VirusTotal**: Sign up at https://www.virustotal.com/gui/join-us
2. **AbuseIPDB**: Register at https://www.abuseipdb.com/register
3. **Google Safe Browsing**: Get key from https://developers.google.com/safe-browsing/v4/get-started

## Usage

### Starting the Service

```bash
# Start daemon
sudo systemctl start soteria

# Check status
sudo systemctl status soteria

# View logs
sudo journalctl -u soteria -f
```

### Command Line Interface

```bash
# Enter interactive CLI
sudo soteria cli

# CLI commands:
soteria> status          # Check system status
soteria> threats         # View recent threats
soteria> stats           # Show statistics
soteria> search <query>  # Search threat logs
soteria> export data.csv # Export threat data
soteria> dashboard       # Open web dashboard
```

### Web Dashboard

Access the dashboard at `http://localhost:8080` (default port)

Features:
- Real-time threat monitoring
- Network traffic visualization
- System resource monitoring
- Interactive threat analysis

## API Endpoints

- `GET /api/status` - System status
- `GET /api/threats` - Recent threats
- `GET /api/statistics` - Traffic statistics
- `GET /api/threat/<id>` - Threat details

## Architecture

```
├── main.py                 # Entry point
├── core/
│   ├── engine.py          # Main orchestrator
│   └── thread_manager.py  # Thread management
├── capture/
│   └── sniffer.py         # Packet capture
├── detection/
│   ├── url_detector.py    # URL analysis
│   ├── program_detector.py # Process monitoring
│   └── traffic_detector.py # Traffic analysis
├── logs_management/
│   ├── database.py        # SQLite storage
│   ├── alerting.py        # Alert management
│   └── reporting.py       # Report generation
├── ui/
│   └── dashboard.py       # Flask web interface
└── cli/
    └── interface.py       # CLI handler
```

## Performance Tuning

### High Traffic Networks

Adjust in configuration:
- `packet_sampling_rate`: Reduce to sample packets
- `worker_threads`: Increase for more parallelism
- `max_packet_queue_size`: Increase buffer size

### Resource Usage

Monitor with:
```bash
soteria> status
```

## Troubleshooting

### Common Issues

1. **Permission Denied**
   - Ensure running with sudo/root privileges
   - Check file permissions in /etc/soteria

2. **High CPU Usage**
   - Adjust packet_sampling_rate
   - Check detection thresholds
   - Review process whitelist

3. **API Errors**
   - Verify API keys in configuration
   - Check rate limits
   - Ensure internet connectivity

### Debug Mode

```bash
sudo soteria run -d  # Run in foreground with debug logging
```

## Security Considerations

- API keys are stored in configuration file with restricted permissions
- Supports privilege dropping after initialization
- Encrypted storage for sensitive data
- Network traffic anonymization options

## Contributing

1. Fork the repository
2. Create feature branch
3. Commit changes
4. Push to branch
5. Create Pull Request

## License

This project is licensed under the MIT License.

## Acknowledgments

- Scapy for packet manipulation
- Flask for web framework
- YARA for malware detection
- VirusTotal, AbuseIPDB, and Google Safe Browsing for threat intelligence