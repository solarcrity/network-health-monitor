"""
Configuration settings for Network Health Dashboard
"""

import os

# Flask Configuration
DEBUG = False
HOST = '0.0.0.0'
PORT = 5000
SECRET_KEY = 'network-monitor-secret-key'

# Monitoring Configuration
REFRESH_INTERVAL = 5  # seconds between updates
HISTORY_LIMIT = 100  # Keep last N connections
ALERT_HISTORY = 50   # Keep last N alerts

# Database Configuration
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, 'data')
DATABASE_PATH = os.path.join(DATA_DIR, 'connections.db')

# Logging Configuration
LOGS_DIR = os.path.join(BASE_DIR, 'logs')
LOG_FILE = os.path.join(LOGS_DIR, 'app.log')
LOG_LEVEL = 'INFO'

# Alert Settings
UNKNOWN_IP_THRESHOLD = 2  # Alert if new IP seen more than X times
PORT_CHANGE_ALERT = True  # Alert on port open/close
SUSPICIOUS_PORTS = [445, 3389, 22]  # Ports to watch closely

# Whitelist (IPs to ignore)
WHITELIST_IPS = [
    '127.0.0.1',
    '0.0.0.0',
    '::1',  # IPv6 localhost
]