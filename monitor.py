"""
Network Health Dashboard - Monitoring Engine
Captures active network connections and detects suspicious activity
"""

import subprocess
import sqlite3
import logging
from datetime import datetime
from config import DATABASE_PATH, WHITELIST_IPS, SUSPICIOUS_PORTS

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class NetworkMonitor:
    """Main monitoring class"""
    
    def __init__(self):
        self.known_ips = set()
        self.known_ports = set()
        self.init_database()
    
    def init_database(self):
        """Initialize SQLite database"""
        try:
            conn = sqlite3.connect(DATABASE_PATH)
            c = conn.cursor()
            
            # Connections table
            c.execute('''CREATE TABLE IF NOT EXISTS connections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                local_ip TEXT NOT NULL,
                local_port INTEGER,
                remote_ip TEXT,
                remote_port INTEGER,
                protocol TEXT,
                state TEXT,
                process_name TEXT
            )''')
            
            # Alerts table
            c.execute('''CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                alert_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT,
                source_ip TEXT,
                source_port INTEGER
            )''')
            
            conn.commit()
            conn.close()
            logger.info("✓ Database initialized")
        except Exception as e:
            logger.error(f"Database init error: {e}")
    
    def get_active_connections(self):
        """
        Get active network connections using netstat/ss
        Returns list of connection dictionaries
        """
        connections = []
        
        try:
            # Try 'ss' first (newer), fallback to 'netstat'
            try:
                cmd = "ss -tuln"
                output = subprocess.check_output(cmd, shell=True, text=True)
                use_ss = True
            except:
                cmd = "netstat -tuln"
                output = subprocess.check_output(cmd, shell=True, text=True)
                use_ss = False
            
            # Parse output
            lines = output.split('\n')[1:]  # Skip header
            
            for line in lines:
                if not line.strip():
                    continue
                
                parts = line.split()
                if len(parts) < 4:
                    continue
                
                try:
                    protocol = parts[0]
                    local_addr = parts[3]
                    state = parts[-1] if len(parts) > 5 else 'LISTEN'
                    
                    # Parse local address
                    if ':' in local_addr:
                        local_ip, local_port = local_addr.rsplit(':', 1)
                        local_port = int(local_port)
                    else:
                        local_ip = local_addr
                        local_port = 0
                    
                    # Clean up IPv6 addresses
                    if '[' in local_ip and ']' in local_ip:
                        local_ip = local_ip.replace('[', '').replace(']', '')
                    
                    connection = {
                        'protocol': protocol.upper(),
                        'local_ip': local_ip,
                        'local_port': local_port,
                        'state': state.upper(),
                        'remote_ip': None,
                        'remote_port': None,
                        'timestamp': datetime.now().isoformat()
                    }
                    
                    connections.append(connection)
                
                except (IndexError, ValueError) as e:
                    logger.debug(f"Error parsing line: {line}, Error: {e}")
                    continue
            
            return connections
        
        except Exception as e:
            logger.error(f"Error getting connections: {e}")
            return []
    
    def detect_unknown_ips(self, connections):
        """Detect new/unknown IPs"""
        alerts = []
        
        for conn in connections:
            local_ip = conn.get('local_ip', '')
            
            # Skip whitelisted IPs
            if local_ip in WHITELIST_IPS or local_ip == '0.0.0.0':
                continue
            
            # Check if IP is new
            if local_ip not in self.known_ips:
                self.known_ips.add(local_ip)
                alerts.append({
                    'alert_type': 'NEW_CONNECTION',
                    'severity': 'INFO',
                    'description': f'New connection detected on {local_ip}',
                    'source_ip': local_ip,
                    'source_port': conn.get('local_port', 0)
                })
        
        return alerts
    
    def check_suspicious_ports(self, connections):
        """Check for suspicious port activity"""
        alerts = []
        
        for conn in connections:
            port = conn.get('local_port', 0)
            state = conn.get('state', '')
            
            if port in SUSPICIOUS_PORTS and state == 'LISTEN':
                alerts.append({
                    'alert_type': 'SUSPICIOUS_PORT',
                    'severity': 'WARNING',
                    'description': f'Suspicious port {port} is LISTENING',
                    'source_ip': conn.get('local_ip', ''),
                    'source_port': port
                })
        
        return alerts
    
    def save_connections(self, connections):
        """Store connections in database"""
        try:
            conn = sqlite3.connect(DATABASE_PATH)
            c = conn.cursor()
            
            for conn_data in connections:
                c.execute('''INSERT INTO connections 
                    (timestamp, local_ip, local_port, protocol, state, remote_ip, remote_port)
                    VALUES (?, ?, ?, ?, ?, ?, ?)''',
                    (conn_data.get('timestamp'),
                     conn_data.get('local_ip'),
                     conn_data.get('local_port'),
                     conn_data.get('protocol'),
                     conn_data.get('state'),
                     conn_data.get('remote_ip'),
                     conn_data.get('remote_port')))
            
            conn.commit()
            conn.close()
            logger.debug(f"Saved {len(connections)} connections")
        
        except Exception as e:
            logger.error(f"Error saving connections: {e}")
    
    def save_alert(self, alert):
        """Store single alert in database"""
        try:
            conn = sqlite3.connect(DATABASE_PATH)
            c = conn.cursor()
            
            c.execute('''INSERT INTO alerts 
                (timestamp, alert_type, severity, description, source_ip, source_port)
                VALUES (?, ?, ?, ?, ?, ?)''',
                (datetime.now().isoformat(),
                 alert.get('alert_type'),
                 alert.get('severity'),
                 alert.get('description'),
                 alert.get('source_ip'),
                 alert.get('source_port')))
            
            conn.commit()
            conn.close()
        
        except Exception as e:
            logger.error(f"Error saving alert: {e}")
    
    def scan(self):
        """
        Complete scan: capture connections, detect issues, save data
        Call this every N seconds from the scheduler
        """
        logger.info("🔍 Starting network scan...")
        
        # Get connections
        connections = self.get_active_connections()
        logger.info(f"Found {len(connections)} active connections")
        
        # Detect issues
        all_alerts = []
        all_alerts.extend(self.detect_unknown_ips(connections))
        all_alerts.extend(self.check_suspicious_ports(connections))
        
        # Save data
        self.save_connections(connections)
        
        for alert in all_alerts:
            self.save_alert(alert)
            logger.warning(f"⚠️ Alert: {alert.get('description')}")
        
        if all_alerts:
            logger.info(f"Generated {len(all_alerts)} alerts")
        
        return {
            'connections': len(connections),
            'alerts': len(all_alerts),
            'timestamp': datetime.now().isoformat()
        }


# Create global monitor instance
monitor = NetworkMonitor()

if __name__ == '__main__':
    # Test the monitor
    result = monitor.scan()
    print(f"✓ Monitor test successful: {result}")