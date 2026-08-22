#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════════════════╗
║                    NETWORK HEALTH MONITOR v1.0                           ║
║                   Real-time Network Monitoring Tool                       ║
║                                                                           ║
║  A professional security tool for monitoring network connections,        ║
║  detecting suspicious activity, and tracking port changes in real-time.  ║
╚═══════════════════════════════════════════════════════════════════════════╝

Author: Arceus | Security Tools Portfolio
License: MIT
Usage: python3 network-health-monitor.py
"""

import os
import sys
import sqlite3
import subprocess
import logging
import time
import signal
from datetime import datetime
from config import (
    DATABASE_PATH, WHITELIST_IPS, SUSPICIOUS_PORTS, 
    LOGS_DIR, LOG_FILE, REFRESH_INTERVAL
)
from monitor import monitor

# Color codes for terminal
class Colors:
    """ANSI color codes for terminal output"""
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'

class Status:
    """Status symbols"""
    SUCCESS = f"{Colors.GREEN}✓{Colors.RESET}"
    ERROR = f"{Colors.RED}✗{Colors.RESET}"
    WARNING = f"{Colors.YELLOW}⚠{Colors.RESET}"
    INFO = f"{Colors.BLUE}ℹ{Colors.RESET}"
    ARROW = f"{Colors.CYAN}→{Colors.RESET}"
    BULLET = f"{Colors.MAGENTA}•{Colors.RESET}"

# Setup logging
if not os.path.exists(LOGS_DIR):
    os.makedirs(LOGS_DIR)

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class TerminalUI:
    """Terminal User Interface for Network Health Monitor"""
    
    def __init__(self):
        self.is_running = True
        self.connection_count = 0
        self.alert_count = 0
        self.start_time = datetime.now()
        signal.signal(signal.SIGINT, self.handle_interrupt)
    
    def handle_interrupt(self, signum, frame):
        """Handle Ctrl+C gracefully"""
        print(f"\n\n{Status.INFO} Shutting down Network Health Monitor...")
        self.is_running = False
        self.print_footer()
        sys.exit(0)
    
    def print_banner(self):
        """Print ASCII art banner"""
        banner = f"""
{Colors.CYAN}{Colors.BOLD}
╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                           ║
║          ███╗   ██╗███████╗████████╗██╗    ██╗ ██████╗ ██╗  ██╗           ║
║          ████╗  ██║██╔════╝╚══██╔══╝██║    ██║██╔═══██╗██║ ██╔╝           ║
║          ██╔██╗ ██║█████╗     ██║   ██║ █╗ ██║██║   ██║█████╔╝            ║
║          ██║╚██╗██║██╔══╝     ██║   ██║███╗██║██║   ██║██╔═██╗            ║
║          ██║ ╚████║███████╗   ██║   ╚███╔███╔╝╚██████╔╝██║  ██╗           ║
║          ╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═╝           ║
║                                                                           ║
║        NETWORK HEALTH MONITOR - Real-time Monitoring By Phochacco         ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝
{Colors.RESET}
"""
        print(banner)
    
    def print_header(self):
        """Print session header with info"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        hostname = os.popen('hostname').read().strip()
        user = os.popen('whoami').read().strip()
        
        print(f"\n{Colors.BOLD}{Colors.BLUE}┌─ Session Info{Colors.RESET}")
        print(f"│ {Status.INFO} Started: {timestamp}")
        print(f"│ {Status.INFO} Hostname: {hostname}")
        print(f"│ {Status.INFO} User: {user}")
        print(f"│ {Status.INFO} Refresh Rate: {REFRESH_INTERVAL}s")
        print(f"└──────────────────────────────────────────────────────────────\n")
    
    def print_scan_header(self, scan_number):
        """Print scan header"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        uptime = datetime.now() - self.start_time
        hours, remainder = divmod(int(uptime.total_seconds()), 3600)
        minutes, seconds = divmod(remainder, 60)
        
        print(f"\n{Colors.BOLD}{Colors.YELLOW}[{timestamp}] Scan #{scan_number}{Colors.RESET} {Colors.DIM}(Uptime: {hours}h {minutes}m {seconds}s){Colors.RESET}")
        print(f"{Colors.DIM}{'─' * 75}{Colors.RESET}")
    
    def print_connections_section(self, connections):
        """Print active connections section"""
        if not connections:
            print(f"{Status.INFO} No connections found")
            return
        
        self.connection_count = len(connections)
        print(f"\n{Colors.BOLD}{Colors.CYAN}📊 Active Connections ({len(connections)} total){Colors.RESET}")
        print(f"{Colors.DIM}{'─' * 75}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.BLUE}", end="")
        print(f"{'Local IP':<20} {'Port':<8} {'Protocol':<10} {'State':<15}")
        print(f"{Colors.DIM}{'─' * 75}{Colors.RESET}")
        
        for i, conn in enumerate(connections[:10]):
            local_ip = conn.get('local_ip', 'N/A')
            local_port = conn.get('local_port', 0)
            protocol = conn.get('protocol', 'N/A')
            state = conn.get('state', 'N/A')
            
            if state == 'LISTEN':
                state_color = Colors.GREEN
            else:
                state_color = Colors.WHITE
            
            if local_port in SUSPICIOUS_PORTS:
                port_marker = f"{Colors.RED}{Status.WARNING}{Colors.RESET}"
            else:
                port_marker = " "
            
            print(f"{local_ip:<20} {local_port:<8} {protocol:<10} {state_color}{state:<15}{Colors.RESET}", end="")
            print(f" {port_marker}")
        
        if len(connections) > 10:
            print(f"{Colors.DIM}... and {len(connections) - 10} more connections{Colors.RESET}")
        
        print()
    
    def print_alerts_section(self, alerts):
        """Print alerts section"""
        if not alerts:
            print(f"{Colors.GREEN}{Status.SUCCESS} No alerts - Network looks healthy!{Colors.RESET}\n")
            return
        
        self.alert_count = len(alerts)
        
        print(f"\n{Colors.BOLD}{Colors.RED}🚨 ALERTS ({len(alerts)} total){Colors.RESET}")
        print(f"{Colors.DIM}{'─' * 75}{Colors.RESET}")
        
        critical = [a for a in alerts if a.get('severity') == 'CRITICAL']
        warning = [a for a in alerts if a.get('severity') == 'WARNING']
        info = [a for a in alerts if a.get('severity') == 'INFO']
        
        if critical:
            print(f"\n{Colors.BG_RED}{Colors.WHITE} CRITICAL ({len(critical)}) {Colors.RESET}")
            for alert in critical[:5]:
                print(f"  {Colors.RED}{Status.ERROR}{Colors.RESET} {alert.get('description', 'Unknown')}")
                print(f"     {Colors.DIM}• IP: {alert.get('source_ip')} | Port: {alert.get('source_port')}{Colors.RESET}")
        
        if warning:
            print(f"\n{Colors.YELLOW}{Colors.BOLD}⚠ WARNING ({len(warning)}){Colors.RESET}")
            for alert in warning[:5]:
                print(f"  {Status.WARNING} {alert.get('description', 'Unknown')}")
                print(f"     {Colors.DIM}• IP: {alert.get('source_ip')} | Port: {alert.get('source_port')}{Colors.RESET}")
        
        if info:
            print(f"\n{Colors.BLUE}{Colors.BOLD}ℹ INFO ({len(info)}){Colors.RESET}")
            for alert in info[:3]:
                print(f"  {Status.INFO} {alert.get('description', 'Unknown')}")
        
        print()
    
    def print_stats(self, stats):
        """Print statistics"""
        print(f"{Colors.BOLD}{Colors.MAGENTA}📈 Statistics{Colors.RESET}")
        print(f"{Colors.DIM}{'─' * 75}{Colors.RESET}")
        print(f"  {Status.BULLET} Total Connections Tracked: {Colors.CYAN}{stats.get('total_connections', 0)}{Colors.RESET}")
        print(f"  {Status.BULLET} Total Alerts Generated: {Colors.RED}{stats.get('total_alerts', 0)}{Colors.RESET}")
        print(f"  {Status.BULLET} Unique IP Addresses: {Colors.GREEN}{stats.get('unique_ips', 0)}{Colors.RESET}")
        print(f"  {Status.BULLET} Current Session Connections: {Colors.YELLOW}{self.connection_count}{Colors.RESET}")
        print(f"  {Status.BULLET} Current Session Alerts: {Colors.RED}{self.alert_count}{Colors.RESET}")
        print()
    
    def print_footer(self):
        """Print footer"""
        uptime = datetime.now() - self.start_time
        hours, remainder = divmod(int(uptime.total_seconds()), 3600)
        minutes, seconds = divmod(remainder, 60)
        
        footer = f"""
{Colors.DIM}{'─' * 75}{Colors.RESET}
{Colors.DIM}Session Duration: {hours}h {minutes}m {seconds}s | Database: {DATABASE_PATH}{Colors.RESET}
{Colors.DIM}Logs: {LOG_FILE} | Press Ctrl+C to exit{Colors.RESET}
{Colors.DIM}{'─' * 75}{Colors.RESET}
"""
        print(footer)
    
    def run(self):
        """Main monitoring loop"""
        self.print_banner()
        self.print_header()
        
        scan_number = 0
        
        print(f"{Status.SUCCESS} Starting network monitoring...")
        print(f"{Status.INFO} Refresh interval: {REFRESH_INTERVAL} seconds")
        print(f"{Status.WARNING} Press {Colors.BOLD}Ctrl+C{Colors.RESET} to stop\n")
        
        time.sleep(2)
        
        try:
            while self.is_running:
                scan_number += 1
                
                try:
                    result = monitor.scan()
                    connections = self.get_connections()
                    alerts = self.get_alerts()
                    stats = self.get_stats()
                    
                    self.print_scan_header(scan_number)
                    self.print_connections_section(connections)
                    self.print_alerts_section(alerts)
                    self.print_stats(stats)
                    self.print_footer()
                    
                    logger.info(f"Scan #{scan_number}: {result['connections']} connections, {result['alerts']} alerts")
                
                except Exception as e:
                    print(f"{Status.ERROR} Error during scan: {e}")
                    logger.error(f"Scan error: {e}")
                
                try:
                    time.sleep(REFRESH_INTERVAL)
                except KeyboardInterrupt:
                    raise KeyboardInterrupt
        
        except KeyboardInterrupt:
            self.handle_interrupt(None, None)
    
    def get_connections(self):
        """Fetch connections from database"""
        try:
            conn = sqlite3.connect(DATABASE_PATH)
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute('''SELECT * FROM connections ORDER BY timestamp DESC LIMIT 50''')
            rows = c.fetchall()
            conn.close()
            return [dict(row) for row in rows]
        except Exception as e:
            logger.error(f"Error fetching connections: {e}")
            return []
    
    def get_alerts(self):
        """Fetch alerts from database"""
        try:
            conn = sqlite3.connect(DATABASE_PATH)
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute('''SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 30''')
            rows = c.fetchall()
            conn.close()
            return [dict(row) for row in rows]
        except Exception as e:
            logger.error(f"Error fetching alerts: {e}")
            return []
    
    def get_stats(self):
        """Fetch statistics"""
        try:
            conn = sqlite3.connect(DATABASE_PATH)
            c = conn.cursor()
            
            c.execute('SELECT COUNT(*) FROM connections')
            total_connections = c.fetchone()[0]
            
            c.execute('SELECT COUNT(*) FROM alerts')
            total_alerts = c.fetchone()[0]
            
            c.execute('SELECT COUNT(DISTINCT local_ip) FROM connections')
            unique_ips = c.fetchone()[0]
            
            conn.close()
            
            return {
                'total_connections': total_connections,
                'total_alerts': total_alerts,
                'unique_ips': unique_ips
            }
        except Exception as e:
            logger.error(f"Error fetching stats: {e}")
            return {'total_connections': 0, 'total_alerts': 0, 'unique_ips': 0}


def main():
    """Main entry point"""
    try:
        ui = TerminalUI()
        ui.run()
    except Exception as e:
        print(f"{Status.ERROR} Fatal error: {e}")
        logger.error(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
