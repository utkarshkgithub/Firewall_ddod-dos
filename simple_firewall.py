#!/usr/bin/env python3
"""
Simple DDoS/DoS Protection Firewall
A lightweight firewall that monitors network traffic and blocks potential DDoS/DoS attacks
"""

import os
import sys
import time
import threading
import subprocess
from collections import defaultdict, deque
from datetime import datetime, timedelta
import signal
import json
import logging
from dataclasses import dataclass
from typing import Dict, Set, List
import argparse

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP
    import psutil
    from colorama import Fore, Style, init
    import netifaces
except ImportError as e:
    print(f"Required package missing: {e}")
    print("Run: pip install scapy psutil colorama netifaces")
    sys.exit(1)

# Initialize colorama
init(autoreset=True)

@dataclass
class AttackSignature:
    """Defines attack patterns and thresholds"""
    syn_flood_threshold: int = 100  # SYN packets per minute
    connection_threshold: int = 50   # Connections per IP per minute
    packet_rate_threshold: int = 1000  # Packets per IP per minute
    port_scan_threshold: int = 20    # Different ports accessed per minute
    icmp_flood_threshold: int = 100  # ICMP packets per minute

class FirewallStats:
    """Statistics tracking for the firewall"""
    def __init__(self):
        self.blocked_ips: Set[str] = set()
        self.attack_attempts = defaultdict(int)
        self.packets_analyzed = 0
        self.start_time = datetime.now()
        
    def get_uptime(self) -> str:
        uptime = datetime.now() - self.start_time
        return str(uptime).split('.')[0]  # Remove microseconds

class SimpleFirewall:
    """Main firewall class that handles DDoS/DoS protection"""
    
    def __init__(self, interface: str = None, config_file: str = None):
        self.interface = interface or self._get_default_interface()
        self.running = False
        self.stats = FirewallStats()
        
        # Load configuration
        self.config = self._load_config(config_file)
        self.signatures = AttackSignature(**self.config.get('thresholds', {}))
        
        # Tracking dictionaries with time windows
        self.ip_packets = defaultdict(lambda: deque())     # Packet count per IP
        self.ip_connections = defaultdict(lambda: deque()) # Connection attempts per IP
        self.ip_ports = defaultdict(lambda: set())         # Ports accessed per IP
        self.ip_syn_packets = defaultdict(lambda: deque()) # SYN packets per IP
        self.ip_icmp_packets = defaultdict(lambda: deque())# ICMP packets per IP
        self.ip_last_reset = defaultdict(lambda: datetime.now())
        
        # Blocked IPs with timestamp
        self.blocked_ips: Dict[str, datetime] = {}
        self.whitelist: Set[str] = set(self.config.get('whitelist', []))
        
        # Setup logging
        self._setup_logging()
        
        # Lock for thread safety
        self.lock = threading.Lock()
        
    def _get_default_interface(self) -> str:
        """Get the default network interface"""
        try:
            interfaces = netifaces.interfaces()
            # Prefer ethernet interfaces, then wireless
            for iface in interfaces:
                if iface.startswith(('eth', 'en')):
                    return iface
            for iface in interfaces:
                if iface.startswith('wl'):
                    return iface
            return interfaces[0] if interfaces else 'eth0'
        except Exception:
            return 'eth0'
    
    def _load_config(self, config_file: str) -> dict:
        """Load configuration from file or use defaults"""
        default_config = {
            'thresholds': {},
            'whitelist': ['127.0.0.1', '::1'],
            'block_duration': 300,  # 5 minutes
            'log_level': 'INFO'
        }
        
        if config_file and os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    config = json.load(f)
                    default_config.update(config)
            except Exception as e:
                print(f"Error loading config: {e}. Using defaults.")
        
        return default_config
    
    def _setup_logging(self):
        """Setup logging configuration"""
        log_level = getattr(logging, self.config.get('log_level', 'INFO'))
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('firewall.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def _cleanup_old_entries(self, ip: str):
        """Clean up old entries from tracking dictionaries"""
        current_time = datetime.now()
        minute_ago = current_time - timedelta(minutes=1)
        
        # Clean packet tracking
        while self.ip_packets[ip] and self.ip_packets[ip][0] < minute_ago:
            self.ip_packets[ip].popleft()
            
        # Clean connection tracking
        while self.ip_connections[ip] and self.ip_connections[ip][0] < minute_ago:
            self.ip_connections[ip].popleft()
            
        # Clean SYN packet tracking
        while self.ip_syn_packets[ip] and self.ip_syn_packets[ip][0] < minute_ago:
            self.ip_syn_packets[ip].popleft()
            
        # Clean ICMP packet tracking  
        while self.ip_icmp_packets[ip] and self.ip_icmp_packets[ip][0] < minute_ago:
            self.ip_icmp_packets[ip].popleft()
        
        # Reset port tracking every minute
        if current_time - self.ip_last_reset[ip] > timedelta(minutes=1):
            self.ip_ports[ip] = set()
            self.ip_last_reset[ip] = current_time
    
    def _is_whitelisted(self, ip: str) -> bool:
        """Check if IP is in whitelist"""
        return ip in self.whitelist
    
    def _block_ip(self, ip: str, reason: str):
        """Block an IP address using iptables"""
        if self._is_whitelisted(ip):
            self.logger.info(f"IP {ip} is whitelisted, not blocking")
            return
            
        with self.lock:
            if ip not in self.blocked_ips:
                try:
                    # Block incoming traffic from the IP
                    subprocess.run([
                        'sudo', 'iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'
                    ], check=True, capture_output=True)
                    
                    self.blocked_ips[ip] = datetime.now()
                    self.stats.blocked_ips.add(ip)
                    self.stats.attack_attempts[reason] += 1
                    
                    self.logger.warning(f"🚫 BLOCKED IP: {ip} - Reason: {reason}")
                    print(f"{Fore.RED}🚫 BLOCKED: {ip} - {reason}{Style.RESET_ALL}")
                    
                except subprocess.CalledProcessError as e:
                    self.logger.error(f"Failed to block IP {ip}: {e}")
    
    def _unblock_expired_ips(self):
        """Unblock IPs that have exceeded the block duration"""
        current_time = datetime.now()
        block_duration = timedelta(seconds=self.config.get('block_duration', 300))
        
        with self.lock:
            expired_ips = []
            for ip, block_time in self.blocked_ips.items():
                if current_time - block_time > block_duration:
                    expired_ips.append(ip)
            
            for ip in expired_ips:
                try:
                    subprocess.run([
                        'sudo', 'iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'
                    ], check=True, capture_output=True)
                    
                    del self.blocked_ips[ip]
                    self.logger.info(f"✅ UNBLOCKED IP: {ip}")
                    print(f"{Fore.GREEN}✅ UNBLOCKED: {ip}{Style.RESET_ALL}")
                    
                except subprocess.CalledProcessError:
                    # Rule might not exist, remove from tracking anyway
                    del self.blocked_ips[ip]
    
    def _detect_attacks(self, packet):
        """Analyze packet for potential attacks"""
        if not packet.haslayer(IP):
            return
            
        ip = packet[IP].src
        current_time = datetime.now()
        
        # Skip if already blocked
        if ip in self.blocked_ips:
            return
            
        # Clean old entries
        self._cleanup_old_entries(ip)
        
        # Track packet
        self.ip_packets[ip].append(current_time)
        
        # Check packet rate (potential DDoS)
        packet_count = len(self.ip_packets[ip])
        if packet_count > self.signatures.packet_rate_threshold:
            self._block_ip(ip, f"High packet rate: {packet_count}/min")
            return
        
        # Check for SYN flood
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            
            # Track connections
            self.ip_connections[ip].append(current_time)
            
            # Track SYN packets
            if tcp.flags & 0x02:  # SYN flag
                self.ip_syn_packets[ip].append(current_time)
                
                syn_count = len(self.ip_syn_packets[ip])
                if syn_count > self.signatures.syn_flood_threshold:
                    self._block_ip(ip, f"SYN flood: {syn_count}/min")
                    return
            
            # Track ports for port scanning detection
            self.ip_ports[ip].add(tcp.dport)
            
            port_count = len(self.ip_ports[ip])
            if port_count > self.signatures.port_scan_threshold:
                self._block_ip(ip, f"Port scan: {port_count} ports")
                return
            
            # Check connection rate
            conn_count = len(self.ip_connections[ip])
            if conn_count > self.signatures.connection_threshold:
                self._block_ip(ip, f"High connection rate: {conn_count}/min")
                return
        
        # Check for ICMP flood
        if packet.haslayer(ICMP):
            self.ip_icmp_packets[ip].append(current_time)
            
            icmp_count = len(self.ip_icmp_packets[ip])
            if icmp_count > self.signatures.icmp_flood_threshold:
                self._block_ip(ip, f"ICMP flood: {icmp_count}/min")
                return
    
    def _packet_handler(self, packet):
        """Handle each captured packet"""
        self.stats.packets_analyzed += 1
        self._detect_attacks(packet)
    
    def _cleanup_thread(self):
        """Background thread to clean up expired blocks"""
        while self.running:
            self._unblock_expired_ips()
            time.sleep(30)  # Check every 30 seconds
    
    def _stats_thread(self):
        """Background thread to display statistics"""
        while self.running:
            time.sleep(60)  # Update every minute
            self._display_stats()
    
    def _display_stats(self):
        """Display current firewall statistics"""
        print(f"\n{Fore.CYAN}=== Firewall Statistics ==={Style.RESET_ALL}")
        print(f"Uptime: {self.stats.get_uptime()}")
        print(f"Packets analyzed: {self.stats.packets_analyzed}")
        print(f"Currently blocked IPs: {len(self.blocked_ips)}")
        print(f"Total IPs blocked: {len(self.stats.blocked_ips)}")
        
        if self.stats.attack_attempts:
            print(f"\n{Fore.YELLOW}Attack Types Detected:{Style.RESET_ALL}")
            for attack_type, count in self.stats.attack_attempts.items():
                print(f"  {attack_type}: {count}")
        
        if self.blocked_ips:
            print(f"\n{Fore.RED}Currently Blocked IPs:{Style.RESET_ALL}")
            for ip in list(self.blocked_ips.keys())[:10]:  # Show first 10
                print(f"  {ip}")
    
    def start(self):
        """Start the firewall"""
        self.running = True
        
        print(f"{Fore.GREEN}🛡️  Starting Simple Firewall{Style.RESET_ALL}")
        print(f"Interface: {self.interface}")
        print(f"Block duration: {self.config.get('block_duration', 300)} seconds")
        print(f"Monitoring for DDoS/DoS attacks...")
        print(f"Press Ctrl+C to stop\n")
        
        # Start background threads
        cleanup_thread = threading.Thread(target=self._cleanup_thread, daemon=True)
        stats_thread = threading.Thread(target=self._stats_thread, daemon=True)
        
        cleanup_thread.start()
        stats_thread.start()
        
        try:
            # Start packet capture
            sniff(
                iface=self.interface,
                prn=self._packet_handler,
                store=False,
                stop_filter=lambda x: not self.running
            )
        except PermissionError:
            print(f"{Fore.RED}Error: Permission denied. Run with sudo.{Style.RESET_ALL}")
            sys.exit(1)
        except KeyboardInterrupt:
            self.stop()
        except Exception as e:
            self.logger.error(f"Error in packet capture: {e}")
            self.stop()
    
    def stop(self):
        """Stop the firewall and cleanup"""
        print(f"\n{Fore.YELLOW}Stopping firewall...{Style.RESET_ALL}")
        self.running = False
        
        # Display final stats
        self._display_stats()
        
        # Optional: Unblock all IPs on shutdown
        print(f"{Fore.YELLOW}Cleaning up iptables rules...{Style.RESET_ALL}")
        with self.lock:
            for ip in list(self.blocked_ips.keys()):
                try:
                    subprocess.run([
                        'sudo', 'iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'
                    ], capture_output=True)
                except subprocess.CalledProcessError:
                    pass  # Rule might not exist
        
        print(f"{Fore.GREEN}Firewall stopped.{Style.RESET_ALL}")

def main():
    parser = argparse.ArgumentParser(description='Simple DDoS/DoS Protection Firewall')
    parser.add_argument('-i', '--interface', help='Network interface to monitor')
    parser.add_argument('-c', '--config', help='Configuration file path')
    parser.add_argument('--stats', action='store_true', help='Show current statistics and exit')
    
    args = parser.parse_args()
    
    if args.stats:
        # Just show some basic system stats
        print(f"{Fore.CYAN}=== System Network Stats ==={Style.RESET_ALL}")
        try:
            stats = psutil.net_io_counters()
            print(f"Bytes sent: {stats.bytes_sent:,}")
            print(f"Bytes received: {stats.bytes_recv:,}")
            print(f"Packets sent: {stats.packets_sent:,}")
            print(f"Packets received: {stats.packets_recv:,}")
        except Exception as e:
            print(f"Error getting stats: {e}")
        return
    
    # Check if running as root
    if os.geteuid() != 0:
        print(f"{Fore.RED}This script requires root privileges to modify iptables.{Style.RESET_ALL}")
        print(f"Please run with: sudo python3 {sys.argv[0]}")
        sys.exit(1)
    
    firewall = SimpleFirewall(interface=args.interface, config_file=args.config)
    
    # Setup signal handlers
    def signal_handler(signum, frame):
        firewall.stop()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    firewall.start()

if __name__ == "__main__":
    main()
