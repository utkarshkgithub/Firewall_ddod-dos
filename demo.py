#!/usr/bin/env python3
"""
Demo script showing firewall capabilities without requiring root access
"""

import json
import time
from datetime import datetime, timedelta
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

def load_config():
    """Load the firewall configuration"""
    try:
        with open('firewall_config.json', 'r') as f:
            return json.load(f)
    except Exception:
        return {
            "thresholds": {
                "syn_flood_threshold": 100,
                "connection_threshold": 50,
                "packet_rate_threshold": 1000,
                "port_scan_threshold": 20,
                "icmp_flood_threshold": 100
            },
            "block_duration": 300
        }

def simulate_attack_detection():
    """Simulate what the firewall would detect"""
    config = load_config()
    
    print(f"{Fore.CYAN}🛡️  Firewall Attack Detection Demo{Style.RESET_ALL}")
    print("=" * 50)
    
    # Show configuration
    print(f"{Fore.YELLOW}Current Thresholds:{Style.RESET_ALL}")
    for key, value in config['thresholds'].items():
        print(f"  {key.replace('_', ' ').title()}: {value}")
    
    print(f"\nBlock Duration: {config.get('block_duration', 300)} seconds")
    print(f"Whitelist: {', '.join(['127.0.0.1', '::1', '192.168.1.1'])}")
    
    print(f"\n{Fore.GREEN}🔍 Monitoring Network Traffic...{Style.RESET_ALL}")
    
    # Simulate different attack scenarios
    scenarios = [
        {
            "ip": "203.0.113.45",
            "attack": "SYN Flood",
            "packets": 150,
            "threshold": config['thresholds']['syn_flood_threshold'],
            "description": "Excessive SYN packets detected"
        },
        {
            "ip": "198.51.100.23",
            "attack": "Port Scan", 
            "packets": 25,
            "threshold": config['thresholds']['port_scan_threshold'],
            "description": "Scanning multiple ports"
        },
        {
            "ip": "192.0.2.100",
            "attack": "ICMP Flood",
            "packets": 120,
            "threshold": config['thresholds']['icmp_flood_threshold'],
            "description": "ICMP ping flood detected"
        },
        {
            "ip": "203.0.113.77",
            "attack": "Connection Flood",
            "packets": 75,
            "threshold": config['thresholds']['connection_threshold'],
            "description": "Rapid connection attempts"
        }
    ]
    
    blocked_ips = []
    
    for i, scenario in enumerate(scenarios):
        time.sleep(1)
        
        print(f"\n📊 Analyzing traffic from {scenario['ip']}...")
        print(f"   {scenario['attack']}: {scenario['packets']}/min (threshold: {scenario['threshold']}/min)")
        
        if scenario['packets'] > scenario['threshold']:
            print(f"{Fore.RED}🚨 ATTACK DETECTED: {scenario['attack']} from {scenario['ip']}{Style.RESET_ALL}")
            print(f"{Fore.RED}🚫 BLOCKING IP: {scenario['ip']} - {scenario['description']}{Style.RESET_ALL}")
            blocked_ips.append({
                'ip': scenario['ip'],
                'reason': scenario['attack'],
                'time': datetime.now()
            })
        else:
            print(f"{Fore.GREEN}✅ Traffic within normal limits{Style.RESET_ALL}")
    
    # Show summary
    print(f"\n{Fore.CYAN}📋 Attack Detection Summary{Style.RESET_ALL}")
    print("=" * 30)
    print(f"Total packets analyzed: {sum(s['packets'] for s in scenarios)}")
    print(f"Attacks detected: {len(blocked_ips)}")
    print(f"IPs blocked: {len(blocked_ips)}")
    
    if blocked_ips:
        print(f"\n{Fore.RED}🚫 Blocked IPs:{Style.RESET_ALL}")
        for block in blocked_ips:
            print(f"  {block['ip']} - {block['reason']} at {block['time'].strftime('%H:%M:%S')}")
    
    print(f"\n{Fore.YELLOW}ℹ️  In real operation:{Style.RESET_ALL}")
    print("  • These IPs would be blocked via iptables")
    print("  • Blocking would last 5 minutes (configurable)")
    print("  • All activity would be logged to firewall.log")
    print("  • Real-time monitoring of network interfaces")

def show_features():
    """Show detailed firewall features"""
    print(f"\n{Fore.CYAN}🛡️  Firewall Features{Style.RESET_ALL}")
    print("=" * 25)
    
    features = [
        ("Real-time Monitoring", "Captures and analyzes all network packets"),
        ("SYN Flood Protection", "Detects TCP SYN flood attacks"),
        ("Port Scan Detection", "Identifies port scanning attempts"),
        ("ICMP Flood Protection", "Blocks ICMP ping floods"),
        ("Connection Rate Limiting", "Prevents connection flooding"),
        ("Automatic IP Blocking", "Uses iptables to block malicious IPs"),
        ("Configurable Thresholds", "Customize detection sensitivity"),
        ("IP Whitelisting", "Protect trusted IP addresses"),
        ("Time-based Unblocking", "Automatically unblock IPs after timeout"),
        ("Comprehensive Logging", "Detailed logs of all firewall activity"),
        ("Real-time Statistics", "Live monitoring dashboard"),
        ("Multi-interface Support", "Monitor specific network interfaces")
    ]
    
    for feature, description in features:
        print(f"{Fore.GREEN}✅{Style.RESET_ALL} {Fore.YELLOW}{feature}:{Style.RESET_ALL} {description}")

def main():
    print(f"{Fore.MAGENTA}{'=' * 60}{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA}🛡️  SIMPLE DDOS/DOS PROTECTION FIREWALL DEMO{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA}{'=' * 60}{Style.RESET_ALL}")
    
    show_features()
    
    print(f"\n{Fore.CYAN}Press Enter to run attack detection demo...{Style.RESET_ALL}")
    input()
    
    simulate_attack_detection()
    
    print(f"\n{Fore.GREEN}🚀 To start the real firewall:{Style.RESET_ALL}")
    print(f"   sudo python3 run.py --start")
    print(f"\n{Fore.YELLOW}🧪 To test the firewall:{Style.RESET_ALL}")
    print(f"   python3 test_attacks.py 127.0.0.1")
    
    print(f"\n{Fore.BLUE}📖 See README.md for complete documentation{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
