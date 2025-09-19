#!/usr/bin/env python3
"""
Simple Firewall Runner
Main entry point for the DDoS/DoS protection firewall
"""

import sys
import os
import argparse
from simple_firewall import SimpleFirewall, main as firewall_main

# Import colorama for colored output
try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    HAS_COLORAMA = True
except ImportError:
    # Fallback if colorama is not available
    class MockColor:
        def __getattr__(self, name):
            return ""
    Fore = MockColor()
    Style = MockColor()
    HAS_COLORAMA = False

def show_banner():
    """Display banner"""
    print("=" * 60)
    print("🛡️  SIMPLE DDOS/DOS PROTECTION FIREWALL")
    print("=" * 60)
    print("Features:")
    print("• Real-time packet analysis")
    print("• SYN flood detection")
    print("• Port scan detection")
    print("• ICMP flood detection") 
    print("• Connection rate limiting")
    print("• Automatic IP blocking with iptables")
    print("• Configurable thresholds")
    print("=" * 60)

def show_usage():
    """Show usage instructions"""
    print("\nUsage Examples:")
    print("  sudo python3 run.py                    # Start with defaults")
    print("  sudo python3 run.py -i eth0           # Monitor specific interface")
    print("  sudo python3 run.py -c config.json    # Use custom config")
    print("  sudo python3 run.py --stats           # Show network statistics")
    print("\nTesting:")
    # print("  python3 test_attacks.py 127.0.0.1     # Test firewall (in another terminal)")
    print("\nConfiguration file (firewall_config.json):")
    print("  Edit thresholds, whitelist IPs, and block duration")
    print("\nLogs:")
    print("  Check firewall.log for detailed activity")

def main():
    show_banner()
    
    if len(sys.argv) == 1:
        show_usage()
        print(f"\nTo start the firewall, run: sudo python3 {sys.argv[0]} --start")
        return
    
    parser = argparse.ArgumentParser(description='Simple DDoS/DoS Protection Firewall')
    parser.add_argument('--start', action='store_true', help='Start the firewall')
    parser.add_argument('-i', '--interface', help='Network interface to monitor')
    parser.add_argument('-c', '--config', default='firewall_config.json', help='Configuration file')
    parser.add_argument('--stats', action='store_true', help='Show network statistics')
    parser.add_argument('--test', help='Run attack simulation against target IP')
    
    args = parser.parse_args()
    
    if args.stats:
        # Import and show stats
        try:
            import psutil
            
            print(f"\n{Fore.CYAN}=== Network Statistics ==={Style.RESET_ALL}")
            stats = psutil.net_io_counters()
            print(f"Bytes sent: {stats.bytes_sent:,}")
            print(f"Bytes received: {stats.bytes_recv:,}")
            print(f"Packets sent: {stats.packets_sent:,}")  
            print(f"Packets received: {stats.packets_recv:,}")
            
            print(f"\n{Fore.CYAN}=== Active Network Connections ==={Style.RESET_ALL}")
            connections = psutil.net_connections(kind='inet')
            conn_count = {}
            for conn in connections[:20]:  # Show first 20
                state = conn.status if hasattr(conn, 'status') else 'unknown'
                conn_count[state] = conn_count.get(state, 0) + 1
                if conn.raddr:
                    print(f"{conn.laddr[0]}:{conn.laddr[1]} -> {conn.raddr[0]}:{conn.raddr[1]} [{state}]")
                else:
                    print(f"{conn.laddr[0]}:{conn.laddr[1]} -> * [LISTENING]")
            
            print(f"\n{Fore.YELLOW}Connection States:{Style.RESET_ALL}")
            for state, count in conn_count.items():
                print(f"  {state}: {count}")
                
        except Exception as e:
            print(f"Error getting stats: {e}")
        return
    
    if args.test:
        print(f"\n{Fore.YELLOW}Starting attack simulation against {args.test}{Style.RESET_ALL}")
        print("Make sure the firewall is running in another terminal!")
        os.system(f"python3 test_attacks.py {args.test}")
        return
    
    if args.start:
        # Check root privileges
        if os.geteuid() != 0:
            print(f"\n{Fore.RED}❌ Root privileges required!{Style.RESET_ALL}")
            print(f"Run: sudo python3 {sys.argv[0]} --start")
            return
        
        # Start the firewall
        # print(f"\n{Fore.GREEN}🚀 Starting firewall...{Style.RESET_ALL}")
        print(f"Config: {args.config}")
        print(f"Interface: {args.interface or 'auto-detect'}")
        
        # Import the main firewall function and run it
        sys.argv = ['simple_firewall.py']
        if args.interface:
            sys.argv.extend(['-i', args.interface])
        if args.config:
            sys.argv.extend(['-c', args.config])
        
        firewall_main()
    else:
        show_usage()

if __name__ == "__main__":
    main()