# Simple DDoS/DoS Protection Firewall

A lightweight, real-time firewall that monitors network traffic and automatically blocks DDoS/DoS attacks on your local system.

## Features

🛡️ **Attack Detection:**
- SYN flood attacks
- Port scanning attempts
- ICMP flood attacks
- High connection rate attacks
- Excessive packet rate monitoring

🚫 **Protection Mechanisms:**
- Automatic IP blocking using iptables
- Configurable attack thresholds
- Time-based blocking with auto-unblock
- IP whitelisting support
- Real-time monitoring and logging

📊 **Monitoring:**
- Real-time statistics display
- Comprehensive logging
- Attack type classification
- Network interface monitoring

## Quick Start

1. **Install dependencies:**
   ```bash
   pip install scapy psutil colorama netifaces
   ```

2. **Start the firewall:**
   ```bash
   sudo python3 run.py --start
   ```

3. **Test the firewall** (in another terminal):
   ```bash
   python3 test_attacks.py 127.0.0.1
   ```

## Usage

### Basic Commands

```bash
# Show help and usage
python3 run.py

# Start firewall with default settings
sudo python3 run.py --start

# Monitor specific network interface
sudo python3 run.py --start -i eth0

# Use custom configuration file
sudo python3 run.py --start -c my_config.json

# Show network statistics
python3 run.py --stats

# Test firewall with simulated attacks
python3 run.py --test 127.0.0.1
```

### Direct Firewall Usage

```bash
# Start firewall directly
sudo python3 simple_firewall.py

# Monitor specific interface
sudo python3 simple_firewall.py -i wlan0

# Use custom config
sudo python3 simple_firewall.py -c firewall_config.json

# Show statistics only
sudo python3 simple_firewall.py --stats
```

## Configuration

Edit `firewall_config.json` to customize thresholds:

```json
{
    "thresholds": {
        "syn_flood_threshold": 100,     // SYN packets per minute
        "connection_threshold": 50,      // Connections per IP per minute
        "packet_rate_threshold": 1000,   // Total packets per IP per minute
        "port_scan_threshold": 20,       // Different ports accessed per minute
        "icmp_flood_threshold": 100      // ICMP packets per minute
    },
    "whitelist": [
        "127.0.0.1",                    // Always allow localhost
        "192.168.1.1"                   // Add trusted IPs here
    ],
    "block_duration": 300,              // Block duration in seconds (5 minutes)
    "log_level": "INFO"                 // Logging level
}
```

## How It Works

1. **Packet Capture:** Uses Scapy to capture and analyze network packets in real-time
2. **Pattern Detection:** Monitors for suspicious patterns:
   - High packet rates from single IPs
   - Excessive SYN packets (SYN flood)
   - Port scanning behavior
   - ICMP flooding
   - Rapid connection attempts

3. **Automatic Blocking:** When thresholds are exceeded:
   - Adds iptables rule to drop packets from attacking IP
   - Logs the attack with details
   - Displays real-time alerts
   - Automatically unblocks IPs after configured duration

4. **Monitoring:** Provides real-time statistics and maintains detailed logs

## Files

- `run.py` - Main entry point with user-friendly interface
- `simple_firewall.py` - Core firewall implementation
- `test_attacks.py` - Attack simulation for testing
- `firewall_config.json` - Configuration file
- `firewall.log` - Activity log file (created when running)

## Requirements

- **Python 3.6+**
- **Root privileges** (required for iptables access)
- **Linux system** (uses iptables for blocking)

### Python Packages:
- `scapy` - Packet capture and analysis
- `psutil` - System and network statistics
- `colorama` - Colored terminal output  
- `netifaces` - Network interface detection

## Testing

The included test script can simulate various types of attacks:

```bash
# Simulate all attack types
sudo python3 test_attacks.py 127.0.0.1

# Specific attack types
sudo python3 test_attacks.py 127.0.0.1 --attack-type syn
sudo python3 test_attacks.py 127.0.0.1 --attack-type port
sudo python3 test_attacks.py 127.0.0.1 --attack-type icmp

# Custom duration and port
sudo python3 test_attacks.py 192.168.1.100 --port 8080 --duration 60
```

**⚠️ Warning:** Only test against systems you own or have explicit permission to test!

## Monitoring and Logs

The firewall provides several ways to monitor activity:

### Real-time Display
- Attack alerts with color coding
- Statistics updated every minute
- Currently blocked IPs
- Attack type breakdown

### Log Files
Check `firewall.log` for detailed activity:
```bash
tail -f firewall.log
```

### Network Statistics
```bash
python3 run.py --stats
```

## Troubleshooting

### Permission Errors
```bash
# Make sure to run with sudo
sudo python3 run.py --start
```

### Interface Detection Issues
```bash
# List available interfaces
ip link show

# Specify interface manually
sudo python3 run.py --start -i eth0
```

### Blocked Legitimate Traffic
- Add trusted IPs to whitelist in config
- Adjust thresholds if too sensitive
- Check `firewall.log` for blocking reasons

### Unblocking IPs Manually
```bash
# List current iptables rules
sudo iptables -L INPUT -n

# Remove specific rule
sudo iptables -D INPUT -s [IP_ADDRESS] -j DROP

# Clear all INPUT rules (use with caution)
sudo iptables -F INPUT
```

## Limitations

- **Linux Only:** Uses iptables for blocking (Linux-specific)
- **IPv4 Focus:** Primarily designed for IPv4 traffic
- **Root Required:** Needs root privileges for iptables access
- **Basic Detection:** Simple threshold-based detection (not ML-based)

## Security Notes

- This is a **basic firewall** for common attack patterns
- Should be used alongside other security measures
- Test thoroughly before deploying in production
- Monitor logs regularly for false positives
- Keep whitelist updated with trusted IPs

## License

This project is provided as-is for educational and defensive purposes. Use responsibly and only on systems you own or have permission to protect.
