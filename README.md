# RougeDHCPSnooper
A Python-based rogue DHCP server detection tool for network security monitoring.

## Features

- **DHCP Message Validation**: Validates DHCP messages and filters out invalid communications
- **Rogue Server Detection**: Identifies unauthorized DHCP servers on the network  
- **Real-time Alerts**: Provides immediate notifications with IP and MAC addresses of suspicious devices
- **Whitelist Support**: Maintains a list of authorized DHCP servers for comparison
- **Multi-interface Scanning**: Monitors all network interfaces except loopback

## How It Works

### DHCP Protocol Overview
DHCP (Dynamic Host Configuration Protocol) operates on the application layer using UDP ports 67 (server) and 68 (client). The protocol involves an 8-message exchange process:

1. **DHCP Discover** - Client broadcasts to find available DHCP servers
2. **DHCP Offer** - Server responds with available IP and configuration
3. **DHCP Request** - Client requests specific IP address
4. **DHCP Acknowledgment** - Server confirms IP assignment
5. **DHCP Negative Acknowledgment** - Server denies request (pool exhausted)
6. **DHCP Decline** - Client rejects invalid configuration
7. **DHCP Release** - Client releases IP address
8. **DHCP Inform** - Client requests configuration without IP assignment

### Detection Method
The tool works by:
1. Creating DHCP Discover packets for each network interface
2. Broadcasting these packets to detect responding DHCP servers
3. Comparing discovered servers against a whitelist of authorized servers
4. Alerting on any unauthorized DHCP responses

## Requirements

- Python 3.6+
- Scapy library
- Root/administrator privileges for network packet manipulation
- Network access to interfaces being monitored

## Installation

```bash
sudo pip3 install scapy
```

## Usage

```bash
sudo python3 dhcp_snooper.py
```

## Configuration

Create a `dhcp_whitelist.txt` file with authorized DHCP server IP addresses (one per line):
```
192.168.1.1
10.0.0.1
```

## Architecture

### Core Components
- **Interface Discovery**: Identifies available network interfaces
- **Packet Crafting**: Creates properly formatted DHCP Discover packets
- **Response Analysis**: Processes DHCP Offer responses
- **Whitelist Validation**: Compares discovered servers against authorized list
- **Alert System**: Notifies users of rogue server detection

### Key Functions
- `get_network_interfaces()`: Lists all available network interfaces
- `create_dhcp_discover()`: Constructs DHCP discovery packets
- `send_discovery()`: Broadcasts discovery packets and collects responses
- `validate_servers()`: Compares responses against whitelist
- `generate_alerts()`: Creates notifications for rogue servers

## Security Considerations

- Requires elevated privileges for packet manipulation
- Should be run in controlled network environments
- May generate network traffic that could be detected by IDS systems
- Ensure proper authorization before scanning networks

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is for educational and authorized security testing purposes only.

## References

- saurabhsharma56. (2018). DHCP Protocol Overview
- Kumar. (2020). Python subprocess module
- nikhilaggarwal3 & rkbhola5. (2022). Regular expressions in Python
- Scapy Documentation. (n.d.). Network packet manipulation
