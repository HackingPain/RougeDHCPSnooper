#!/usr/bin/env python3
"""
RougeDHCPSnooper - A Python-based rogue DHCP server detection tool
Author: Network Security Tool
License: Educational and authorized security testing purposes only
"""

import sys
import os
import logging
import re
import subprocess
import argparse
import json
from datetime import datetime
from typing import List, Dict, Tuple, Optional

# Suppress Scapy warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.interactive").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)

try:
    from scapy.all import *  # type: ignore
    from scapy.layers.dhcp import DHCP, BOOTP  # type: ignore
    from scapy.layers.inet import IP, UDP  # type: ignore
    from scapy.layers.l2 import Ether  # type: ignore
    from scapy.sendrecv import srp  # type: ignore
    from scapy.config import conf  # type: ignore
    from scapy.arch import get_if_raw_hwaddr  # type: ignore
except ImportError:
    print("Scapy is not installed on your system.")
    print("Try using: sudo pip3 install scapy")
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('dhcp_snooper.log'),
        logging.StreamHandler()
    ]
)

class DHCPSnooper:
    """Main class for DHCP snooping functionality"""
    
    def __init__(self, whitelist_file: str = "dhcp_whitelist.txt", 
                 timeout: int = 5, verbose: bool = False):
        """
        Initialize the DHCP snooper
        
        Args:
            whitelist_file: Path to file containing authorized DHCP servers
            timeout: Timeout for DHCP discovery in seconds
            verbose: Enable verbose logging
        """
        self.whitelist_file = whitelist_file
        self.timeout = timeout
        self.verbose = verbose
        self.logger = logging.getLogger(__name__)
        
        # Disable Scapy's IP address checking for broadcast packets
        conf.checkIPaddr = False
        
        # Initialize data structures
        self.authorized_servers = self._load_whitelist()
        self.discovered_servers = {}
        self.rogue_servers = []
        
        if verbose:
            self.logger.setLevel(logging.DEBUG)
    
    def _load_whitelist(self) -> List[str]:
        """Load authorized DHCP servers from whitelist file"""
        try:
            with open(self.whitelist_file, 'r') as f:
                servers = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            self.logger.info(f"Loaded {len(servers)} authorized DHCP servers from {self.whitelist_file}")
            return servers
        except FileNotFoundError:
            self.logger.warning(f"Whitelist file {self.whitelist_file} not found. Creating sample file.")
            self._create_sample_whitelist()
            return []
        except Exception as e:
            self.logger.error(f"Error loading whitelist: {e}")
            return []
    
    def _create_sample_whitelist(self):
        """Create a sample whitelist file"""
        sample_content = """# Authorized DHCP Servers
# Add one IP address per line
# Lines starting with # are comments
192.168.1.1
10.0.0.1
172.16.0.1
"""
        try:
            with open(self.whitelist_file, 'w') as f:
                f.write(sample_content)
            self.logger.info(f"Created sample whitelist file: {self.whitelist_file}")
        except Exception as e:
            self.logger.error(f"Error creating sample whitelist: {e}")
    
    def get_network_interfaces(self) -> List[str]:
        """Get all network interfaces except loopback"""
        interfaces = []
        try:
            # Get interfaces using subprocess
            result = subprocess.run(['ip', 'link', 'show'], 
                                  capture_output=True, text=True, check=True)
            
            # Parse interface names using regex
            interface_pattern = r'^\d+:\s+([^:]+):'
            for line in result.stdout.split('\n'):
                match = re.match(interface_pattern, line)
                if match:
                    interface_name = match.group(1)
                    # Skip loopback and other virtual interfaces
                    if interface_name != "lo" and not interface_name.startswith("virbr"):
                        interfaces.append(interface_name)
            
            self.logger.info(f"Found {len(interfaces)} network interfaces: {interfaces}")
            return interfaces
            
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Error getting network interfaces: {e}")
            return []
        except Exception as e:
            self.logger.error(f"Unexpected error getting interfaces: {e}")
            return []
    
    def create_dhcp_discover(self, interface: str) -> Optional[Ether]:
        """Create a DHCP Discover packet for the specified interface"""
        try:
            # Get hardware address for the interface
            hw_addr = get_if_raw_hwaddr(interface)[1]
            
            # Create DHCP Discover packet
            dhcp_discover = (
                Ether(dst="ff:ff:ff:ff:ff:ff") /
                IP(src="0.0.0.0", dst="255.255.255.255") /
                UDP(sport=68, dport=67) /
                BOOTP(chaddr=hw_addr) /
                DHCP(options=[("message-type", "discover"), "end"])
            )
            
            self.logger.debug(f"Created DHCP Discover packet for interface {interface}")
            return dhcp_discover
            
        except Exception as e:
            self.logger.error(f"Error creating DHCP Discover packet for {interface}: {e}")
            return None
    
    def send_discovery(self, interface: str) -> Dict[str, str]:
        """Send DHCP discovery packet and collect responses"""
        discovered = {}
        
        try:
            dhcp_discover = self.create_dhcp_discover(interface)
            if not dhcp_discover:
                return discovered
            
            self.logger.info(f"Sending DHCP discovery on interface {interface}")
            
            # Send packet and wait for responses
            ans, unans = srp(dhcp_discover, multi=True, iface=interface, 
                           timeout=self.timeout, verbose=0)
            
            # Process responses
            for request, response in ans:
                if response.haslayer(DHCP):
                    server_ip = response[IP].src
                    server_mac = response[Ether].src
                    discovered[server_mac] = server_ip
                    
                    self.logger.debug(f"Found DHCP server: IP={server_ip}, MAC={server_mac}")
            
            return discovered
            
        except Exception as e:
            self.logger.error(f"Error during DHCP discovery on {interface}: {e}")
            return discovered
    
    def validate_servers(self, discovered_servers: Dict[str, str]) -> Tuple[List, List]:
        """Validate discovered servers against whitelist"""
        authorized = []
        rogue = []
        
        for mac, ip in discovered_servers.items():
            server_info = {"ip": ip, "mac": mac, "timestamp": datetime.now().isoformat()}
            
            if ip in self.authorized_servers:
                authorized.append(server_info)
                self.logger.info(f"✓ Authorized DHCP server found: {ip} ({mac})")
            else:
                rogue.append(server_info)
                self.logger.warning(f"⚠ ROGUE DHCP server detected: {ip} ({mac})")
        
        return authorized, rogue
    
    def generate_alert(self, rogue_servers: List[Dict]):
        """Generate alerts for rogue DHCP servers"""
        if not rogue_servers:
            self.logger.info("No rogue DHCP servers detected.")
            return
        
        alert_msg = f"\n{'='*60}\n"
        alert_msg += f"🚨 SECURITY ALERT: {len(rogue_servers)} ROGUE DHCP SERVER(S) DETECTED!\n"
        alert_msg += f"{'='*60}\n"
        
        for server in rogue_servers:
            alert_msg += f"IP Address: {server['ip']}\n"
            alert_msg += f"MAC Address: {server['mac']}\n"
            alert_msg += f"Detected at: {server['timestamp']}\n"
            alert_msg += f"{'-'*40}\n"
        
        alert_msg += f"IMMEDIATE ACTION REQUIRED:\n"
        alert_msg += f"1. Investigate the source of unauthorized DHCP servers\n"
        alert_msg += f"2. Disable rogue DHCP servers\n"
        alert_msg += f"3. Update network security policies\n"
        alert_msg += f"{'='*60}\n"
        
        print(alert_msg)
        self.logger.critical(alert_msg)
    
    def save_results(self, filename: str = "dhcp_scan_results.json"):
        """Save scan results to JSON file"""
        results = {
            "scan_timestamp": datetime.now().isoformat(),
            "authorized_servers": self.authorized_servers,
            "discovered_servers": self.discovered_servers,
            "rogue_servers": self.rogue_servers
        }
        
        try:
            with open(filename, 'w') as f:
                json.dump(results, f, indent=2)
            self.logger.info(f"Results saved to {filename}")
        except Exception as e:
            self.logger.error(f"Error saving results: {e}")
    
    def run_scan(self):
        """Main scanning function"""
        self.logger.info("Starting DHCP snooping scan...")
        
        # Get network interfaces
        interfaces = self.get_network_interfaces()
        if not interfaces:
            self.logger.error("No network interfaces found. Exiting.")
            return
        
        # Scan each interface
        all_discovered = {}
        for interface in interfaces:
            self.logger.info(f"Scanning interface: {interface}")
            discovered = self.send_discovery(interface)
            all_discovered.update(discovered)
        
        # Store results
        self.discovered_servers = all_discovered
        
        # Validate servers
        authorized, rogue = self.validate_servers(all_discovered)
        self.rogue_servers = rogue
        
        # Generate alerts
        self.generate_alert(rogue)
        
        # Save results
        self.save_results()
        
        # Summary
        self.logger.info(f"Scan complete. Found {len(all_discovered)} DHCP servers total.")
        self.logger.info(f"Authorized: {len(authorized)}, Rogue: {len(rogue)}")

def main():
    """Main function with command-line interface"""
    parser = argparse.ArgumentParser(description="DHCP Rogue Server Detection Tool")
    parser.add_argument("-w", "--whitelist", default="dhcp_whitelist.txt",
                       help="Path to whitelist file (default: dhcp_whitelist.txt)")
    parser.add_argument("-t", "--timeout", type=int, default=5,
                       help="Timeout for DHCP discovery in seconds (default: 5)")
    parser.add_argument("-v", "--verbose", action="store_true",
                       help="Enable verbose logging")
    parser.add_argument("-o", "--output", default="dhcp_scan_results.json",
                       help="Output file for results (default: dhcp_scan_results.json)")
    
    args = parser.parse_args()
    
    # Check if running as root
    if os.geteuid() != 0:
        print("This script requires root privileges to manipulate network packets.")
        print("Please run with sudo.")
        sys.exit(1)
    
    # Initialize and run snooper
    snooper = DHCPSnooper(
        whitelist_file=args.whitelist,
        timeout=args.timeout,
        verbose=args.verbose
    )
    
    try:
        snooper.run_scan()
    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
        sys.exit(0)
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()