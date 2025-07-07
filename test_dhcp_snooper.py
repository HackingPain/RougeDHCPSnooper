#!/usr/bin/env python3
"""
Unit tests for RougeDHCPSnooper
"""

import unittest
import tempfile
import os
import json
from unittest.mock import Mock, patch, MagicMock
from dhcp_snooper import DHCPSnooper

class TestDHCPSnooper(unittest.TestCase):
    """Test cases for DHCPSnooper class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.test_whitelist = tempfile.NamedTemporaryFile(mode='w', delete=False)
        self.test_whitelist.write("192.168.1.1\n10.0.0.1\n172.16.0.1\n")
        self.test_whitelist.close()
        
        self.snooper = DHCPSnooper(whitelist_file=self.test_whitelist.name)
    
    def tearDown(self):
        """Clean up test fixtures"""
        os.unlink(self.test_whitelist.name)
    
    def test_load_whitelist_success(self):
        """Test successful whitelist loading"""
        expected_servers = ["192.168.1.1", "10.0.0.1", "172.16.0.1"]
        self.assertEqual(self.snooper.authorized_servers, expected_servers)
    
    def test_load_whitelist_file_not_found(self):
        """Test whitelist loading when file doesn't exist"""
        snooper = DHCPSnooper(whitelist_file="nonexistent.txt")
        self.assertEqual(snooper.authorized_servers, [])
    
    def test_create_sample_whitelist(self):
        """Test sample whitelist creation"""
        test_file = tempfile.NamedTemporaryFile(delete=False)
        test_file.close()
        os.unlink(test_file.name)
        
        snooper = DHCPSnooper(whitelist_file=test_file.name)
        self.assertTrue(os.path.exists(test_file.name))
        
        # Clean up
        os.unlink(test_file.name)
    
    @patch('dhcp_snooper.subprocess.run')
    def test_get_network_interfaces(self, mock_run):
        """Test network interface discovery"""
        # Mock subprocess output
        mock_run.return_value = Mock()
        mock_run.return_value.stdout = """1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP mode DEFAULT group default qlen 1000
3: wlan0: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN mode DEFAULT group default qlen 1000"""
        
        interfaces = self.snooper.get_network_interfaces()
        expected_interfaces = ["eth0", "wlan0"]
        self.assertEqual(interfaces, expected_interfaces)
    
    def test_validate_servers_authorized(self):
        """Test server validation with authorized servers"""
        discovered = {"aa:bb:cc:dd:ee:ff": "192.168.1.1"}
        authorized, rogue = self.snooper.validate_servers(discovered)
        
        self.assertEqual(len(authorized), 1)
        self.assertEqual(len(rogue), 0)
        self.assertEqual(authorized[0]["ip"], "192.168.1.1")
    
    def test_validate_servers_rogue(self):
        """Test server validation with rogue servers"""
        discovered = {"aa:bb:cc:dd:ee:ff": "192.168.1.100"}
        authorized, rogue = self.snooper.validate_servers(discovered)
        
        self.assertEqual(len(authorized), 0)
        self.assertEqual(len(rogue), 1)
        self.assertEqual(rogue[0]["ip"], "192.168.1.100")
    
    def test_validate_servers_mixed(self):
        """Test server validation with mixed authorized and rogue servers"""
        discovered = {
            "aa:bb:cc:dd:ee:ff": "192.168.1.1",  # authorized
            "11:22:33:44:55:66": "192.168.1.100"  # rogue
        }
        authorized, rogue = self.snooper.validate_servers(discovered)
        
        self.assertEqual(len(authorized), 1)
        self.assertEqual(len(rogue), 1)
        self.assertEqual(authorized[0]["ip"], "192.168.1.1")
        self.assertEqual(rogue[0]["ip"], "192.168.1.100")
    
    def test_save_results(self):
        """Test results saving functionality"""
        test_file = tempfile.NamedTemporaryFile(delete=False)
        test_file.close()
        
        # Set up test data
        self.snooper.discovered_servers = {"aa:bb:cc:dd:ee:ff": "192.168.1.1"}
        self.snooper.rogue_servers = [{"ip": "192.168.1.100", "mac": "11:22:33:44:55:66"}]
        
        # Save results
        self.snooper.save_results(test_file.name)
        
        # Verify file was created and contains expected data
        self.assertTrue(os.path.exists(test_file.name))
        
        with open(test_file.name, 'r') as f:
            results = json.load(f)
        
        self.assertIn("scan_timestamp", results)
        self.assertIn("authorized_servers", results)
        self.assertIn("discovered_servers", results)
        self.assertIn("rogue_servers", results)
        
        # Clean up
        os.unlink(test_file.name)

class TestDHCPSnooperIntegration(unittest.TestCase):
    """Integration tests for DHCPSnooper"""
    
    @patch('dhcp_snooper.get_if_raw_hwaddr')
    @patch('dhcp_snooper.srp')
    def test_create_dhcp_discover_packet(self, mock_srp, mock_get_hw):
        """Test DHCP discover packet creation"""
        # Mock hardware address
        mock_get_hw.return_value = (None, b'\xaa\xbb\xcc\xdd\xee\xff')
        
        snooper = DHCPSnooper()
        packet = snooper.create_dhcp_discover("eth0")
        
        self.assertIsNotNone(packet)
        # Verify packet structure if packet exists
        if packet:
            self.assertTrue(packet.haslayer("Ether"))
            self.assertTrue(packet.haslayer("IP"))
            self.assertTrue(packet.haslayer("UDP"))
            self.assertTrue(packet.haslayer("BOOTP"))
            self.assertTrue(packet.haslayer("DHCP"))

if __name__ == '__main__':
    unittest.main()