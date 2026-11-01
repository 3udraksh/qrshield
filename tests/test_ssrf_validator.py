from tests.test_base import IsolatedTestCase
from unittest import mock
import socket
import analyzer


class SSRFValidatorTestCase(IsolatedTestCase):
    """
    Tier 1 unit tests for is_unsafe_network_target() IP and hostname validator.
    """

    def test_empty_hostname(self):
        """Empty or None input is rejected."""
        res_none = analyzer.is_unsafe_network_target(None)
        self.assertTrue(res_none["unsafe"])
        self.assertEqual(res_none["reason"], "No hostname provided")

        res_empty = analyzer.is_unsafe_network_target("")
        self.assertTrue(res_empty["unsafe"])
        self.assertEqual(res_empty["reason"], "No hostname provided")

    def test_direct_non_public_ip_literals(self):
        """Direct non-public IPv4 and IPv6 addresses are blocked without DNS lookup."""
        non_public_ips = [
            "127.0.0.1",        # IPv4 loopback
            "127.0.1.1",        # IPv4 loopback block
            "10.0.0.1",         # RFC 1918 Private
            "172.16.0.1",       # RFC 1918 Private
            "192.168.1.1",      # RFC 1918 Private
            "169.254.169.254",  # Link-Local / Cloud Metadata
            "192.0.2.1",        # RFC 5737 TEST-NET-1 (Reserved)
            "198.51.100.1",     # RFC 5737 TEST-NET-2 (Reserved)
            "203.0.113.1",      # RFC 5737 TEST-NET-3 (Reserved)
            "224.0.0.1",        # Multicast
            "0.0.0.0",          # Unspecified
            "::1",              # IPv6 loopback
            "fe80::1",          # IPv6 link-local
            "::ffff:127.0.0.1", # IPv4-mapped IPv6 loopback
            "::ffff:10.0.0.1"   # IPv4-mapped IPv6 private
        ]
        for ip in non_public_ips:
            with self.subTest(ip=ip):
                res = analyzer.is_unsafe_network_target(ip)
                self.assertTrue(res["unsafe"], f"Expected {ip} to be unsafe")
                self.assertEqual(res["reason"], "Non-public IP address")

    def test_direct_public_ip_literal(self):
        """Routable public IP address is permitted."""
        res = analyzer.is_unsafe_network_target("93.184.216.34")
        self.assertFalse(res["unsafe"])
        self.assertIsNone(res["reason"])
        self.assertEqual(res["addresses"], ["93.184.216.34"])

    def test_hostname_resolving_to_private_ip(self):
        """Hostname resolving to a non-public IP is blocked."""
        self.mock_dns.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))
        ]
        res = analyzer.is_unsafe_network_target("localhost.localdomain")
        self.assertTrue(res["unsafe"])
        self.assertIn("Hostname resolves to a non-public IP address", res["reason"])

    def test_hostname_resolving_to_public_ip(self):
        """Hostname resolving to a routable public IP is permitted."""
        self.mock_dns.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))
        ]
        res = analyzer.is_unsafe_network_target("legit.example.com")
        self.assertFalse(res["unsafe"])
        self.assertIsNone(res["reason"])
        self.assertEqual(res["addresses"], ["93.184.216.34"])

    def test_dns_resolution_failure(self):
        """Hostname failing DNS resolution is treated as unsafe."""
        self.mock_dns.side_effect = socket.gaierror(-2, "Name or service not known")
        res = analyzer.is_unsafe_network_target("nonexistent.domain.example")
        self.assertTrue(res["unsafe"])
        self.assertEqual(res["reason"], "Hostname could not be resolved")

    def test_dns_resolution_timeout(self):
        """DNS resolution timeout is handled gracefully."""
        self.mock_dns.side_effect = socket.timeout("Timed out")
        res = analyzer.is_unsafe_network_target("slow.domain.example")
        self.assertTrue(res["unsafe"])
        self.assertEqual(res["reason"], "Hostname resolution timed out")
