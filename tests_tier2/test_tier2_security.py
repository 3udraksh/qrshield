from tests.test_base import IsolatedTestCase
from unittest import mock
import socket
import analyzer


class Tier2SecurityTestCase(IsolatedTestCase):
    """
    Tier 2 security tests verifying SSRF prevention and DNS pinning across TLS inspection.
    """

    def test_get_tls_certificate_blocks_loopback(self):
        """get_tls_certificate immediately blocks IPv4 loopback without attempting connection."""
        with mock.patch("socket.create_connection") as mock_conn:
            result = analyzer.get_tls_certificate("127.0.0.1", port=443)
            self.assertFalse(result["retrieved"])
            self.assertIn("Blocked unsafe network target", result["error"])
            mock_conn.assert_not_called()

    def test_get_tls_certificate_blocks_metadata_ip(self):
        """get_tls_certificate blocks link-local / cloud metadata address."""
        with mock.patch("socket.create_connection") as mock_conn:
            result = analyzer.get_tls_certificate("169.254.169.254", port=443)
            self.assertFalse(result["retrieved"])
            self.assertIn("Blocked unsafe network target", result["error"])
            mock_conn.assert_not_called()

    def test_get_tls_certificate_blocks_private_ip(self):
        """get_tls_certificate blocks RFC 1918 private address."""
        with mock.patch("socket.create_connection") as mock_conn:
            result = analyzer.get_tls_certificate("10.0.0.1", port=8443)
            self.assertFalse(result["retrieved"])
            self.assertIn("Blocked unsafe network target", result["error"])
            mock_conn.assert_not_called()

    def test_get_tls_certificate_dns_pinning(self):
        """get_tls_certificate pins the socket connection to the pre-validated IP address."""
        self.mock_dns.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))
        ]
        with mock.patch("socket.create_connection") as mock_conn:
            # Mock the context wrapper
            mock_sock = mock.MagicMock()
            mock_conn.return_value.__enter__.return_value = mock_sock
            with mock.patch("ssl.SSLContext.wrap_socket") as mock_wrap:
                mock_ssl_sock = mock.MagicMock()
                mock_ssl_sock.getpeercert.return_value = b"test_cert_der"
                mock_wrap.return_value.__enter__.return_value = mock_ssl_sock

                result = analyzer.get_tls_certificate("safe.example.com", port=443)
                self.assertTrue(result["retrieved"])
                # Connect must target the validated IP, not the unpinned hostname
                mock_conn.assert_called_once_with(("93.184.216.34", 443), timeout=5)
                # wrap_socket must send the original hostname as SNI
                mock_wrap.assert_called_once_with(mock_sock, server_hostname="safe.example.com")

    def test_get_tls_connection_blocks_unsafe_target(self):
        """get_tls_connection blocks unsafe network destination."""
        with mock.patch("socket.create_connection") as mock_conn:
            result = analyzer.get_tls_connection("127.0.0.1", port=443)
            self.assertFalse(result["connected"])
            self.assertIn("Blocked unsafe network target", result["error"])
            mock_conn.assert_not_called()

    def test_make_http_request_blocks_unsafe_target(self):
        """make_http_request blocks non-public IP targets."""
        result = analyzer.make_http_request("http://127.0.0.1:8080/admin")
        self.assertFalse(result["success"])
        self.assertIn("Blocked network target", result["error"])
