from tests.test_base import IsolatedTestCase
from unittest import mock
import socket
import ssl
import http.client
import urllib.request
import analyzer
from qrshield.redirects import (
    NoRedirectHandler,
    PinnedHTTPHandler,
    PinnedHTTPSHandler,
    PinnedHTTPConnection,
    PinnedHTTPSConnection
)


class Tier2SecurityTestCase(IsolatedTestCase):
    """
    Tier 2 security tests verifying SSRF prevention and DNS pinning across TLS inspection
    and HTTP redirect handling.
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

    def test_ssrf_rejects_mixed_public_and_private_dns(self):
        """Hostnames returning mixed public and unsafe DNS answers are rejected fail-closed."""
        self.mock_dns.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))
        ]
        result = analyzer.is_unsafe_network_target("mixed.example.com")
        self.assertTrue(result["unsafe"])
        self.assertIn("Hostname resolves to a non-public IP address", result["reason"])

    def test_ssrf_rejects_ipv6_loopback_and_link_local(self):
        """Direct IPv6 loopback (::1) and link-local (fe80::1) addresses are blocked."""
        res_loopback = analyzer.is_unsafe_network_target("::1")
        self.assertTrue(res_loopback["unsafe"])
        self.assertEqual(res_loopback["reason"], "Non-public IP address")

        res_link_local = analyzer.is_unsafe_network_target("fe80::1")
        self.assertTrue(res_link_local["unsafe"])
        self.assertEqual(res_link_local["reason"], "Non-public IP address")

    def test_make_http_request_attaches_pinned_handlers(self):
        """make_http_request builds an opener with PinnedHTTPHandler bound to the pre-validated IP."""
        self.mock_dns.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))
        ]
        analyzer.make_http_request("http://safe.example.com/login", timeout=5)

        self.mock_opener.assert_called_once()
        args = self.mock_opener.call_args[0]

        has_no_redirect = any(isinstance(a, NoRedirectHandler) for a in args)
        http_handlers = [a for a in args if isinstance(a, PinnedHTTPHandler)]
        https_handlers = [a for a in args if isinstance(a, PinnedHTTPSHandler)]

        self.assertTrue(has_no_redirect, "NoRedirectHandler must be attached")
        self.assertEqual(len(http_handlers), 1)
        self.assertEqual(len(https_handlers), 1)
        self.assertEqual(http_handlers[0].pinned_ip, "93.184.216.34")
        self.assertEqual(https_handlers[0].pinned_ip, "93.184.216.34")

    def test_pinned_http_connection_targets_pinned_ip(self):
        """PinnedHTTPConnection connects TCP socket to pinned IP instead of resolving domain."""
        conn = PinnedHTTPConnection("safe.example.com", 80, pinned_ip="93.184.216.34")
        with mock.patch("socket.create_connection") as mock_conn:
            conn.connect()
            mock_conn.assert_called_once_with(("93.184.216.34", 80), conn.timeout, conn.source_address)

    def test_pinned_https_connection_targets_pinned_ip_with_sni(self):
        """PinnedHTTPSConnection connects TCP socket to pinned IP and preserves domain SNI."""
        ctx = ssl.create_default_context()
        conn = PinnedHTTPSConnection("secure.example.com", 443, pinned_ip="93.184.216.34", context=ctx)
        with mock.patch("socket.create_connection") as mock_conn:
            mock_sock = mock.MagicMock()
            mock_conn.return_value = mock_sock
            with mock.patch.object(ctx, "wrap_socket") as mock_wrap:
                conn.connect()
                # Socket created with pinned IP
                mock_conn.assert_called_once_with(("93.184.216.34", 443), conn.timeout, conn.source_address)
                # TLS wrap retains original hostname for SNI and certificate validation
                mock_wrap.assert_called_once_with(mock_sock, server_hostname="secure.example.com")

    def test_pinned_http_connection_explicit_port(self):
        """PinnedHTTPConnection correctly routes to explicit non-standard ports."""
        conn = PinnedHTTPConnection("safe.example.com:8080", pinned_ip="93.184.216.34")
        self.assertEqual(conn.host, "safe.example.com")
        self.assertEqual(conn.port, 8080)
        with mock.patch("socket.create_connection") as mock_conn:
            conn.connect()
            mock_conn.assert_called_once_with(("93.184.216.34", 8080), conn.timeout, conn.source_address)

    def test_pinned_connection_preserves_host_header(self):
        """PinnedHTTPConnection preserves the original Host header and port."""
        conn = PinnedHTTPConnection("custom.example:9000", pinned_ip="93.184.216.34")
        self.assertEqual(conn.host, "custom.example")
        self.assertEqual(conn.port, 9000)
        self.assertEqual(conn.pinned_ip, "93.184.216.34")

    def test_redirect_to_metadata_ip_blocked(self):
        """follow_redirect_chain terminates immediately if redirect target points to metadata IP."""
        def _mock_make_http_request(url, timeout=5):
            if url == "http://origin.example/start":
                return {
                    "success": True,
                    "url": url,
                    "status_code": 302,
                    "location": "http://169.254.169.254/latest/meta-data",
                    "headers": {},
                    "error": None
                }
            if "169.254.169.254" in url:
                return {
                    "success": False,
                    "url": url,
                    "status_code": None,
                    "location": None,
                    "headers": {},
                    "error": "Blocked network target: Non-public IP address"
                }
            return {"success": False, "url": url, "status_code": None, "location": None, "headers": {}, "error": "Unknown"}

        with mock.patch.object(analyzer, "make_http_request", side_effect=_mock_make_http_request):
            result = analyzer.follow_redirect_chain("http://origin.example/start")
            self.assertFalse(result["completed"])
            self.assertIn("Blocked network target", result["error"])
            self.assertEqual(result["redirect_count"], 1)

    def test_redirect_to_loopback_ip_blocked(self):
        """follow_redirect_chain terminates immediately if redirect target points to loopback IP."""
        def _mock_make_http_request(url, timeout=5):
            if url == "http://origin.example/redirect":
                return {
                    "success": True,
                    "url": url,
                    "status_code": 302,
                    "location": "http://127.0.0.1:8080/admin",
                    "headers": {},
                    "error": None
                }
            if "127.0.0.1" in url:
                return {
                    "success": False,
                    "url": url,
                    "status_code": None,
                    "location": None,
                    "headers": {},
                    "error": "Blocked network target: Non-public IP address"
                }
            return {"success": False, "url": url, "status_code": None, "location": None, "headers": {}, "error": "Unknown"}

        with mock.patch.object(analyzer, "make_http_request", side_effect=_mock_make_http_request):
            result = analyzer.follow_redirect_chain("http://origin.example/redirect")
            self.assertFalse(result["completed"])
            self.assertIn("Blocked network target", result["error"])
            self.assertEqual(result["redirect_count"], 1)

    def test_validate_redirect_target_dangerous_schemes(self):
        """validate_redirect_target rejects dangerous non-HTTP URI schemes."""
        dangerous = [
            "javascript:alert(1)",
            "file:///etc/passwd",
            "data:text/html,<b>pwn</b>",
            "ftp://files.example.com",
            "gopher://gopher.example.com",
            "mailto:admin@example.com"
        ]
        for target in dangerous:
            with self.subTest(target=target):
                res = analyzer.validate_redirect_target(target)
                self.assertFalse(res["valid"])
                self.assertEqual(res["reason"], "Unsupported redirect scheme")
