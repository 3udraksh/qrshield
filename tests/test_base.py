import unittest
from unittest import mock
import tempfile
import os
import socket
import app
import analyzer


class IsolatedTestCase(unittest.TestCase):
    """
    Base test case ensuring complete filesystem and network isolation.
    All setup operations register self.addCleanup() in LIFO order.
    """

    def setUp(self):
        # 1. Ephemeral workspace directory (registered first -> cleaned up last in LIFO)
        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)
        self.temp_dir_path = temp_dir.name

        # 2. Redirect app.HISTORY_FILE to a temporary path
        temp_history = os.path.join(self.temp_dir_path, "test_history.json")
        history_patcher = mock.patch.object(app, "HISTORY_FILE", temp_history)
        history_patcher.start()
        self.addCleanup(history_patcher.stop)
        self.temp_history_file = temp_history

        # 3. Redirect app.UPLOAD_FOLDER to a temporary folder
        temp_uploads = os.path.join(self.temp_dir_path, "uploads")
        os.makedirs(temp_uploads, exist_ok=True)
        upload_patcher = mock.patch.object(app, "UPLOAD_FOLDER", temp_uploads)
        upload_patcher.start()
        self.addCleanup(upload_patcher.stop)
        self.temp_upload_dir = temp_uploads

        # 4. Low-level socket firewall (Zero-Packet Guarantee)
        def _firewall_block(*args, **kwargs):
            raise RuntimeError("Outbound socket connection blocked by test firewall!")

        sock_conn_patcher = mock.patch("socket.socket.connect", side_effect=_firewall_block)
        sock_conn_patcher.start()
        self.addCleanup(sock_conn_patcher.stop)

        sock_conn_ex_patcher = mock.patch("socket.socket.connect_ex", side_effect=_firewall_block)
        sock_conn_ex_patcher.start()
        self.addCleanup(sock_conn_ex_patcher.stop)

        sock_sendto_patcher = mock.patch("socket.socket.sendto", side_effect=_firewall_block)
        sock_sendto_patcher.start()
        self.addCleanup(sock_sendto_patcher.stop)

        # 5. Sanitize runtime environment variables (os.getenv calls)
        env_patcher = mock.patch.dict(os.environ, {
            "URLHAUS_AUTH_KEY": "",
            "GOOGLE_SAFE_BROWSING_API_KEY": "",
            "GEMINI_API_KEY": ""
        })
        env_patcher.start()
        self.addCleanup(env_patcher.stop)

        # 6. Intercept DNS resolution in analyzer
        dns_patcher = mock.patch.object(analyzer.socket, "getaddrinfo")
        self.mock_dns = dns_patcher.start()
        self.mock_dns.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))
        ]
        self.addCleanup(dns_patcher.stop)

        # 7. Intercept TLS socket creation in analyzer
        tls_conn_patcher = mock.patch.object(analyzer.socket, "create_connection")
        self.mock_tls_conn = tls_conn_patcher.start()
        self.mock_tls_conn.return_value = mock.MagicMock()
        self.addCleanup(tls_conn_patcher.stop)

        # 8. Intercept HTTP opener in analyzer
        opener_patcher = mock.patch.object(analyzer.urllib.request, "build_opener")
        self.mock_opener = opener_patcher.start()
        self.mock_director = mock.MagicMock()
        self.mock_opener.return_value = self.mock_director
        self.addCleanup(opener_patcher.stop)

        # 9. Intercept urllib.request.urlopen in analyzer (URLhaus, GSB)
        urlopen_patcher = mock.patch.object(analyzer.urllib.request, "urlopen")
        self.mock_urlopen = urlopen_patcher.start()
        self.mock_urlopen.return_value = mock.MagicMock()
        self.addCleanup(urlopen_patcher.stop)

        # 10. Intercept Gemini Client in analyzer
        genai_patcher = mock.patch.object(analyzer.genai, "Client")
        self.mock_genai_client = genai_patcher.start()
        self.mock_genai_instance = mock.MagicMock()
        self.mock_genai_client.return_value = self.mock_genai_instance
        self.addCleanup(genai_patcher.stop)
