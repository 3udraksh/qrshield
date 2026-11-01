from tests.test_base import IsolatedTestCase
from unittest import mock
import analyzer


class GoldenMasterTestCase(IsolatedTestCase):
    """
    Tier 1 Golden Master baseline snapshot tests.
    Verifies 12 deterministic cases against analyze_url().
    """

    def setUp(self):
        super().setUp()

        # Mock TLS certificate inspection components to simulate a clean TLS certificate
        self.mock_tls_cert_patcher = mock.patch.object(analyzer, "get_tls_certificate")
        self.mock_get_tls_cert = self.mock_tls_cert_patcher.start()
        self.mock_get_tls_cert.return_value = {
            "retrieved": True,
            "hostname": "example.com",
            "port": 443,
            "certificate": b"mock_der_bytes",
            "error": None
        }
        self.addCleanup(self.mock_tls_cert_patcher.stop)

        self.mock_cert_meta_patcher = mock.patch.object(analyzer, "extract_certificate_metadata")
        self.mock_extract_meta = self.mock_cert_meta_patcher.start()
        self.mock_extract_meta.return_value = {
            "common_name": "example.com",
            "issuer": "DigiCert",
            "version": 3,
            "serial_number": "12345",
            "valid_from": "2026-01-01 00:00:00",
            "valid_until": "2027-01-01 00:00:00",
            "san": ["example.com"],
            "dns_name_count": 1,
            "ip_address_count": 0,
            "signature_algorithm": "sha256WithRSAEncryption",
            "error": None
        }
        self.addCleanup(self.mock_cert_meta_patcher.stop)

        self.mock_cert_validity_patcher = mock.patch.object(analyzer, "analyze_certificate_validity")
        self.mock_validity = self.mock_cert_validity_patcher.start()
        self.mock_validity.return_value = {
            "valid": True,
            "status": "VALID",
            "days_remaining": 60,
            "error": None
        }
        self.addCleanup(self.mock_cert_validity_patcher.stop)

        self.mock_cert_id_patcher = mock.patch.object(analyzer, "analyze_certificate_identity")
        self.mock_cert_id = self.mock_cert_id_patcher.start()
        self.mock_cert_id.return_value = {
            "matches": True,
            "match_type": "EXACT",
            "matched_name": "example.com",
            "error": None
        }
        self.addCleanup(self.mock_cert_id_patcher.stop)

        # Mock redirect chain follower to simulate clean non-redirecting requests
        self.mock_redirect_patcher = mock.patch.object(analyzer, "follow_redirect_chain")
        self.mock_redirect = self.mock_redirect_patcher.start()
        self.mock_redirect.side_effect = lambda url, max_redirects=5, timeout=5: {
            "chain": [],
            "hops": [],
            "final_url": url,
            "completed": True,
            "redirect_count": 0,
            "loop_detected": False,
            "max_redirects_reached": False,
            "error": None
        }
        self.addCleanup(self.mock_redirect_patcher.stop)

        # Mock AI explanation generator to ensure deterministic explanation text
        self.mock_ai_patcher = mock.patch.object(analyzer, "generate_ai_explanation")
        self.mock_ai = self.mock_ai_patcher.start()
        self.mock_ai.return_value = {
            "status": "AVAILABLE",
            "explanation": "Deterministic mock AI security explanation."
        }
        self.addCleanup(self.mock_ai_patcher.stop)

    def test_gm01_safe_public_https(self):
        """GM-01: Standard legitimate HTTPS URL."""
        result = analyzer.analyze_url("https://example.com")
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["risk"], "LOW RISK")
        self.assertEqual(result["content_type"], "URL")
        self.assertEqual(len(result["findings"]), 1)
        self.assertEqual(result["findings"][0]["severity"], "info")
        self.assertEqual(result["findings"][0]["indicator"], "No obvious indicators detected")
        self.assertEqual(result["ml_analysis"]["status"], "AVAILABLE")
        self.assertEqual(result["ml_analysis"]["prediction"], 0)
        self.assertEqual(result["ml_consensus"]["agreement"], "AGREE_SAFE")

        validation = analyzer.validate_explainability(result)
        self.assertTrue(validation["valid"], f"Validation failed: {validation.get('missing')}")

    def test_gm02_campus_phishing_url(self):
        """GM-02: Phishing heuristic pattern with suspicious TLD and keywords."""
        result = analyzer.analyze_url("http://university-login-verify.xyz/urgent/account/password")
        self.assertEqual(result["score"], 50)
        self.assertEqual(result["risk"], "CAUTION")
        self.assertEqual(result["content_type"], "URL")
        self.assertIsInstance(result["findings"], list)
        self.assertGreaterEqual(len(result["findings"]), 2)

        indicators = [f.get("indicator") for f in result["findings"] if isinstance(f, dict)]
        self.assertIn("Suspicious-looking TLD", indicators)
        self.assertIn("Security-sensitive keywords", indicators)

        validation = analyzer.validate_explainability(result)
        self.assertTrue(validation["valid"], f"Validation failed: {validation.get('missing')}")

    def test_gm03_explicit_port_https(self):
        """GM-03: HTTPS with explicit non-default port."""
        result = analyzer.analyze_url("https://example.com:8443/login")
        self.assertEqual(result["score"], 15)
        self.assertEqual(result["risk"], "LOW RISK")
        self.assertEqual(result["content_type"], "URL")

        explicit_port_features = [f for f in result.get("features", []) if f.get("name") == "Explicit Port"]
        self.assertEqual(len(explicit_port_features), 1)
        self.assertEqual(explicit_port_features[0].get("value"), 8443)

        validation = analyzer.validate_explainability(result)
        self.assertTrue(validation["valid"], f"Validation failed: {validation.get('missing')}")

    def test_gm04_routable_public_ip_literal(self):
        """GM-04: Routable public IPv4 address destination."""
        result = analyzer.analyze_url("http://93.184.216.34/login")
        self.assertEqual(result["score"], 45)
        self.assertEqual(result["risk"], "CAUTION")

        indicators = [f.get("indicator") for f in result["findings"] if isinstance(f, dict)]
        self.assertIn("IP address used as destination", indicators)

        validation = analyzer.validate_explainability(result)
        self.assertTrue(validation["valid"], f"Validation failed: {validation.get('missing')}")

    def test_gm05_userinfo_at_symbol_deception(self):
        """GM-05: Userinfo @ deception pattern."""
        result = analyzer.analyze_url("http://admin@legit.example:fake@phish.example/login")
        self.assertEqual(result["score"], 45)
        self.assertEqual(result["risk"], "CAUTION")

        messages = [f.get("message") for f in result["findings"] if isinstance(f, dict)]
        self.assertTrue(any("userinfo before @" in m for m in messages if m))

        validation = analyzer.validate_explainability(result)
        self.assertTrue(validation["valid"], f"Validation failed: {validation.get('missing')}")

    def test_gm06_multi_layer_percent_encoding(self):
        """GM-06: Multi-layer percent-encoded URL."""
        result = analyzer.analyze_url("http://example.com/%2561%2563%2563%256f%2575%256e%2574")
        self.assertEqual(result["score"], 45)
        self.assertEqual(result["risk"], "CAUTION")

        indicators = [f.get("indicator") for f in result["findings"] if isinstance(f, dict)]
        self.assertIn("Multiple URL-decoding layers detected", indicators)

        validation = analyzer.validate_explainability(result)
        self.assertTrue(validation["valid"], f"Validation failed: {validation.get('missing')}")

    def test_gm07_punycode_idn(self):
        """GM-07: Internationalized domain name (Punycode)."""
        result = analyzer.analyze_url("http://xn--pple-43d.example/login")
        self.assertEqual(result["score"], 45)
        self.assertEqual(result["risk"], "CAUTION")

        messages = [f.get("message") for f in result["findings"] if isinstance(f, dict)]
        self.assertTrue(any("Punycode" in m for m in messages if m))

        validation = analyzer.validate_explainability(result)
        self.assertTrue(validation["valid"], f"Validation failed: {validation.get('missing')}")

    def test_gm08_wifi_qr_payload(self):
        """GM-08: Wi-Fi network QR payload."""
        result = analyzer.analyze_url("WIFI:S:Campus_Guest;T:WPA;P:secret123;;")
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["risk"], "LOW RISK")
        self.assertEqual(result["content_type"], "WIFI")
        self.assertIsNotNone(result["wifi_analysis"])
        self.assertEqual(result["wifi_analysis"]["ssid"], "Campus_Guest")
        self.assertEqual(result["wifi_analysis"]["authentication"], "WPA")

        validation = analyzer.validate_explainability(result)
        self.assertTrue(validation["valid"], f"Validation failed: {validation.get('missing')}")

    def test_gm09_vcard_qr_payload(self):
        """GM-09: vCard contact payload with embedded URL."""
        payload = "BEGIN:VCARD\nVERSION:3.0\nFN:Staff\nURL:https://example.com\nEND:VCARD"
        result = analyzer.analyze_url(payload)
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["risk"], "LOW RISK")
        self.assertEqual(result["content_type"], "VCARD")
        self.assertIsNotNone(result["vcard_analysis"])
        self.assertEqual(result["vcard_analysis"]["name"], "Staff")
        self.assertIn("https://example.com", result["embedded_urls"])

        validation = analyzer.validate_explainability(result)
        self.assertTrue(validation["valid"], f"Validation failed: {validation.get('missing')}")

    def test_gm10_sms_qr_payload(self):
        """GM-10: SMS message payload with embedded link."""
        payload = "sms:+1234567890?body=Verify: https://verify.example"
        result = analyzer.analyze_url(payload)
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["risk"], "LOW RISK")
        self.assertEqual(result["content_type"], "SMS")
        self.assertIsNotNone(result["message_analysis"])
        self.assertEqual(result["message_analysis"]["recipient"], "+1234567890")
        self.assertIn("https://verify.example", result["embedded_urls"])

        validation = analyzer.validate_explainability(result)
        self.assertTrue(validation["valid"], f"Validation failed: {validation.get('missing')}")

    def test_gm11_empty_url(self):
        """GM-11: Empty string URL input."""
        result = analyzer.analyze_url("")
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["risk"], "LOW RISK")
        self.assertEqual(result["content_type"], "EMPTY")
        self.assertEqual(result["findings"], [])

    def test_gm12_missing_hostname(self):
        """GM-12: Unparseable URL missing hostname."""
        result = analyzer.analyze_url("http://")
        self.assertEqual(result["score"], 100)
        self.assertEqual(result["risk"], "INVALID")
        self.assertEqual(result["findings"], ["The URL could not be parsed correctly."])
        self.assertIsInstance(result["findings"], list)
        self.assertIsInstance(result["findings"][0], str)
