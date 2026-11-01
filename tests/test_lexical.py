from tests.test_base import IsolatedTestCase
from urllib.parse import urlparse
import analyzer


class LexicalAnalysisTestCase(IsolatedTestCase):
    """
    Tier 1 unit tests for URL lexical, entropy, and obfuscation heuristics.
    """

    def test_calculate_entropy(self):
        """Verify Shannon entropy calculation."""
        self.assertEqual(analyzer.calculate_entropy(""), 0.0)
        self.assertEqual(analyzer.calculate_entropy("aaaaaa"), 0.0)

        # Uniform 2-character string -> entropy 1.0 bit
        self.assertAlmostEqual(analyzer.calculate_entropy("abababab"), 1.0, places=4)

        # Diverse strings produce higher entropy
        ent_low = analyzer.calculate_entropy("google.com")
        ent_high = analyzer.calculate_entropy("x7k9-p2q8z1v4.xyz")
        self.assertGreater(ent_high, ent_low)

    def test_decode_url_layers(self):
        """Verify iterative multi-layer percent decoding."""
        url_plain = "https://example.com/test"
        self.assertEqual(analyzer.decode_url_layers(url_plain), [url_plain])

        url_single = "https://example.com/%61%63%63%6f%75%6e%74"
        layers_single = analyzer.decode_url_layers(url_single)
        self.assertEqual(len(layers_single), 2)
        self.assertEqual(layers_single[-1], "https://example.com/account")

        url_double = "https://example.com/%2561"
        layers_double = analyzer.decode_url_layers(url_double)
        self.assertEqual(len(layers_double), 3)
        self.assertEqual(layers_double[1], "https://example.com/%61")
        self.assertEqual(layers_double[2], "https://example.com/a")

    def test_is_ip_address(self):
        """Verify IPv4 and IPv6 detection."""
        self.assertFalse(analyzer.is_ip_address(""))
        self.assertFalse(analyzer.is_ip_address("example.com"))
        self.assertTrue(analyzer.is_ip_address("127.0.0.1"))
        self.assertTrue(analyzer.is_ip_address("192.168.1.1"))
        self.assertTrue(analyzer.is_ip_address("::1"))
        self.assertTrue(analyzer.is_ip_address("2606:2800:220:1:248:1893:25c8:1946"))

    def test_analyze_hostname_structure(self):
        """Verify hostname label analysis and suspicious subdomain keyword stuffing."""
        res_empty = analyzer.analyze_hostname_structure("")
        self.assertEqual(res_empty["subdomain_count"], 0)

        res_clean = analyzer.analyze_hostname_structure("example.com")
        self.assertEqual(res_clean["subdomain_count"], 0)
        self.assertFalse(res_clean["suspicious_subdomain"])

        res_phish = analyzer.analyze_hostname_structure("secure-login.verify.account.example.com")
        self.assertGreaterEqual(res_phish["subdomain_count"], 3)
        self.assertTrue(res_phish["suspicious_subdomain"])

    def test_analyze_punycode(self):
        """Verify Punycode / IDN detection."""
        res_plain = analyzer.analyze_punycode("example.com")
        self.assertFalse(res_plain["detected"])
        self.assertEqual(res_plain["punycode_labels"], [])

        res_puny = analyzer.analyze_punycode("xn--pple-43d.example")
        self.assertTrue(res_puny["detected"])
        self.assertIn("xn--pple-43d", res_puny["punycode_labels"])

    def test_analyze_port(self):
        """Verify port analysis for explicit, default, and invalid ports."""
        parsed_default = urlparse("https://example.com")
        res_default = analyzer.analyze_port(parsed_default)
        self.assertTrue(res_default["valid"])
        self.assertFalse(res_default["explicit"])
        self.assertIsNone(res_default["port"])
        self.assertEqual(res_default["reason"], "No explicit port")

        parsed_explicit = urlparse("https://example.com:8443")
        res_explicit = analyzer.analyze_port(parsed_explicit)
        self.assertTrue(res_explicit["valid"])
        self.assertTrue(res_explicit["explicit"])
        self.assertFalse(res_explicit["default"])
        self.assertEqual(res_explicit["port"], 8443)

        parsed_explicit_default = urlparse("https://example.com:443")
        res_exp_default = analyzer.analyze_port(parsed_explicit_default)
        self.assertTrue(res_exp_default["valid"])
        self.assertTrue(res_exp_default["explicit"])
        self.assertTrue(res_exp_default["default"])
        self.assertEqual(res_exp_default["port"], 443)

        parsed_invalid = urlparse("http://example.com:invalid_port")
        res_invalid = analyzer.analyze_port(parsed_invalid)
        self.assertFalse(res_invalid["valid"])

    def test_analyze_path_query_deception(self):
        """Verify path keywords and redirect parameter detection."""
        parsed = urlparse("https://example.com/verify/password?next=https://evil.example")
        res = analyzer.analyze_path_query_deception(parsed)
        self.assertIn("verify", res["suspicious_path_keywords"])
        self.assertIn("password", res["suspicious_path_keywords"])
        self.assertIn("next", res["redirect_parameters"])

    def test_analyze_obfuscation_combination(self):
        """Verify obfuscation combination counts and levels."""
        res_none = analyzer.analyze_obfuscation_combination(
            decoding_count=0,
            userinfo_detected=False,
            suspicious_subdomain=False,
            punycode_detected=False,
            non_default_port=False,
            suspicious_path=False,
            redirect_parameters=False
        )
        self.assertEqual(res_none["count"], 0)
        self.assertEqual(res_none["level"], "low")

        res_multi = analyzer.analyze_obfuscation_combination(
            decoding_count=2,
            userinfo_detected=True,
            suspicious_subdomain=True,
            punycode_detected=False,
            non_default_port=True,
            suspicious_path=True,
            redirect_parameters=True
        )
        self.assertGreaterEqual(res_multi["count"], 4)
        self.assertEqual(res_multi["level"], "high")
