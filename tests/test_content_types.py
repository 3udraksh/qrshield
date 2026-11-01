from tests.test_base import IsolatedTestCase
import analyzer


class ContentTypesTestCase(IsolatedTestCase):
    """
    Tier 1 unit tests for QR content type detection and non-URL payload parsers.
    """

    def test_detect_qr_content_type(self):
        """Verify content type detection across supported schemes."""
        self.assertEqual(analyzer.detect_qr_content_type(""), "EMPTY")
        self.assertEqual(analyzer.detect_qr_content_type("https://example.com"), "URL")
        self.assertEqual(analyzer.detect_qr_content_type("http://example.com"), "URL")
        self.assertEqual(analyzer.detect_qr_content_type("WIFI:S:MySSID;T:WPA;P:pass;;"), "WIFI")
        self.assertEqual(analyzer.detect_qr_content_type("BEGIN:VCARD\nVERSION:3.0\nFN:John\nEND:VCARD"), "VCARD")
        self.assertEqual(analyzer.detect_qr_content_type("mailto:security@example.com"), "EMAIL")
        self.assertEqual(analyzer.detect_qr_content_type("sms:+123456789"), "SMS")
        self.assertEqual(analyzer.detect_qr_content_type("tel:+123456789"), "PHONE")
        self.assertEqual(analyzer.detect_qr_content_type("geo:37.7749,-122.4194"), "GEOLOCATION")
        self.assertEqual(analyzer.detect_qr_content_type("Plain text memo"), "TEXT")

    def test_analyze_wifi_qr(self):
        """Verify Wi-Fi QR parsing and open network detection."""
        res_invalid = analyzer.analyze_wifi_qr("invalid_content")
        self.assertFalse(res_invalid["valid"])

        res_wpa = analyzer.analyze_wifi_qr("WIFI:S:Campus_Sec;T:WPA;P:secretPass;H:false;;")
        self.assertTrue(res_wpa["valid"])
        self.assertEqual(res_wpa["ssid"], "Campus_Sec")
        self.assertEqual(res_wpa["authentication"], "WPA")
        self.assertFalse(res_wpa["open_network"])
        self.assertIsNone(res_wpa["finding"])

        res_open = analyzer.analyze_wifi_qr("WIFI:S:Airport_Free;T:nopass;;")
        self.assertTrue(res_open["valid"])
        self.assertEqual(res_open["authentication"], "NOPASS")
        self.assertTrue(res_open["open_network"])
        self.assertIsNotNone(res_open["finding"])
        self.assertIn("open network", res_open["finding"])

    def test_analyze_vcard_qr(self):
        """Verify vCard QR parsing and embedded URL extraction."""
        res_invalid = analyzer.analyze_vcard_qr("invalid_content")
        self.assertFalse(res_invalid["valid"])

        vcard_text = (
            "BEGIN:VCARD\n"
            "VERSION:3.0\n"
            "FN:Alice Smith\n"
            "TEL:+1-555-0199\n"
            "EMAIL:alice@example.com\n"
            "URL:https://alice.example.com\n"
            "END:VCARD"
        )
        res_valid = analyzer.analyze_vcard_qr(vcard_text)
        self.assertTrue(res_valid["valid"])
        self.assertEqual(res_valid["name"], "Alice Smith")
        self.assertEqual(res_valid["phone"], "+1-555-0199")
        self.assertEqual(res_valid["email"], "alice@example.com")
        self.assertIn("https://alice.example.com", res_valid["urls"])
        self.assertIsNotNone(res_valid["finding"])

    def test_extract_embedded_urls(self):
        """Verify URL extraction from arbitrary text content."""
        self.assertEqual(analyzer.extract_embedded_urls(""), [])
        text = "Check http://example.com/login and https://secure.example.org/verify."
        urls = analyzer.extract_embedded_urls(text)
        self.assertEqual(len(urls), 2)
        self.assertIn("http://example.com/login", urls)
        self.assertIn("https://secure.example.org/verify", urls)

    def test_analyze_message_qr(self):
        """Verify EMAIL and SMS message payload parsing."""
        res_email = analyzer.analyze_message_qr("mailto:admin@example.com?body=Visit https://evil.example", "EMAIL")
        self.assertTrue(res_email["valid"])
        self.assertEqual(res_email["recipient"], "admin@example.com")
        self.assertEqual(res_email["message"], "Visit https://evil.example")
        self.assertIn("https://evil.example", res_email["urls"])

        res_sms = analyzer.analyze_message_qr("sms:+1987654321?body=Code https://code.example", "SMS")
        self.assertTrue(res_sms["valid"])
        self.assertEqual(res_sms["recipient"], "+1987654321")
        self.assertIn("https://code.example", res_sms["urls"])
