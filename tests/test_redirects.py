from tests.test_base import IsolatedTestCase
from unittest import mock
import analyzer


class RedirectsTestCase(IsolatedTestCase):
    """
    Tier 1 unit tests for redirect following, loop detection, and risk scoring.
    """

    def test_validate_redirect_target(self):
        """Validate destination URL format."""
        self.assertFalse(analyzer.validate_redirect_target("")["valid"])
        self.assertFalse(analyzer.validate_redirect_target("ftp://example.com")["valid"])
        self.assertTrue(analyzer.validate_redirect_target("http://example.com")["valid"])
        self.assertTrue(analyzer.validate_redirect_target("https://example.com")["valid"])

    def test_analyze_redirect_chain_safe_single(self):
        """Single redirect upgrading to HTTPS within same domain."""
        chain_data = {
            "hops": [
                {"url": "http://example.com", "status_code": 301, "location": "https://example.com", "is_redirect": True},
                {"url": "https://example.com", "status_code": 200, "location": None, "is_redirect": False}
            ],
            "final_url": "https://example.com",
            "redirect_count": 1,
            "completed": True,
            "loop_detected": False,
            "max_redirects_reached": False,
            "error": None
        }
        res = analyzer.analyze_redirect_chain(chain_data)
        self.assertEqual(res["redirect_count"], 1)
        self.assertFalse(res["cross_domain_redirect"])
        self.assertFalse(res["https_downgrade"])

        classification = analyzer.classify_redirect_chain(res)
        self.assertEqual(classification, "SINGLE_REDIRECT")

        risk = analyzer.evaluate_redirect_risk(res)
        self.assertEqual(risk["score"], 0)
        self.assertEqual(risk["findings"], [])

    def test_analyze_redirect_chain_cross_domain(self):
        """Cross-domain redirect increases risk score."""
        chain_data = {
            "hops": [
                {"url": "http://short.example/abc", "status_code": 302, "location": "http://target.example/def", "is_redirect": True},
                {"url": "http://target.example/def", "status_code": 200, "location": None, "is_redirect": False}
            ],
            "final_url": "http://target.example/def",
            "redirect_count": 1,
            "completed": True,
            "loop_detected": False,
            "max_redirects_reached": False,
            "error": None
        }
        res = analyzer.analyze_redirect_chain(chain_data)
        self.assertTrue(res["cross_domain_redirect"])
        self.assertFalse(res["https_downgrade"])

        classification = analyzer.classify_redirect_chain(res)
        self.assertEqual(classification, "CROSS_DOMAIN")

        risk = analyzer.evaluate_redirect_risk(res)
        self.assertEqual(risk["score"], 10)
        self.assertEqual(risk["findings"], ["Redirect chain crosses between different domains"])

    def test_analyze_redirect_chain_https_downgrade(self):
        """HTTPS downgrade redirect triggers high severity finding."""
        chain_data = {
            "hops": [
                {"url": "https://secure.example/auth", "status_code": 302, "location": "http://insecure.example/auth", "is_redirect": True},
                {"url": "http://insecure.example/auth", "status_code": 200, "location": None, "is_redirect": False}
            ],
            "final_url": "http://insecure.example/auth",
            "redirect_count": 1,
            "completed": True,
            "loop_detected": False,
            "max_redirects_reached": False,
            "error": None
        }
        res = analyzer.analyze_redirect_chain(chain_data)
        self.assertTrue(res["https_downgrade"])

        classification = analyzer.classify_redirect_chain(res)
        self.assertEqual(classification, "HTTPS_DOWNGRADE")

        risk = analyzer.evaluate_redirect_risk(res)
        self.assertEqual(risk["score"], 30)  # 20 (downgrade) + 10 (cross-domain)
        self.assertIn("Redirect chain downgrades from HTTPS to HTTP", risk["findings"])
        self.assertIn("Redirect chain crosses between different domains", risk["findings"])

    def test_follow_redirect_chain_loop_detection(self):
        """Looping redirects are terminated and loop_detected flag is set."""
        def _mock_make_http_request(url, timeout=5):
            if url == "http://loop.example/1":
                return {"success": True, "url": url, "status_code": 302, "location": "http://loop.example/2", "headers": {}, "error": None}
            if url == "http://loop.example/2":
                return {"success": True, "url": url, "status_code": 302, "location": "http://loop.example/1", "headers": {}, "error": None}
            return {"success": False, "url": url, "status_code": None, "location": None, "headers": {}, "error": "Not found"}

        with mock.patch.object(analyzer, "make_http_request", side_effect=_mock_make_http_request):
            result = analyzer.follow_redirect_chain("http://loop.example/1", max_redirects=5)
            self.assertTrue(result["loop_detected"])
            self.assertFalse(result["completed"])
            self.assertEqual(result["redirect_count"], 2)

    def test_follow_redirect_chain_max_redirects_cutoff(self):
        """Chains exceeding max_redirects are terminated at the limit."""
        def _mock_make_http_request(url, timeout=5):
            hop_num = int(url.split("/")[-1])
            return {
                "success": True,
                "url": url,
                "status_code": 302,
                "location": f"http://long.example/{hop_num + 1}",
                "headers": {},
                "error": None
            }

        with mock.patch.object(analyzer, "make_http_request", side_effect=_mock_make_http_request):
            result = analyzer.follow_redirect_chain("http://long.example/0", max_redirects=5)
            self.assertTrue(result["max_redirects_reached"])
            self.assertFalse(result["completed"])
            self.assertEqual(result["redirect_count"], 6)
