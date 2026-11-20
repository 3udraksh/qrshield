"""
QRShield Tier 2 Feature & Security Tests for v2 Enhancements:
- Privacy redaction (Wi-Fi passwords, URL auth tokens)
- ML model metadata, tree-vote calibration disclaimers, and uncertainty flag
- Security report v2 schema, scan ID, limitations, and redaction
- History search, filtering, clear history route, and sample vs. live data tagging
"""

import json
import os
import re
from unittest import mock
from tests.test_base import IsolatedTestCase
import app
import analyzer
from qrshield.privacy import (
    redact_wifi_payload,
    redact_url_sensitive_params,
    redact_sensitive_payload
)
from qrshield.ml import analyze_ml_prediction
from qrshield.explainability import build_security_report, export_security_report
from qrshield.services import HistoryService


class Tier2V2FeaturesTestCase(IsolatedTestCase):
    """
    Tier 2 test suite for QRShield v2 product enhancements.
    """

    def setUp(self):
        super().setUp()
        self.client = app.app.test_client()

        # Mock heavy external components
        self.mock_tls = mock.patch.object(
            analyzer,
            "get_tls_certificate",
            return_value={"retrieved": False, "certificate": None, "error": "Mocked"}
        )
        self.mock_tls.start()
        self.addCleanup(self.mock_tls.stop)

        self.mock_redir = mock.patch.object(
            analyzer,
            "follow_redirect_chain",
            side_effect=lambda url, **kwargs: {
                "chain": [], "final_url": url, "completed": True,
                "redirect_count": 0, "loop_detected": False, "max_redirects_reached": False, "error": None
            }
        )
        self.mock_redir.start()
        self.addCleanup(self.mock_redir.stop)

        self.mock_ai = mock.patch.object(
            analyzer,
            "generate_ai_explanation",
            return_value={"status": "AVAILABLE", "explanation": "Mock AI explanation"}
        )
        self.mock_ai.start()
        self.addCleanup(self.mock_ai.stop)

    # -------------------------------------------------------------------------
    # 1. Privacy & Sensitive Credential Redaction
    # -------------------------------------------------------------------------

    def test_wifi_password_redaction(self):
        """Wi-Fi payloads have their password field replaced with [REDACTED]."""
        payload = "WIFI:S:SecureNet;T:WPA;P:SuperSecretPass123;;"
        redacted = redact_wifi_payload(payload)
        self.assertNotIn("SuperSecretPass123", redacted)
        self.assertIn("P:[REDACTED]", redacted)
        self.assertIn("S:SecureNet", redacted)
        self.assertIn("T:WPA", redacted)

    def test_url_sensitive_parameter_redaction(self):
        """Sensitive URL query parameters (token, password, key) are masked."""
        url = "https://example.com/login?token=abc123xyz&user=alice&password=secretPassword&redirect=/home"
        redacted = redact_url_sensitive_params(url)
        self.assertNotIn("abc123xyz", redacted)
        self.assertNotIn("secretPassword", redacted)
        self.assertIn("token=%5BREDACTED%5D", redacted)  # urlencoded [REDACTED]
        self.assertIn("user=alice", redacted)
        self.assertIn("redirect=%2Fhome", redacted)

    def test_analyzer_redacts_wifi_in_safe_content(self):
        """analyze_url maintains raw URL for golden master contract while providing safe_content."""
        wifi_raw = "WIFI:S:Guest;T:WPA;P:myVerySecretPass;;"
        res = analyzer.analyze_url(wifi_raw)
        self.assertEqual(res["url"], wifi_raw)
        self.assertIn("safe_content", res)
        self.assertNotIn("myVerySecretPass", res["safe_content"])
        self.assertIn("[REDACTED]", res["safe_content"])

    # -------------------------------------------------------------------------
    # 2. Machine Learning Metadata & Calibration Disclaimers
    # -------------------------------------------------------------------------

    def test_ml_metadata_and_calibration_disclaimer(self):
        """ML inference exposes model architecture, synthetic version, and calibration disclaimer."""
        safe_data = {
            "features": [
                {"name": "URL Length", "value": 19},
                {"name": "Hostname Length", "value": 11},
                {"name": "Subdomain Count", "value": 0},
                {"name": "Path Depth", "value": 0},
                {"name": "Query Parameters", "value": 0},
                {"name": "Percent Encoded Characters", "value": 0},
                {"name": "Hostname Hyphens", "value": 0},
                {"name": "Hostname Digits", "value": 0},
                {"name": "Hostname Entropy", "value": 3.1}
            ]
        }
        res = analyze_ml_prediction(safe_data)
        self.assertEqual(res["status"], "AVAILABLE")
        self.assertEqual(res["model_name"], "RandomForestClassifier")
        self.assertEqual(res["model_version"], "1.0.0-synthetic")
        self.assertFalse(res["is_calibrated"])
        self.assertIn("Tree-vote confidence", res["calibration_disclaimer"])
        self.assertIn("raw_probabilities", res)
        self.assertIsInstance(res["uncertain"], bool)

    def test_ml_uncertainty_flag_on_borderline_confidence(self):
        """When confidence falls in the 40-60% range, the uncertain flag is set to True."""
        mock_model = mock.MagicMock()
        mock_model.predict.return_value = [0]
        # 52% class 0, 48% class 1 -> borderline voting
        mock_model.predict_proba.return_value = [[0.52, 0.48]]

        with mock.patch.object(analyzer, "load_ml_model", return_value=mock_model):
            res = analyze_ml_prediction({"features": []})
            self.assertEqual(res["status"], "AVAILABLE")
            self.assertTrue(res["uncertain"])

    # -------------------------------------------------------------------------
    # 3. Security Report v2 Schema & Privacy Isolation
    # -------------------------------------------------------------------------

    def test_build_security_report_v2_schema_and_redaction(self):
        """Security report includes scan ID, timestamp, limitations, and redacts sensitive Wi-Fi payloads."""
        wifi_result = {
            "url": "WIFI:S:OfficeWifi;T:WPA;P:SuperSecretPasswd123;;",
            "content_type": "WIFI",
            "score": 0,
            "risk": "LOW RISK",
            "risk_analysis": {
                "score": 0,
                "risk": "LOW RISK",
                "risk_basis": "Non-URL QR content",
                "confidence": "LOW",
                "evidence": {"high": 0, "medium": 0, "low": 0},
                "correlation": {"level": "NONE", "count": 0, "signals": []}
            },
            "findings": [],
            "explanations": [],
            "overall_explanation": "Wi-Fi payload detected.",
            "risk_evidence_explanation": "No URL security indicators.",
            "features": {}
        }

        report = build_security_report(wifi_result)
        self.assertEqual(report["report_type"], "QRShield Security Report")
        self.assertEqual(report["version"], "2.0.0")
        self.assertTrue(bool(report.get("scan_id")))
        self.assertIn("limitations", report)
        self.assertIn("privacy_notice", report)

        # Wi-Fi password MUST be redacted in the report
        self.assertNotIn("SuperSecretPasswd123", json.dumps(report))
        self.assertTrue(report["content"]["is_redacted"])
        self.assertIn("[REDACTED]", report["content"]["decoded_content"])

    # -------------------------------------------------------------------------
    # 4. History Service: Filter, Clear, and Sample vs. Live Tagging
    # -------------------------------------------------------------------------

    def test_history_sample_vs_live_tagging(self):
        """Pre-existing seed records (from 2026-09) are flagged as samples; new scans are marked live."""
        # Create temp history with a 2026-09 legacy record
        seed_record = [
            {"timestamp": "2026-09-27 10:00:00", "content": "https://seed.example", "content_type": "URL", "risk": "LOW RISK", "score": 0}
        ]
        with open(self.temp_history_file, "w", encoding="utf-8") as f:
            json.dump(seed_record, f)

        # Load history and verify sample tagging
        loaded = HistoryService.load_history(self.temp_history_file)
        self.assertEqual(len(loaded), 1)
        self.assertTrue(loaded[0]["is_sample"])

        # Save a new scan and verify it is NOT marked as a sample
        new_scan = {"url": "https://new-live-scan.org", "content_type": "URL", "risk": "LOW RISK", "score": 5}
        HistoryService.save_scan(new_scan, self.temp_history_file)

        reloaded = HistoryService.load_history(self.temp_history_file)
        self.assertEqual(len(reloaded), 2)
        # Most recent at index 0
        self.assertFalse(reloaded[0]["is_sample"])
        self.assertTrue(reloaded[1]["is_sample"])

    def test_history_filtering(self):
        """HistoryService.filter_history correctly filters by query, risk level, and content type."""
        history = [
            {"timestamp": "2026-11-20 10:00:00", "content": "https://github.com", "content_type": "URL", "risk": "LOW RISK", "score": 0},
            {"timestamp": "2026-11-20 10:01:00", "content": "http://phish-login.xyz", "content_type": "URL", "risk": "HIGH RISK", "score": 85},
            {"timestamp": "2026-11-20 10:02:00", "content": "WIFI:S:Guest;T:WPA;P:[REDACTED];;", "content_type": "WIFI", "risk": "LOW RISK", "score": 0},
        ]

        # Query filter
        q_res = HistoryService.filter_history(history, query="phish")
        self.assertEqual(len(q_res), 1)
        self.assertEqual(q_res[0]["content"], "http://phish-login.xyz")

        # Risk filter
        risk_res = HistoryService.filter_history(history, risk_filter="HIGH RISK")
        self.assertEqual(len(risk_res), 1)
        self.assertEqual(risk_res[0]["risk"], "HIGH RISK")

        # Type filter
        type_res = HistoryService.filter_history(history, type_filter="WIFI")
        self.assertEqual(len(type_res), 1)
        self.assertEqual(type_res[0]["content_type"], "WIFI")

    def test_clear_history_route(self):
        """POST /clear-history resets history file to an empty list and redirects to /dashboard."""
        seed_record = [{"timestamp": "2026-11-20 10:00:00", "content": "https://example.com", "content_type": "URL", "risk": "LOW RISK", "score": 0}]
        with open(self.temp_history_file, "w", encoding="utf-8") as f:
            json.dump(seed_record, f)

        res = self.client.post("/clear-history")
        self.assertEqual(res.status_code, 302)
        self.assertIn("/dashboard", res.headers.get("Location", ""))

        with open(self.temp_history_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(data, [])

    def test_api_scan_detail_route(self):
        """GET /api/scan/<index> returns JSON scan details or 404 if out of range."""
        seed_record = [{"timestamp": "2026-11-20 10:00:00", "content": "https://api-test.com", "content_type": "URL", "risk": "LOW RISK", "score": 0}]
        with open(self.temp_history_file, "w", encoding="utf-8") as f:
            json.dump(seed_record, f)

        res_ok = self.client.get("/api/scan/0")
        self.assertEqual(res_ok.status_code, 200)
        json_ok = json.loads(res_ok.data.decode("utf-8"))
        self.assertEqual(json_ok["status"], "SUCCESS")
        self.assertEqual(json_ok["scan"]["content"], "https://api-test.com")

        res_404 = self.client.get("/api/scan/999")
        self.assertEqual(res_404.status_code, 404)
