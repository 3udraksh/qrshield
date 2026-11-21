"""
QRShield Tier 2 Security & Behavioral Test Suite: Hybrid ML Engine
Tests the Milestone 2 Advanced Hybrid Machine Learning Engine:
- Model C (HybridEnsembleModel) loading and caching
- Feature extraction v2 (28 features) and edge cases
- Dual-model component prediction and calibration metadata
- Seamless integration with analyze_ml_prediction facade
- Graceful backward-compatible fallback to legacy baseline
- Interpretability signal extraction
- Robustness on previously unseen domain structures
"""

import unittest
from unittest import mock
import os
import pandas as pd
import numpy as np

import analyzer
from qrshield.ml import load_hybrid_model, load_ml_model, analyze_ml_prediction
from qrshield.constants import HYBRID_MODEL_PATH, ML_MODEL_PATH
from ml.features.extractor import extract_features_v2_dict, extract_features_v2_df, SCHEMA_V2_COLUMNS
from ml.models.hybrid_ensemble import HybridEnsembleModel


class Tier2HybridMLEngineTestCase(unittest.TestCase):
    """Rigorous verification of the Milestone 2 hybrid ML engine."""

    def test_production_hybrid_artifact_exists_and_loads(self):
        """Production hybrid joblib artifact exists and is loaded as a singleton."""
        self.assertTrue(os.path.exists(HYBRID_MODEL_PATH), f"Missing artifact at {HYBRID_MODEL_PATH}")
        self.assertTrue(os.path.exists(ML_MODEL_PATH), f"Historical baseline must exist at {ML_MODEL_PATH}")

        model_1 = load_hybrid_model()
        model_2 = load_hybrid_model()
        self.assertIsNotNone(model_1)
        self.assertIs(model_1, model_2, "load_hybrid_model must cache and return singleton instance")
        self.assertIsInstance(model_1, HybridEnsembleModel)
        self.assertEqual(model_1.MODEL_NAME, "HybridEnsemble")
        self.assertEqual(model_1.MODEL_VERSION, "2.0.0-hybrid")

    def test_feature_extractor_v2_schema_completeness(self):
        """Schema v2 extracts exactly 28 documented features with correct types."""
        url = "https://sub.secure-portal.bank.xyz:8443/auth/login.php?user=admin&token=xyz%2F123#frag"
        feat_dict = extract_features_v2_dict(url)

        self.assertEqual(len(feat_dict), 28)
        self.assertEqual(len(SCHEMA_V2_COLUMNS), 28)
        for name in SCHEMA_V2_COLUMNS:
            self.assertIn(name, feat_dict)
            self.assertIsInstance(feat_dict[name], (int, float))

        # Verify key indicator extractions
        self.assertEqual(feat_dict["is_https"], 1)
        self.assertEqual(feat_dict["non_default_port"], 1)
        self.assertEqual(feat_dict["suspicious_tld"], 1)
        self.assertGreaterEqual(feat_dict["suspicious_keyword_count"], 2)
        self.assertGreaterEqual(feat_dict["path_depth"], 2)
        self.assertGreaterEqual(feat_dict["percent_encoding_count"], 1)

    def test_feature_extractor_v2_edge_cases(self):
        """Extractor safely handles malformed, empty, and IPv6 URLs without crashing."""
        edge_cases = [
            "",
            "http://",
            "not-a-valid-url-at-all",
            "http://0000:0000:0000:0000:ffff:d93c:eda6:8080/path",  # Malformed unbracketed IPv6
            "https://user:pass@legit.org/test",
            "http://192.168.1.1/admin"
        ]
        df = extract_features_v2_df(edge_cases)
        self.assertIsInstance(df, pd.DataFrame)
        self.assertEqual(len(df), len(edge_cases))
        self.assertEqual(df.shape[1], 28)
        self.assertFalse(df.isnull().values.any(), "Features dataframe must contain zero NaN values")

    def test_hybrid_prediction_with_url_payload(self):
        """Passing URL payload triggers calibrated Hybrid Ensemble analysis."""
        payload = {
            "url": "https://secure-update-login-account.xyz/verify.php",
            "features": []
        }
        res = analyze_ml_prediction(payload)

        self.assertEqual(res["status"], "AVAILABLE")
        self.assertEqual(res["model_name"], "HybridEnsemble")
        self.assertEqual(res["model_version"], "2.0.0-hybrid")
        self.assertTrue(res["is_calibrated"])
        self.assertIn("Platt scaling", res["calibration_disclaimer"])
        self.assertIsInstance(res["calibrated_probability"], float)
        self.assertGreaterEqual(res["calibrated_probability"], 0.0)
        self.assertLessEqual(res["calibrated_probability"], 1.0)
        self.assertIn(res["label"], ["LIKELY_SAFE", "SUSPICIOUS"])

        # Check sub-model components
        components = res.get("components")
        self.assertIsNotNone(components)
        self.assertIn("character_model_prob", components)
        self.assertIn("structural_model_prob", components)
        self.assertIn("character_weight", components)
        self.assertIn("structural_weight", components)
        self.assertIn("submodels_agree", components)
        self.assertEqual(components["character_weight"], 0.4)
        self.assertEqual(components["structural_weight"], 0.6)

    def test_fallback_to_legacy_rf_when_url_omitted(self):
        """When input dictionary contains only features (no URL), falls back to legacy RF."""
        legacy_input = {
            "features": [
                {"name": "URL Length", "value": 25},
                {"name": "Hostname Length", "value": 15},
                {"name": "Subdomain Count", "value": 1},
                {"name": "Path Depth", "value": 1},
                {"name": "Query Parameters", "value": 0},
                {"name": "Percent Encoded Characters", "value": 0},
                {"name": "Hostname Hyphens", "value": 0},
                {"name": "Hostname Digits", "value": 0},
                {"name": "Hostname Entropy", "value": 2.8}
            ]
        }
        res = analyze_ml_prediction(legacy_input)
        self.assertEqual(res["status"], "AVAILABLE")
        self.assertEqual(res["model_name"], "RandomForestClassifier")
        self.assertEqual(res["model_version"], "1.0.0-synthetic")
        self.assertFalse(res["is_calibrated"])

    def test_fallback_when_hybrid_artifact_is_unavailable(self):
        """Simulating missing hybrid artifact falls back safely to legacy baseline."""
        with mock.patch.object(analyzer, "load_hybrid_model", return_value=None):
            payload = {
                "url": "https://example.com/test",
                "features": [
                    {"name": "URL Length", "value": 24},
                    {"name": "Hostname Length", "value": 11},
                    {"name": "Subdomain Count", "value": 0},
                    {"name": "Path Depth", "value": 1},
                    {"name": "Query Parameters", "value": 0},
                    {"name": "Percent Encoded Characters", "value": 0},
                    {"name": "Hostname Hyphens", "value": 0},
                    {"name": "Hostname Digits", "value": 0},
                    {"name": "Hostname Entropy", "value": 3.0}
                ]
            }
            res = analyze_ml_prediction(payload)
            self.assertEqual(res["model_name"], "RandomForestClassifier")
            self.assertEqual(res["model_version"], "1.0.0-synthetic")

    def test_facade_re_exports_hybrid_assets(self):
        """Canonical facade analyzer.py re-exports HYBRID_MODEL_PATH and load_hybrid_model."""
        self.assertTrue(hasattr(analyzer, "HYBRID_MODEL_PATH"))
        self.assertTrue(hasattr(analyzer, "load_hybrid_model"))
        self.assertIn("HYBRID_MODEL_PATH", analyzer.__all__)
        self.assertIn("load_hybrid_model", analyzer.__all__)

    def test_interpretability_ngram_extraction(self):
        """Character sub-model exposes influential n-grams with distinct indicators."""
        hybrid = load_hybrid_model()
        char_model = hybrid.char_model
        top_ngrams = char_model.get_top_ngrams(top_k=10)

        self.assertIn("malicious_indicators", top_ngrams)
        self.assertIn("benign_indicators", top_ngrams)
        self.assertEqual(len(top_ngrams["malicious_indicators"]), 10)
        self.assertEqual(len(top_ngrams["benign_indicators"]), 10)

        malicious_tokens = [item[0] for item in top_ngrams["malicious_indicators"]]
        # Common phishing signals captured by character n-grams
        self.assertTrue(any(t in malicious_tokens for t in ["php", ".php", "login", "app", "gin."]))


if __name__ == "__main__":
    unittest.main()
