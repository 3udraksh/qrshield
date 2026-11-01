from tests.test_base import IsolatedTestCase
from unittest import mock
import os
import analyzer


class MLConsensusTestCase(IsolatedTestCase):
    """
    Tier 1 unit tests for ML feature extraction, model inference, and consensus logic.
    """

    def test_model_artifact_load_verification(self):
        """Verify that the serialized ML model artifact exists and loads correctly."""
        self.assertTrue(
            os.path.exists(analyzer.ML_MODEL_PATH),
            f"Model artifact not found at {analyzer.ML_MODEL_PATH}"
        )
        model = analyzer.load_ml_model()
        self.assertIsNotNone(model, "Failed to deserialize model artifact with joblib")
        self.assertEqual(model.n_features_in_, 9, "Model expects exactly 9 input features")
        self.assertEqual(list(model.classes_), [0, 1], "Model must classify binary classes 0 and 1")

    def test_extract_ml_features(self):
        """Verify extraction of the 9 features in expected order."""
        empty_res = {"features": []}
        features = analyzer.extract_ml_features(empty_res)
        self.assertEqual(len(features), 1)
        self.assertEqual(len(features[0]), 9)
        self.assertEqual(features[0], [0, 0, 0, 0, 0, 0, 0, 0, 0])

        populated_res = {
            "features": [
                {"name": "URL Length", "value": 50},
                {"name": "Hostname Length", "value": 20},
                {"name": "Subdomain Count", "value": 2},
                {"name": "Path Depth", "value": 3},
                {"name": "Query Parameters", "value": 4},
                {"name": "Percent Encoded Characters", "value": 5},
                {"name": "Hostname Hyphens", "value": 1},
                {"name": "Hostname Digits", "value": 2},
                {"name": "Hostname Entropy", "value": 3.75}
            ]
        }
        features_pop = analyzer.extract_ml_features(populated_res)
        self.assertEqual(features_pop[0], [50, 20, 2, 3, 4, 5, 1, 2, 3.75])

    def test_analyze_ml_prediction_with_real_model(self):
        """Verify inference using the real read-only model artifact."""
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
        pred_safe = analyzer.analyze_ml_prediction(safe_data)
        self.assertEqual(pred_safe["status"], "AVAILABLE")
        self.assertEqual(pred_safe["prediction"], 0)
        self.assertEqual(pred_safe["label"], "LIKELY_SAFE")
        self.assertIsInstance(pred_safe["confidence"], float)

    def test_analyze_ml_prediction_missing_model_fallback(self):
        """Verify graceful fallback when model is unavailable."""
        with mock.patch.object(analyzer, "load_ml_model", return_value=None):
            res = analyzer.analyze_ml_prediction({"features": []})
            self.assertEqual(res["status"], "UNAVAILABLE")
            self.assertIsNone(res["prediction"])
            self.assertEqual(res["label"], "UNKNOWN")

    def test_evaluate_ml_consensus(self):
        """Verify agreement and disagreement logic between heuristic score and ML."""
        # Agreement Safe: score <= 20 and pred == 0
        agree_safe = analyzer.evaluate_ml_consensus(10, {"status": "AVAILABLE", "prediction": 0, "confidence": 0.95})
        self.assertEqual(agree_safe["agreement"], "AGREE_SAFE")

        # Agreement Suspicious: score > 20 and pred == 1
        agree_susp = analyzer.evaluate_ml_consensus(60, {"status": "AVAILABLE", "prediction": 1, "confidence": 0.88})
        self.assertEqual(agree_susp["agreement"], "AGREE_SUSPICIOUS")

        # Disagreement: heuristic suspicious, ML safe
        disagree_1 = analyzer.evaluate_ml_consensus(60, {"status": "AVAILABLE", "prediction": 0, "confidence": 0.85})
        self.assertEqual(disagree_1["agreement"], "ML_DISAGREEMENT")

        # Disagreement: heuristic safe, ML suspicious
        disagree_2 = analyzer.evaluate_ml_consensus(10, {"status": "AVAILABLE", "prediction": 1, "confidence": 0.85})
        self.assertEqual(disagree_2["agreement"], "ML_DISAGREEMENT")

        # Model unavailable
        unavail = analyzer.evaluate_ml_consensus(10, {"status": "UNAVAILABLE", "prediction": None})
        self.assertEqual(unavail["status"], "UNAVAILABLE")
        self.assertEqual(unavail["agreement"], "UNKNOWN")
