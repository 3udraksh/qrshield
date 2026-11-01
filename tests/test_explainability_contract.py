from tests.test_base import IsolatedTestCase
import analyzer


class ExplainabilityContractTestCase(IsolatedTestCase):
    """
    Tier 1 unit tests for validate_explainability() contract verification.
    """

    def _get_valid_result_stub(self):
        return {
            "score": 15,
            "risk": "LOW RISK",
            "findings": [{"severity": "low", "message": "Notice"}],
            "explanations": [{"title": "Notice", "what": "Detail", "why_it_matters": "Context", "user_action": "Check"}],
            "overall_explanation": "Overall explanation text",
            "risk_evidence_explanation": "Evidence explanation text",
            "risk_analysis": {
                "score": 15,
                "risk": "LOW RISK",
                "risk_basis": "No significant indicators",
                "confidence": "HIGH",
                "evidence": {"high": 0, "medium": 0, "low": 1},
                "correlation": {"level": "NONE", "count": 0, "signals": []}
            }
        }

    def test_valid_contract_passes(self):
        """A complete, consistent result object passes validation."""
        result = self._get_valid_result_stub()
        val = analyzer.validate_explainability(result)
        self.assertTrue(val["valid"])
        self.assertEqual(val["missing"], [])

    def test_non_dict_result_fails(self):
        """Passing non-dict input fails validation."""
        val = analyzer.validate_explainability("invalid_input")
        self.assertFalse(val["valid"])
        self.assertEqual(val["missing"], ["result"])

    def test_missing_top_level_field(self):
        """Missing top-level required fields are identified."""
        result = self._get_valid_result_stub()
        del result["overall_explanation"]
        val = analyzer.validate_explainability(result)
        self.assertFalse(val["valid"])
        self.assertIn("overall_explanation", val["missing"])

    def test_missing_risk_analysis_subfield(self):
        """Missing risk_analysis subfield is identified."""
        result = self._get_valid_result_stub()
        del result["risk_analysis"]["confidence"]
        val = analyzer.validate_explainability(result)
        self.assertFalse(val["valid"])
        self.assertIn("confidence", val["missing"])

    def test_score_inconsistency(self):
        """Mismatch between result score and risk_analysis score is caught."""
        result = self._get_valid_result_stub()
        result["score"] = 45  # Mismatched from risk_analysis["score"] = 15
        val = analyzer.validate_explainability(result)
        self.assertFalse(val["valid"])
        self.assertEqual(val["missing"], ["score_consistency"])

    def test_risk_level_inconsistency(self):
        """Mismatch between result risk and risk_analysis risk is caught."""
        result = self._get_valid_result_stub()
        result["risk"] = "HIGH RISK"  # Mismatched from risk_analysis["risk"] = "LOW RISK"
        val = analyzer.validate_explainability(result)
        self.assertFalse(val["valid"])
        self.assertEqual(val["missing"], ["risk_consistency"])
