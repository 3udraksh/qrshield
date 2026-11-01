"""
QRShield Machine Learning Feature Extraction, Model Inference & Consensus
"""

import os
import joblib
import pandas as pd
from qrshield.constants import ML_MODEL_PATH
from qrshield.compat import dispatch


def load_ml_model():
    """
    Load the pre-trained Random Forest model artifact.
    """
    if not os.path.exists(ML_MODEL_PATH):
        return None

    try:
        return joblib.load(ML_MODEL_PATH)
    except Exception:
        return None


def extract_ml_features(result):
    """
    Extract the standard 9-feature numerical vector from an analysis result.
    """
    feature_map = {
        feature.get("name"): feature.get("value")
        for feature in result.get("features", [])
        if isinstance(feature, dict)
    }

    return [[
        feature_map.get("URL Length", 0),
        feature_map.get("Hostname Length", 0),
        feature_map.get("Subdomain Count", 0),
        feature_map.get("Path Depth", 0),
        feature_map.get("Query Parameters", 0),
        feature_map.get("Percent Encoded Characters", 0),
        feature_map.get("Hostname Hyphens", 0),
        feature_map.get("Hostname Digits", 0),
        feature_map.get("Hostname Entropy", 0)
    ]]


def analyze_ml_prediction(result):
    """
    Run machine-learning inference on an analysis result.
    """
    model = dispatch("load_ml_model", load_ml_model)()

    if model is None:
        return {
            "status": "UNAVAILABLE",
            "prediction": None,
            "label": "UNKNOWN",
            "confidence": None
        }

    try:
        features = extract_ml_features(result)
        feature_names = [
            "URL Length",
            "Hostname Length",
            "Subdomain Count",
            "Path Depth",
            "Query Parameters",
            "Percent Encoded Characters",
            "Hostname Hyphens",
            "Hostname Digits",
            "Hostname Entropy"
        ]

        df = pd.DataFrame(features, columns=feature_names)
        prediction = int(model.predict(df)[0])
        probabilities = model.predict_proba(df)[0]
        confidence = float(max(probabilities))
        label = "SUSPICIOUS" if prediction == 1 else "LIKELY_SAFE"

        return {
            "status": "AVAILABLE",
            "prediction": prediction,
            "label": label,
            "confidence": round(confidence, 3)
        }

    except Exception as error:
        return {
            "status": "ERROR",
            "prediction": None,
            "label": "UNKNOWN",
            "confidence": None,
            "error": str(error)
        }


def evaluate_ml_consensus(score, ml_analysis):
    """
    Evaluate consensus between the rule-based heuristic score and ML model prediction.
    """
    if not isinstance(ml_analysis, dict):
        return {
            "status": "UNAVAILABLE",
            "agreement": "UNKNOWN",
            "confidence": None,
            "message": "Machine learning analysis is unavailable."
        }

    if ml_analysis.get("status") != "AVAILABLE":
        return {
            "status": ml_analysis.get("status", "UNAVAILABLE"),
            "agreement": "UNKNOWN",
            "confidence": ml_analysis.get("confidence"),
            "message": "Machine learning analysis could not be used."
        }

    prediction = ml_analysis.get("prediction")
    confidence = ml_analysis.get("confidence")

    if prediction not in (0, 1):
        return {
            "status": "AVAILABLE",
            "agreement": "UNKNOWN",
            "confidence": confidence,
            "message": "Machine learning prediction is unavailable."
        }

    if score <= 20:
        heuristic_label = "LIKELY_SAFE"
    else:
        heuristic_label = "SUSPICIOUS"

    ml_label = "SUSPICIOUS" if prediction == 1 else "LIKELY_SAFE"

    if heuristic_label == ml_label:
        agreement = "AGREE_SAFE" if prediction == 0 else "AGREE_SUSPICIOUS"
        message = "Machine learning and heuristic analysis agree."
    else:
        agreement = "ML_DISAGREEMENT"
        message = (
            "Machine learning and heuristic analysis disagree. "
            "The existing heuristic risk assessment remains authoritative."
        )

    return {
        "status": "AVAILABLE",
        "agreement": agreement,
        "heuristic_label": heuristic_label,
        "ml_label": ml_label,
        "confidence": confidence,
        "message": message
    }
