"""
QRShield Model B: Structural Feature URL Classification
Builds, evaluates, and compares tree-based and boosting models on versioned structural features:
- Historical Random Forest (Schema v1 baseline, 9 features)
- Enhanced Random Forest (Schema v2, 28 features)
- Extra Trees Classifier (Schema v2)
- HistGradientBoosting Classifier (Schema v2)
"""

import os
import sys
sys.path.insert(0, os.path.abspath("."))

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import (
    RandomForestClassifier,
    ExtraTreesClassifier,
    HistGradientBoostingClassifier
)
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, average_precision_score, brier_score_loss, confusion_matrix
)
from ml.features.extractor import (
    SCHEMA_V1_COLUMNS,
    SCHEMA_V2_COLUMNS,
    extract_features_v1,
    extract_features_v2_df
)


class StructuralFeatureModel:
    """Structural feature classification model pipeline."""

    def __init__(self, model_type="hist_gradient_boosting"):
        self.model_type = model_type
        self.feature_columns = SCHEMA_V2_COLUMNS

        if model_type == "random_forest_v1":
            self.feature_columns = SCHEMA_V1_COLUMNS
            self.model = RandomForestClassifier(n_estimators=100, max_depth=12, random_state=42, n_jobs=-1)
        elif model_type == "random_forest_v2":
            self.model = RandomForestClassifier(n_estimators=150, max_depth=16, random_state=42, n_jobs=-1)
        elif model_type == "extra_trees":
            self.model = ExtraTreesClassifier(n_estimators=150, max_depth=16, random_state=42, n_jobs=-1)
        elif model_type == "hist_gradient_boosting":
            self.model = HistGradientBoostingClassifier(
                max_iter=150,
                max_depth=10,
                learning_rate=0.08,
                random_state=42
            )
        else:
            raise ValueError(f"Unknown model_type: {model_type}")

        self.calibrated_model = None
        self.is_fitted = False

    def fit(self, X_train, y_train, X_val=None, y_val=None):
        """Fit structural model on extracted features and calibrate probabilities on validation set."""
        print(f"[Model B] Fitting {self.model_type} on {X_train.shape[0]} samples ({X_train.shape[1]} features)...")
        self.model.fit(X_train, y_train)

        if X_val is not None and y_val is not None:
            print(f"[Model B] Calibrating probabilities on validation split via Platt scaling...")
            try:
                from sklearn.frozen import FrozenEstimator
                self.calibrated_model = CalibratedClassifierCV(
                    estimator=FrozenEstimator(self.model),
                    method="sigmoid"
                )
            except ImportError:
                self.calibrated_model = CalibratedClassifierCV(
                    estimator=self.model,
                    method="sigmoid",
                    cv="prefit"
                )
            self.calibrated_model.fit(X_val, y_val)
        else:
            self.calibrated_model = None

        self.is_fitted = True
        return self

    def predict_proba(self, X):
        """Predict probabilities using calibrated model if available."""
        if not self.is_fitted:
            raise RuntimeError("Model must be fitted before inference.")

        if self.calibrated_model is not None:
            return self.calibrated_model.predict_proba(X)
        return self.model.predict_proba(X)

    def predict(self, X, threshold=0.5):
        """Predict binary malicious class using specified threshold."""
        probs = self.predict_proba(X)[:, 1]
        return (probs >= threshold).astype(int)

    def evaluate(self, X, y, threshold=0.5):
        """Compute full classification and calibration metrics."""
        y_true = np.array(y)
        probs = self.predict_proba(X)[:, 1]
        preds = (probs >= threshold).astype(int)

        tn, fp, fn, tp = confusion_matrix(y_true, preds).ravel()
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

        return {
            "model_family": f"Model B (Structural - {self.model_type})",
            "accuracy": round(accuracy_score(y_true, preds), 4),
            "precision": round(precision_score(y_true, preds, zero_division=0), 4),
            "recall": round(recall_score(y_true, preds, zero_division=0), 4),
            "f1": round(f1_score(y_true, preds, zero_division=0), 4),
            "roc_auc": round(roc_auc_score(y_true, probs), 4),
            "pr_auc": round(average_precision_score(y_true, probs), 4),
            "brier_score": round(brier_score_loss(y_true, probs), 4),
            "fpr": round(fpr, 4),
            "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)}
        }

    def get_feature_importances(self):
        """Extract feature importances if supported by the model architecture."""
        if hasattr(self.model, "feature_importances_"):
            importances = self.model.feature_importances_
            pairs = sorted(zip(self.feature_columns, importances), key=lambda p: p[1], reverse=True)
            return [(col, round(float(val), 4)) for col, val in pairs]
        return []

    def save(self, filepath):
        """Save fitted model and feature schema to joblib."""
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        joblib.dump(self, filepath)
        print(f"[Model B] Saved artifact to {filepath}")

    @classmethod
    def load(cls, filepath):
        """Load structural model artifact."""
        return joblib.load(filepath)
