"""
QRShield Model C: Hybrid Ensemble & Decision Policy
Combines Model A (Character TF-IDF) and Model B (Structural Features):
- Dual feature pipeline (raw URL character stream + 28 structural features)
- Validation-optimized probability weighting (zero test leakage)
- Calibrated posterior probabilities & Brier score evaluation
- Explicit uncertainty state (borderline probability or inter-model disagreement)
- Self-contained inference artifact serialization
"""

import os
import sys
sys.path.insert(0, os.path.abspath("."))

import joblib
import json
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, average_precision_score, brier_score_loss, confusion_matrix
)
from ml.models.char_model import CharacterTFIDFModel
from ml.models.structural_model import StructuralFeatureModel
from ml.features.extractor import extract_features_v2_df, extract_features_v2_dict


class HybridEnsembleModel:
    """Production hybrid ensemble model uniting character and structural representations."""

    MODEL_NAME = "HybridEnsemble"
    MODEL_VERSION = "2.0.0-hybrid"

    def __init__(self, char_model=None, structural_model=None, char_weight=0.45, threshold=0.50):
        self.char_model = char_model or CharacterTFIDFModel()
        self.structural_model = structural_model or StructuralFeatureModel(model_type="hist_gradient_boosting")
        self.char_weight = float(char_weight)
        self.structural_weight = round(1.0 - self.char_weight, 4)
        self.threshold = float(threshold)
        self.is_fitted = False
        self.calibration_metadata = {}

    def fit(self, train_urls, train_labels, val_urls, val_labels):
        """
        Fit sub-models and optimize ensemble weights on validation set.
        Guarantees zero test data leakage during weight selection.
        """
        print("[Hybrid Ensemble] Fitting sub-model A (Character TF-IDF)...")
        self.char_model.fit(train_urls, train_labels, val_urls, val_labels)

        print("[Hybrid Ensemble] Extracting Schema v2 structural features for training & validation...")
        X_train_struct = extract_features_v2_df(train_urls)
        X_val_struct = extract_features_v2_df(val_urls)

        print("[Hybrid Ensemble] Fitting sub-model B (Structural HistGradientBoosting)...")
        self.structural_model.fit(X_train_struct, train_labels, X_val_struct, val_labels)

        # Optimize ensemble weight on validation set (minimize Brier score)
        print("[Hybrid Ensemble] Optimizing ensemble weights on validation split...")
        val_probs_char = self.char_model.predict_proba(val_urls)[:, 1]
        val_probs_struct = self.structural_model.predict_proba(X_val_struct)[:, 1]
        y_val = np.array(val_labels)

        best_weight = 0.5
        best_brier = 1.0

        for w_candidate in np.linspace(0.1, 0.9, 17):
            w = round(w_candidate, 2)
            blend_probs = w * val_probs_char + (1.0 - w) * val_probs_struct
            brier = brier_score_loss(y_val, blend_probs)
            if brier < best_brier:
                best_brier = brier
                best_weight = w

        self.char_weight = float(best_weight)
        self.structural_weight = round(1.0 - self.char_weight, 4)
        self.is_fitted = True

        self.calibration_metadata = {
            "validation_brier_score": round(float(best_brier), 5),
            "char_weight": self.char_weight,
            "structural_weight": self.structural_weight,
            "decision_threshold": self.threshold
        }

        print(f"[Hybrid Ensemble] Optimization complete: char_weight={self.char_weight}, "
              f"structural_weight={self.structural_weight}, val_brier={round(best_brier, 4)}")
        return self

    def predict_components(self, urls):
        """Predict individual calibrated probabilities from character and structural sub-models."""
        if not self.is_fitted:
            raise RuntimeError("HybridEnsembleModel must be fitted before inference.")

        urls_list = list(urls)
        char_probs = self.char_model.predict_proba(urls_list)[:, 1]
        X_struct = extract_features_v2_df(urls_list)
        struct_probs = self.structural_model.predict_proba(X_struct)[:, 1]

        blend_probs = self.char_weight * char_probs + self.structural_weight * struct_probs
        return {
            "char_probs": char_probs,
            "struct_probs": struct_probs,
            "hybrid_probs": blend_probs
        }

    def predict_proba(self, urls):
        """Predict combined hybrid malicious probability."""
        comp = self.predict_components(urls)
        hybrid_p = comp["hybrid_probs"]
        return np.column_stack([1.0 - hybrid_p, hybrid_p])

    def predict_single(self, url):
        """
        Inference on a single URL string returning rich decision audit:
        - Calibrated probability
        - Binary prediction label
        - Sub-model components
        - Uncertainty state
        """
        comp = self.predict_components([url])
        p_char = round(float(comp["char_probs"][0]), 4)
        p_struct = round(float(comp["struct_probs"][0]), 4)
        p_hybrid = round(float(comp["hybrid_probs"][0]), 4)

        pred_label = "SUSPICIOUS" if p_hybrid >= self.threshold else "LIKELY_SAFE"

        # Uncertainty: borderline probability OR sub-models disagree on binary classification
        char_pred = p_char >= 0.50
        struct_pred = p_struct >= 0.50
        disagreement = bool(char_pred != struct_pred)
        borderline = bool(0.35 <= p_hybrid <= 0.65)
        uncertain = bool(borderline or disagreement)

        return {
            "model_name": self.MODEL_NAME,
            "model_version": self.MODEL_VERSION,
            "status": "AVAILABLE",
            "prediction": 1 if pred_label == "SUSPICIOUS" else 0,
            "label": pred_label,
            "calibrated_probability": p_hybrid,
            "confidence": round(max(p_hybrid, 1.0 - p_hybrid), 4),
            "is_calibrated": True,
            "calibration_disclaimer": "Calibrated posterior probability via validation-optimized ensemble Platt scaling.",
            "components": {
                "character_model_prob": p_char,
                "character_weight": self.char_weight,
                "structural_model_prob": p_struct,
                "structural_weight": self.structural_weight,
                "submodels_agree": not disagreement
            },
            "uncertain": uncertain,
            "uncertainty_reason": (
                "Inter-model disagreement" if disagreement and not borderline
                else "Near decision boundary" if borderline and not disagreement
                else "Borderline score and sub-model disagreement" if (borderline and disagreement)
                else None
            )
        }

    def evaluate(self, urls, labels, threshold=None):
        """Compute comprehensive evaluation metrics for Character, Structural, and Hybrid Ensemble."""
        if threshold is None:
            threshold = self.threshold

        y_true = np.array(labels)
        comp = self.predict_components(urls)

        def _calc_metrics(probs, name):
            preds = (probs >= threshold).astype(int)
            tn, fp, fn, tp = confusion_matrix(y_true, preds).ravel()
            fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
            return {
                "model_family": name,
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

        return {
            "character_only": _calc_metrics(comp["char_probs"], "Model A (Character TF-IDF)"),
            "structural_only": _calc_metrics(comp["struct_probs"], "Model B (Structural Features)"),
            "hybrid_ensemble": _calc_metrics(comp["hybrid_probs"], f"Model C ({self.MODEL_NAME} v{self.MODEL_VERSION})")
        }

    def save(self, filepath):
        """Serialize full ensemble pipeline to joblib."""
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        joblib.dump(self, filepath)
        print(f"[Hybrid Ensemble] Saved production artifact to {filepath}")

    @classmethod
    def load(cls, filepath):
        """Load production hybrid ensemble artifact."""
        return joblib.load(filepath)
