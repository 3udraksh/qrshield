"""
QRShield Model A: Character-Level TF-IDF URL Classification
Builds, tunes, calibrates, and inspects character-level n-gram models:
- Sublinear TF-IDF character vectorizer (3-5 n-grams)
- Logistic Regression
- Linear SVM
- Platt-Calibrated Linear SVM
- Influential n-gram interpretability extraction
"""

import os
import joblib
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.svm import LinearSVC
from sklearn.calibration import CalibratedClassifierCV
from sklearn.pipeline import Pipeline
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, average_precision_score, brier_score_loss, confusion_matrix
)


class CharacterTFIDFModel:
    """Character-level TF-IDF model pipeline with probability calibration."""

    def __init__(self, ngram_range=(3, 5), max_features=10000, min_df=3):
        self.ngram_range = ngram_range
        self.max_features = max_features
        self.min_df = min_df

        self.vectorizer = TfidfVectorizer(
            analyzer="char",
            ngram_range=ngram_range,
            max_features=max_features,
            min_df=min_df,
            sublinear_tf=True
        )

        self.lr_model = LogisticRegression(C=1.0, max_iter=1000, random_state=42, class_weight="balanced")
        self.svm_raw = LinearSVC(C=0.5, max_iter=2000, random_state=42, class_weight="balanced")
        self.svm_calibrated = None

        self.best_model = None
        self.is_fitted = False

    def fit(self, train_urls, train_labels, val_urls=None, val_labels=None):
        """Fit vectorizer, train candidates, and calibrate Linear SVM on validation data."""
        print(f"[Model A] Vectorizing {len(train_urls)} training URLs (char n-grams {self.ngram_range})...")
        X_train = self.vectorizer.fit_transform(train_urls)
        y_train = np.array(train_labels)

        print("[Model A] Fitting Logistic Regression...")
        self.lr_model.fit(X_train, y_train)

        print("[Model A] Fitting Linear SVM...")
        self.svm_raw.fit(X_train, y_train)

        if val_urls is not None and val_labels is not None:
            print("[Model A] Calibrating Linear SVM on validation split via Platt scaling...")
            X_val = self.vectorizer.transform(val_urls)
            y_val = np.array(val_labels)

            try:
                from sklearn.frozen import FrozenEstimator
                self.svm_calibrated = CalibratedClassifierCV(
                    estimator=FrozenEstimator(self.svm_raw),
                    method="sigmoid"
                )
            except ImportError:
                self.svm_calibrated = CalibratedClassifierCV(
                    estimator=self.svm_raw,
                    method="sigmoid",
                    cv="prefit"
                )

            self.svm_calibrated.fit(X_val, y_val)
            self.best_model = self.svm_calibrated
        else:
            self.best_model = self.lr_model

        self.is_fitted = True
        return self

    def predict_proba(self, urls, model_type="calibrated_svm"):
        """Predict calibrated malicious probabilities."""
        if not self.is_fitted:
            raise RuntimeError("Model must be fitted before inference.")

        X = self.vectorizer.transform(urls)

        if model_type == "logistic_regression":
            return self.lr_model.predict_proba(X)
        elif model_type == "calibrated_svm" and self.svm_calibrated is not None:
            return self.svm_calibrated.predict_proba(X)
        else:
            # Raw SVM decision function mapped through sigmoid as fallback
            df = self.svm_raw.decision_function(X)
            probs_1 = 1 / (1 + np.exp(-df))
            return np.column_stack([1 - probs_1, probs_1])

    def predict(self, urls, threshold=0.5, model_type="calibrated_svm"):
        """Predict binary malicious class using specified threshold."""
        probs = self.predict_proba(urls, model_type=model_type)[:, 1]
        return (probs >= threshold).astype(int)

    def evaluate(self, urls, labels, threshold=0.5, model_type="calibrated_svm"):
        """Compute complete classification and calibration metrics."""
        y_true = np.array(labels)
        probs = self.predict_proba(urls, model_type=model_type)[:, 1]
        preds = (probs >= threshold).astype(int)

        tn, fp, fn, tp = confusion_matrix(y_true, preds).ravel()
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

        return {
            "model_family": f"Model A (Char TF-IDF - {model_type})",
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

    def get_top_ngrams(self, top_k=20):
        """Extract top influential character n-grams from the Linear SVM / Logistic Regression."""
        feature_names = self.vectorizer.get_feature_names_out()
        weights = self.lr_model.coef_[0]

        top_malicious_idx = np.argsort(weights)[-top_k:][::-1]
        top_benign_idx = np.argsort(weights)[:top_k]

        return {
            "malicious_indicators": [(feature_names[i], round(float(weights[i]), 4)) for i in top_malicious_idx],
            "benign_indicators": [(feature_names[i], round(float(weights[i]), 4)) for i in top_benign_idx]
        }

    def save(self, filepath):
        """Save vectorizer, fitted models, and configuration to joblib."""
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        joblib.dump(self, filepath)
        print(f"[Model A] Saved artifact to {filepath}")

    @classmethod
    def load(cls, filepath):
        """Load character model artifact."""
        return joblib.load(filepath)
