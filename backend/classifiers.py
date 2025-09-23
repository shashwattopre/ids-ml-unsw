# backend/classifier.py
import json
import joblib
import numpy as np
from typing import Dict, Any
import os

# === Hardcoded paths ===
MODEL_PATH = "./model/pipeline.joblib"
SCHEMA_PATH = "./model/feature_schema.json"
ALERT_THRESHOLD = 0.90   # you can adjust


class Classifier:
    def __init__(self):
        # load schema
        with open(SCHEMA_PATH, 'r') as f:
            self.schema = json.load(f)

        # load model
        self.model = joblib.load(MODEL_PATH)
        self.feature_order = self.schema['selected_features']

    def _row_from_features(self, feats: Dict[str, Any]):
        row = [feats.get(col) for col in self.feature_order]
        return row

    def predict_proba(self, X):
        """
        Return class probabilities for input X.
        Works for sklearn Pipeline or direct estimator.
        """
        if hasattr(self.model, "predict_proba"):
            return self.model.predict_proba(X)
        elif hasattr(self.model, "steps"):  # sklearn pipeline
            try:
                final_estimator = self.model.steps[-1][1]
                if hasattr(final_estimator, "predict_proba"):
                    return final_estimator.predict_proba(X)
            except Exception:
                pass
        # fallback: fake probability from predict()
        preds = self.model.predict(X)
        return np.array([[1 - p, p] for p in preds])

    def predict(self, feats: Dict[str, Any]) -> tuple[int, float]:
        X = np.array([self._row_from_features(feats)])

        probs = self.predict_proba(X)
        p1 = float(probs[:, 1][0])
        label = int(p1 >= ALERT_THRESHOLD)
        return label, p1


# Lazy-loading proxy (so model loads only when needed)
_classif_instance = None
def get_classifier():
    global _classif_instance
    if _classif_instance is None:
        _classif_instance = Classifier()
    return _classif_instance


class _ClassifierProxy:
    def __getattr__(self, name):
        return getattr(get_classifier(), name)

    def __repr__(self):
        return f"<CLASSIFIER proxy to {get_classifier()!r}>"


# backward-compatible global
CLASSIFIER = _ClassifierProxy()
