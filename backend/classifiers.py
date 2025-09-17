import json
import time
import joblib
import numpy as np
from typing import Dict, Any
from .settings import SETTINGS

class Classifier:
    def __init__(self):
        with open(SETTINGS.schema_path, 'r') as f:
            self.schema = json.load(f)
        self.model = joblib.load(SETTINGS.model_path)
        self.feature_order = self.schema['selected_features']

    def _row_from_features(self, feats: Dict[str, Any]):
        row = [feats.get(col) for col in self.feature_order]
        return row

    def predict(self, feats: Dict[str, Any]) -> tuple[int, float]:
        X = np.array([self._row_from_features(feats)])
        proba = getattr(self.model, 'predict_proba', None)
        if proba:
            p1 = float(proba(X)[:,1][0])
            label = int(p1 >= SETTINGS.alert_threshold)
            return label, p1
        # Fallback for models without probas
        pred = int(self.model.predict(X)[0])
        score = 1.0 if pred == 1 else 0.0
        return pred, score

CLASSIFIER = Classifier()
