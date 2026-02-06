"""Optional anomaly detection using Isolation Forest."""
from __future__ import annotations

import importlib.util
from typing import Any


class AnomalyDetector:
    """Wrapper around IsolationForest with graceful fallback."""

    def __init__(self) -> None:
        self.available = importlib.util.find_spec("sklearn") is not None

    def _vectorize(self, logs: list[dict]) -> list[list[float]]:
        vectors = []
        for log in logs:
            value = float(len(log.get("message", "")))
            vectors.append([value])
        return vectors

    def detect_anomaly(self, logs: list[dict]) -> tuple[bool, float]:
        if not self.available or not logs:
            return False, 0.0

        from sklearn.ensemble import IsolationForest

        features = self._vectorize(logs)
        model = IsolationForest(contamination=0.1, random_state=42)
        model.fit(features)
        scores = model.decision_function(features)
        anomaly_score = min(scores)
        is_anomaly = anomaly_score < 0
        confidence = abs(anomaly_score)
        return bool(is_anomaly), float(confidence)
