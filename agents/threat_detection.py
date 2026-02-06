"""Threat detection agent with rule-based and optional ML detection."""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from ml.anomaly import AnomalyDetector


@dataclass
class DetectionResult:
    alert: bool
    confidence: float
    reason: str
    signals: dict


class ThreatDetectionAgent:
    """Detect suspicious behavior using deterministic rules and ML."""

    def __init__(self, failed_login_threshold: int = 5) -> None:
        self.failed_login_threshold = failed_login_threshold
        self.anomaly_detector = AnomalyDetector()

    def detect(self, normalized_logs: list[dict]) -> DetectionResult:
        failed_logins = [
            log for log in normalized_logs if log.get("event_type") == "login_failed"
        ]
        ip_counts = Counter(log.get("source_ip", "unknown") for log in failed_logins)
        suspicious_ips = [ip for ip, count in ip_counts.items() if count >= self.failed_login_threshold]

        signals = {
            "failed_login_count": len(failed_logins),
            "suspicious_ips": suspicious_ips,
        }

        rule_alert = bool(suspicious_ips)
        rule_confidence = 0.8 if rule_alert else 0.2
        rule_reason = (
            "Multiple failed login attempts detected from the same source." if rule_alert else "No rule-based alerts."
        )

        ml_alert = False
        ml_confidence = 0.0
        ml_reason = "ML anomaly detection unavailable."
        if self.anomaly_detector.available:
            ml_alert, ml_confidence = self.anomaly_detector.detect_anomaly(normalized_logs)
            ml_reason = (
                "ML model detected anomalous log patterns." if ml_alert else "ML model found no anomalies."
            )
            signals["ml_score"] = ml_confidence

        alert = rule_alert or ml_alert
        confidence = max(rule_confidence, ml_confidence)
        reason = f"{rule_reason} {ml_reason}"

        return DetectionResult(alert=alert, confidence=confidence, reason=reason, signals=signals)
