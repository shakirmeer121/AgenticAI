from collections import Counter
from dataclasses import dataclass
from ml.anomaly import AnomalyDetector


@dataclass
class DetectionResult:
    signals: dict


class ThreatDetectionAgent:
    """
    Extract raw, grounded security-relevant signals from ANY type of log.
    No verdicts. No attack names. No assumptions.
    """

    def __init__(self) -> None:
        self.anomaly_detector = AnomalyDetector()

    def detect(self, normalized_logs: list[dict]) -> DetectionResult:
        log_count = len(normalized_logs)

        event_types = [log.get("event_type", "unknown") for log in normalized_logs]
        sources = [log.get("source", "unknown") for log in normalized_logs]

        event_type_dist = Counter(event_types)
        source_dist = Counter(sources)

        # --- DOMAIN DETECTION ---
        auth_events_present = any(
            et in ("login", "auth", "authentication", "failed_login")
            for et in event_types
        )

        api_events_present = any("api" in et for et in event_types)
        network_events_present = any("network" in et for et in event_types)
        iam_events_present = any("iam" in et for et in event_types)

        activity_domains = {
            "authentication": auth_events_present,
            "api": api_events_present,
            "network": network_events_present,
            "iam": iam_events_present,
        }

        # --- USER / IP ACTIVITY (ONLY IF PRESENT) ---
        user_activity = Counter(
            log["user"] for log in normalized_logs if log.get("user")
        )

        ip_activity = Counter(
            log.get("ip") or log.get("destination_ip")
            for log in normalized_logs
            if log.get("ip") or log.get("destination_ip")
        )

        # --- ERROR & AUTH FAILURES ---
        auth_failures = [
            log for log in normalized_logs
            if log.get("event_type") in ("failed_login", "auth_failure")
        ]

        error_events = [
            log for log in normalized_logs
            if log.get("response_code", 0) >= 400
        ]

        # --- API DATA EXPORT SIGNALS ---
        api_export_events = [
            log for log in normalized_logs
            if log.get("event_type") == "api_request"
            and "export" in (log.get("endpoint", "") + log.get("message", "")).lower()
        ]

        total_bytes_sent = sum(
            log.get("bytes_sent", 0) or log.get("total_bytes_sent", 0)
            for log in normalized_logs
        )

        # --- NETWORK EXFIL SIGNALS ---
        network_egress_events = [
            log for log in normalized_logs
            if log.get("event_type") == "network_egress"
        ]

        # --- IAM RISK SIGNALS ---
        iam_risky_events = [
            log for log in normalized_logs
            if log.get("event_type", "").startswith("iam")
            and log.get("mfa_used") is False
        ]

        # --- ML ANOMALY (OPTIONAL) ---
        ml_anomaly = False
        ml_score = 0.0

        # --- FINAL SIGNALS ---
        signals = {
            "log_count": log_count,

            "activity_domains": activity_domains,

            "event_type_distribution": dict(event_type_dist),
            "source_distribution": dict(source_dist),

            "users_observed": list(user_activity.keys()),
            "ips_observed": list(ip_activity.keys()),

            "auth_events_present": auth_events_present,
            "auth_failure_count": len(auth_failures),

            "api_export_event_count": len(api_export_events),
            "total_data_bytes_observed": total_bytes_sent,

            "network_egress_event_count": len(network_egress_events),

            "iam_risky_event_count": len(iam_risky_events),

            "ml_anomaly_detected": ml_anomaly,
            "ml_anomaly_score": ml_score,
        }

        return DetectionResult(signals=signals)
