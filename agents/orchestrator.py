from agents.memory import MemoryAgent
from agents.monitoring import MonitoringAgent
from agents.threat_detection import ThreatDetectionAgent
from agents.investigation import InvestigationAgent
from logs.models import Log


class AgentOrchestrator:
    """
    Orchestrates log ingestion, detection, investigation, and memory storage.

    IMPORTANT:
    - Each run is scoped ONLY to the logs provided in the request
    - No cross-request contamination
    """

    def __init__(self) -> None:
        self.monitoring_agent = MonitoringAgent()
        self.detection_agent = ThreatDetectionAgent()
        self.investigation_agent = InvestigationAgent()
        self.memory_agent = MemoryAgent()

    def run(self, log_entries: list[dict]) -> dict:
        """
        Run full analysis pipeline for a single ingestion batch.
        """

        normalized_logs: list[dict] = []

        # --- Normalize and persist logs ---
        for entry in log_entries:
            normalized = self.monitoring_agent.normalize(entry)

            log_record = Log.objects.create(
                source=normalized.source,
                timestamp=normalized.timestamp,
                raw_message=normalized.message,
                normalized={
                    "source": normalized.source,
                    "timestamp": normalized.timestamp.isoformat(),
                    "message": normalized.message,
                    **normalized.metadata,
                },
            )

            normalized_logs.append(log_record.normalized)

        # --- Detection (signals only, no verdicts) ---
        detection = self.detection_agent.detect(normalized_logs)

        # --- Investigation (LLM-driven reasoning) ---
        investigation = self.investigation_agent.investigate(
            signals=detection.signals,
            normalized_logs=normalized_logs,
        )

        is_alert = investigation.attack_type.lower() != "benign"

        # --- Store incident AFTER analysis ---
        memory = self.memory_agent.store_incident(
            {
                "alert": is_alert,
                "confidence": investigation.confidence,
                "attack_type": investigation.attack_type,
                "severity": investigation.severity,
                "summary": investigation.summary,
                "recommendations": investigation.recommendations,
                "signals": detection.signals,
            }
        )

        # --- Final API response ---
        return {
            "incident_id": memory.incident.id,
            "alert": is_alert,
            "confidence": investigation.confidence,
            "attack_type": investigation.attack_type,
            "severity": investigation.severity,
            "summary": investigation.summary,
            "recommendations": investigation.recommendations,
            "signals": detection.signals,
            "similar_incidents": memory.similar_incidents,
        }
