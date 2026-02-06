"""Agent orchestrator to run the pipeline."""
from __future__ import annotations

from dataclasses import asdict

from agents.investigation import InvestigationAgent
from agents.memory import MemoryAgent
from agents.monitoring import MonitoringAgent
from agents.response import ResponseRecommendationAgent
from agents.threat_detection import ThreatDetectionAgent
from logs.models import Log


class AgentOrchestrator:
    """Run the SOC pipeline synchronously."""

    def __init__(self) -> None:
        self.monitoring_agent = MonitoringAgent()
        self.detection_agent = ThreatDetectionAgent()
        self.investigation_agent = InvestigationAgent()
        self.response_agent = ResponseRecommendationAgent()
        self.memory_agent = MemoryAgent()

    def run(self, log_entries: list[dict]) -> dict:
        normalized_logs = []
        for entry in log_entries:
            normalized = self.monitoring_agent.normalize(entry)
            Log.objects.create(
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
            normalized_logs.append({
                "source": normalized.source,
                "timestamp": normalized.timestamp.isoformat(),
                "message": normalized.message,
                **normalized.metadata,
            })

        detection_result = self.detection_agent.detect(normalized_logs)
        investigation_result = self.investigation_agent.investigate(
            detection=asdict(detection_result),
            normalized_logs=normalized_logs,
        )
        response_result = self.response_agent.recommend(asdict(investigation_result))

        memory_result = self.memory_agent.store_incident(
            {
                "alert": detection_result.alert,
                "confidence": detection_result.confidence,
                "reason": detection_result.reason,
                "attack_type": investigation_result.attack_type,
                "severity": investigation_result.severity,
                "summary": investigation_result.summary,
                "recommendations": {
                    "actions": response_result.actions,
                    "justification": response_result.justification,
                    "severity": response_result.severity,
                },
                "signals": detection_result.signals,
            }
        )

        return {
            "incident_id": memory_result.incident.id,
            "alert": detection_result.alert,
            "confidence": detection_result.confidence,
            "reason": detection_result.reason,
            "attack_type": investigation_result.attack_type,
            "severity": investigation_result.severity,
            "summary": investigation_result.summary,
            "recommendations": response_result.actions,
            "similar_incidents": memory_result.similar_incidents,
        }
