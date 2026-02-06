"""Investigation agent that explains threats using LLM or heuristics."""
from __future__ import annotations

from dataclasses import dataclass

from agents.llm import OpenAICompatibleLLM


@dataclass
class InvestigationResult:
    attack_type: str
    severity: str
    summary: str


class InvestigationAgent:
    """Classify and explain the detected threat."""

    def __init__(self, llm: OpenAICompatibleLLM | None = None) -> None:
        self.llm = llm or OpenAICompatibleLLM()

    def investigate(self, detection: dict, normalized_logs: list[dict]) -> InvestigationResult:
        if detection["alert"]:
            attack_type = "Brute Force"
            severity = "High"
            summary = (
                "Repeated authentication failures suggest a brute force attempt "
                "against protected accounts. The activity is focused and likely automated."
            )
        else:
            attack_type = "Benign"
            severity = "Low"
            summary = "No indicators of malicious activity were found in the provided logs."

        prompt = (
            "You are a SOC analyst. Summarize the incident, classify attack type, "
            "assess severity, and explain intent and risk. Logs: "
            f"{normalized_logs} Detection: {detection}"
        )
        llm_response = self.llm.generate(prompt)
        if self.llm.is_configured():
            summary = llm_response.content

        return InvestigationResult(attack_type=attack_type, severity=severity, summary=summary)
