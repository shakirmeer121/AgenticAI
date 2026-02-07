"""Response recommendation agent for defensive actions."""
from __future__ import annotations

from dataclasses import dataclass
from agents.llm import OpenAICompatibleLLM


@dataclass
class ResponseRecommendation:
    actions: list[str]
    justification: str
    severity: str


class ResponseRecommendationAgent:
    """Suggest defensive remediation steps only."""

    def __init__(self, llm: OpenAICompatibleLLM | None = None) -> None:
        self.llm = llm or OpenAICompatibleLLM()

    def recommend(self, investigation: dict) -> ResponseRecommendation:
        severity = investigation.get("severity", "Low")

        if severity == "High":
            actions = [
                "Temporarily lock targeted accounts after repeated failures.",
                "Enforce multi-factor authentication for privileged users.",
                "Block or rate-limit the source IP.",
                "Notify the security team and document the incident.",
            ]
            justification = "Confirmed brute force behavior detected."

        elif severity == "Medium":
            actions = [
                "Monitor the source IP for continued authentication failures.",
                "Apply temporary rate limiting on login endpoints.",
                "Escalate if activity continues.",
            ]
            justification = "Suspicious authentication behavior detected."

        else:
            actions = [
                "Continue monitoring authentication logs.",
                "Educate users on strong password practices.",
            ]
            justification = "No immediate threat detected."

        if self.llm.is_configured():
            llm_response = self.llm.generate(
                f"Provide defensive recommendations for: {investigation}"
            )
            return ResponseRecommendation(
                actions=[llm_response.content],
                justification="LLM-generated recommendation",
                severity=severity,
            )

        return ResponseRecommendation(actions, justification, severity)
