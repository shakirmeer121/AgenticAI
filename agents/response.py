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
                "Add the source IPs to a temporary blocklist or rate limiter.",
                "Notify the security team and document the incident.",
            ]
            justification = "High-risk authentication abuse detected."
        else:
            actions = [
                "Continue monitoring authentication logs for unusual patterns.",
                "Educate users on strong password hygiene.",
            ]
            justification = "No critical indicators detected."

        prompt = (
            "Provide defensive remediation steps in JSON. "
            f"Investigation: {investigation}"
        )
        llm_response = self.llm.generate(prompt)
        if self.llm.is_configured():
            return ResponseRecommendation(actions=[llm_response.content], justification="LLM response", severity=severity)

        return ResponseRecommendation(actions=actions, justification=justification, severity=severity)
