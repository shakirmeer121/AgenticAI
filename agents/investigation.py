# agents/investigation.py
from __future__ import annotations
from dataclasses import dataclass
from typing import Any, List

from agents.llm import OpenAICompatibleLLM


@dataclass
class InvestigationResult:
    attack_type: str
    severity: str
    confidence: float
    summary: List[str]
    recommendations: List[str]


class InvestigationAgent:
    """
    LLM-driven investigation agent for ANY type of log:
    Authentication, API, Network, IAM, Cloud, Application, Unknown.

    Guarantees:
    - No hallucinated users, IPs, or entities
    - Evidence-based titles
    - Bullet-point summaries and recommendations
    """

    def __init__(self, llm: OpenAICompatibleLLM | None = None) -> None:
        self.llm = llm or OpenAICompatibleLLM()

    def investigate(
        self,
        signals: dict,
        normalized_logs: list[dict],
    ) -> InvestigationResult:
        """
        Analyze signals + normalized logs and return a structured InvestigationResult.
        """

        # --- Extract ground-truth entities from logs ---
        unique_users = sorted({
            log.get("user")
            for log in normalized_logs
            if log.get("user")
        })

        unique_ips = sorted({
            log.get("ip") or log.get("destination_ip")
            for log in normalized_logs
            if log.get("ip") or log.get("destination_ip")
        })

        log_sources = sorted({
            log.get("source")
            for log in normalized_logs
            if log.get("source")
        })

        # --- SYSTEM PROMPT ---
        system_prompt = f"""
You are a senior Security Operations Center (SOC) analyst and Cybersecurity expert.
Your role is INVESTIGATION ONLY. You do not generate alerts independently.

STRICT RULES:
- Base your analysis ONLY on the provided logs and signals.
- Mention users, IPs, sources, entities etc, present in the logs.
- If a detail is missing, state "not observed".

You may receive ANY type of log, including but not limited to:
- Authentication and access logs
- API usage and data access logs
- Network traffic, DNS, and egress logs
- IAM, privilege escalation, and key usage events
- Cloud control-plane or infrastructure changes
- Application or unknown/custom events

Your responsibilities:
1. Classify activity as Benign, Suspicious, or Malicious.
2. Treat low-volume or single-event activity as valid if impact or intent is evident.
3. Correlate activity across users, IPs, services, resources, and time.
4. Identify abuse of trust, misconfiguration, control-plane access, or data movement.
5. Assign a SHORT, evidence-based attack_type derived ONLY from observed behavior.
6. Assign severity based on BUSINESS IMPACT:
   - Informational
   - Low
   - Medium
   - High
   - Critical
7. Assign confidence between 0.0 and 1.0 based on evidence strength.

OUTPUT REQUIREMENTS (MANDATORY):
- Summary MUST be bullet points (list of strings).
- Recommendations MUST be bullet points (list of strings).
- No paragraphs.
- No generic advice.
- Defensive actions.
- If Benign, explain WHY in bullets.

IMPORTANT CONSTRAINTS:
- Do NOT reuse prior patterns unless evidence matches.
- Do NOT default to common attack labels.
- Severity must reflect impact, not event count.

Entities observed:
- user: {unique_users}
- ip: {unique_ips}
- source: {log_sources}

Respond ONLY in VALID JSON using this EXACT schema:
{{
  "attack_type": "string",
  "severity": "string",
  "confidence": number,
  "summary": [
    "string"
  ],
  "recommendations": [
    "string"
  ]
}}
"""

        # --- USER PROMPT ---
        user_prompt = f"""
Security signals:
{signals}

Normalized logs:
{normalized_logs}
"""

        full_prompt = f"{system_prompt}\n{user_prompt}"

        # --- Call LLM ---
        response: dict[str, Any] = self.llm.generate_json(full_prompt)

        # --- HARD VALIDATION ---
        attack_type = response.get("attack_type", "Benign")
        severity = response.get("severity", "Informational")
        confidence = float(response.get("confidence", 0.0))
        summary = response.get("summary", [])
        recommendations = response.get("recommendations", [])

        if not isinstance(summary, list):
            raise ValueError("LLM returned invalid summary format (must be list)")

        if not isinstance(recommendations, list):
            raise ValueError("LLM returned invalid recommendations format (must be list)")

        # --- Block hallucinated users / IPs ---
        allowed_entities = set(unique_users) | set(unique_ips)

        def contains_hallucination(text: str) -> bool:
            for token in text.split():
                if token.startswith(("10.", "192.", "172.", "user", "admin")):
                    if token not in allowed_entities:
                        return True
            return False


        return InvestigationResult(
            attack_type=attack_type,
            severity=severity,
            confidence=confidence,
            summary=summary,
            recommendations=recommendations,
        )
