# agents/llm.py
from __future__ import annotations
import json, os, re
from typing import Any
from openai import OpenAI


class OpenAICompatibleLLM:
    """OpenAI-compatible LLM wrapper for OpenRouter with entity enforcement."""

    def __init__(self) -> None:
        api_key = os.getenv("OPENROUTER_API_KEY")
        if not api_key:
            raise RuntimeError(
                "OPENROUTER_API_KEY is not set. LLM-driven analysis cannot run."
            )

        self.client = OpenAI(
            api_key=api_key,
            base_url="https://openrouter.ai/api/v1",
        )

        self.model = "gpt-4o-mini"

    def generate_json(self, prompt: str, allowed_entities: dict[str, list[str]] | None = None) -> dict[str, Any]:
        """
        Generate structured JSON from LLM prompt.
        
        Optional:
        allowed_entities = {
            "users": ["service_backup"],
            "ips": ["185.231.77.12"],
            "sources": ["api-gateway","network-monitor","iam-service"]
        }
        The LLM will be instructed NOT to invent any entity outside these lists.
        """

        # Append strict entity rules to the prompt
        if allowed_entities:
            entities_text = json.dumps(allowed_entities, indent=2)
            entity_instructions = (
                "\n\nIMPORTANT: ONLY refer to the users, IPs, and sources listed below. "
                "Do NOT invent any other users, IPs, or sources. If a field is not present, leave it blank or omit it.\n"
                f"Allowed entities:\n{entities_text}"
            )
            prompt = prompt + entity_instructions

        response = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {
                    "role": "system",
                    "content": (
                        
                """
                You are a senior Security Operations Center (SOC) analyst and Cybersecurity expert.
                Your task is INVESTIGATION. You do NOT generate detections or alerts independently.

                You MUST base your analysis STRICTLY AND ONLY on the provided logs and signals.
                - Mention users, IPs, sources, entities etc, present in the logs.

                You may receive ANY type of log, including but NOT LIMITED TO:
                - Authentication and access logs
                - API usage and data access logs
                - Network traffic, DNS, and egress logs
                - IAM, privilege escalation, API key, and credential events
                - Cloud control-plane, CI/CD, or infrastructure changes
                - Application, service-mesh, or custom events
                - Previously unseen or unknown log formats

                Your responsibilities:
                1. Determine whether the activity is **Benign, Suspicious, or Malicious** based on observed behavior.
                2. Treat **low-volume, slow, single-event, or stealthy activity** as valid attacks if intent or impact is implied.
                3. Correlate events across:
                - Sources
                - Users / service accounts
                - IPs / destinations
                - Resources / endpoints
                - Time sequence
                4. Identify:
                - Abuse of trust
                - Misconfiguration
                - Control-plane access
                - Credential misuse
                - Data movement or exfiltration patterns
                5. Assign a short, **evidence-based attack_type**:
                - The title MUST be derived directly from observed behavior.
                - DO NOT use generic labels (e.g., “Brute Force”, “Suspicious Activity”) unless explicitly supported.
                6. Assign severity using BUSINESS IMPACT:
                - Informational: Expected or harmless behavior
                - Low: Suspicious, no clear impact
                - Medium: Confirmed threat, limited scope
                - High: Privilege abuse, sensitive access, or exposure
                - Critical: Systemic compromise, control-plane abuse, data exfiltration, or business risk
                7. Assign a confidence score between 0.0 and 1.0 reflecting **strength of evidence**, not intuition.

                OUTPUT REQUIREMENTS (MANDATORY):
                8. The **summary MUST be in clear bullet points**, NOT paragraphs.
                Each bullet MUST:
                - Reference observed entities (users, IPs, services, endpoints)
                - Explain WHY the behavior matters
                9. The **recommendations MUST be in clear bullet points**, NOT paragraphs.
                Each recommendation MUST:
                - Be defensive only
                - Be directly tied to observed entities or misconfigurations
                - Avoid generic advice (e.g., “monitor closely”, “improve security”)
                10. If evidence is insufficient for an attack, classify as **Benign** and explain WHY in bullets.

                IMPORTANT CONSTRAINTS:
                - Mention users, IPs, sources, entities etc, present in the logs.
                - DO NOT reuse prior incident patterns unless the evidence clearly matches.
                - DO NOT assume intent — infer only from observable impact and behavior.
                - If a common attack type is NOT clearly supported, DO NOT use it.
                - Severity MUST align with **potential business and security impact**, not event count.

                Respond ONLY in VALID JSON using this EXACT schema:
                {
                "attack_type": string,
                "severity": string,
                "confidence": number,
                "summary": [
                    string
                ],
                "recommendations": [
                    string
                ]
                }

                """
                                        
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            temperature=0.3,
        )

        content = response.choices[0].message.content
        if not content:
            raise RuntimeError("LLM returned empty response")

        # --- sanitize LLM output ---
        # Remove ```json or ``` code fences
        content = re.sub(r"^```json\s*", "", content.strip(), flags=re.IGNORECASE)
        content = re.sub(r"^```", "", content.strip())
        content = re.sub(r"\s*```$", "", content.strip())
        content = content.strip()

        # --- enforce allowed entities in output ---
        if allowed_entities:
            content = self._sanitize_entities(content, allowed_entities)

        try:
            return json.loads(content)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"LLM returned invalid JSON:\n{content}") from exc

    def _sanitize_entities(self, content: str, allowed_entities: dict[str, list[str]]) -> str:
        """
        Replace any user/IP/source mentions in content that are not in allowed_entities with [REDACTED].
        """
        # Sanitize users
        for u in re.findall(r"\b\w+\b", content):
            if "users" in allowed_entities and u not in allowed_entities["users"]:
                content = re.sub(rf"\b{re.escape(u)}\b", "[REDACTED]", content)

        # Sanitize IPs
        ips_in_text = re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", content)
        for ip in ips_in_text:
            if "ips" in allowed_entities and ip not in allowed_entities["ips"]:
                content = content.replace(ip, "[REDACTED]")

        # Sanitize sources
        for src in allowed_entities.get("sources", []):
            if src not in allowed_entities["sources"]:
                content = content.replace(src, "[REDACTED]")

        return content
