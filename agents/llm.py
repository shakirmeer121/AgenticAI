"""LLM interface abstraction for OpenAI-compatible providers."""
from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass
class LLMResponse:
    content: str


class OpenAICompatibleLLM:
    """Minimal LLM client placeholder.

    This class is intentionally lightweight and safe by default. It returns
    deterministic responses unless an API key and endpoint are configured.
    """

    def __init__(self, api_key: str | None = None, endpoint: str | None = None) -> None:
        self.api_key = api_key or os.getenv("LLM_API_KEY")
        self.endpoint = endpoint or os.getenv("LLM_API_ENDPOINT")

    def is_configured(self) -> bool:
        return bool(self.api_key and self.endpoint)

    def generate(self, prompt: str) -> LLMResponse:
        """Generate a response for the prompt.

        For safety and offline usage, this returns a deterministic response when
        the API is not configured. Integrators can extend this method with a
        real HTTP call in production.
        """
        if not self.is_configured():
            return LLMResponse(
                content=(
                    "LLM not configured. Provide LLM_API_KEY and LLM_API_ENDPOINT "
                    "to enable enhanced analysis. Prompt summary: "
                    f"{prompt[:200]}"
                )
            )

        # Placeholder for real integration. Keep deterministic for now.
        return LLMResponse(content="LLM integration stub: configure real client.")
