"""Monitoring agent for log ingestion and normalization."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass
class NormalizedLog:
    source: str
    timestamp: datetime
    message: str
    metadata: dict


class MonitoringAgent:
    """Normalize raw log entries into a consistent schema."""

    def normalize(self, entry: dict) -> NormalizedLog:
        source = entry.get("source") or "unknown"
        timestamp = entry.get("timestamp")
        if isinstance(timestamp, str):
            timestamp = datetime.fromisoformat(timestamp)
        message = entry.get("message", "")
        metadata = entry.get("metadata") or {}
        return NormalizedLog(
            source=source,
            timestamp=timestamp,
            message=message,
            metadata=metadata,
        )
