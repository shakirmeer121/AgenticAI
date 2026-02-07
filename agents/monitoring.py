from dataclasses import dataclass
from datetime import datetime
from django.utils.dateparse import parse_datetime
from django.utils import timezone


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

        # If missing or invalid, default to current time
        if not timestamp:
            timestamp = timezone.now()
        elif isinstance(timestamp, str):
            try:
                timestamp = timezone.make_aware(datetime.fromisoformat(timestamp))
            except Exception:
                timestamp = timezone.now()

        message = entry.get("message") or entry.get("raw_message") or ""
        metadata = entry.get("metadata") or {}

        return NormalizedLog(
            source=source,
            timestamp=timestamp,
            message=message,
            metadata=metadata,
        )
