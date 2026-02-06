"""Simulated log generator for testing the pipeline."""
from __future__ import annotations

<<<<<<< codex/build-autonomous-cybersecurity-threat-analysis-system-odyc78
from datetime import datetime, timedelta, timezone
=======
from datetime import datetime, timedelta
>>>>>>> main


def generate_bruteforce_logs(
    username: str = "admin",
    source_ip: str = "192.0.2.10",
    attempts: int = 6,
) -> list[dict]:
<<<<<<< codex/build-autonomous-cybersecurity-threat-analysis-system-odyc78
    now = datetime.now(timezone.utc)
=======
    now = datetime.utcnow()
>>>>>>> main
    logs = []
    for i in range(attempts):
        logs.append(
            {
                "source": "auth-service",
                "timestamp": (now + timedelta(seconds=i)).isoformat(),
                "message": f"Failed login for {username}",
                "metadata": {
                    "event_type": "login_failed",
                    "username": username,
                    "source_ip": source_ip,
                },
            }
        )
    return logs
