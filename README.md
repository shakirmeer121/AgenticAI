# AgenticAI - Autonomous Defensive SOC

This project is a **defensive-only** autonomous cybersecurity threat analysis system built with **Django** and plain Python agents. It simulates a lightweight SOC pipeline: log ingestion → detection → investigation → response recommendations → memory.

> ✅ **Defensive use only**. No offensive hacking or exploit execution is included.

## Features

- **Log ingestion API** (`POST /api/logs/`)
- **Incident listing API** (`GET /api/incidents/`)
- Modular agents:
  - MonitoringAgent (normalization)
  - ThreatDetectionAgent (rules + optional ML)
  - InvestigationAgent (LLM or deterministic)
  - ResponseRecommendationAgent (defensive actions)
  - MemoryAgent (DB + vector store fallback)
- **Isolation Forest** anomaly detection (optional)
- **Vector memory** fallback if FAISS/Chroma unavailable
- **Simulated brute-force log generator**
- **Unit tests** for detection logic

## Project Structure

```
agentic_ai/          # Django project settings
agents/              # Agent classes
logs/                # Log ingestion app
incidents/           # Incident storage app
ml/                  # ML helpers (Isolation Forest)
scripts/             # Demo pipeline script
```

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python manage.py migrate
python manage.py createsuperuser
```

## Running the API

```bash
python manage.py runserver
```

### Ingest Logs

```bash
curl -X POST http://localhost:8000/api/logs/ \
  -H "Content-Type: application/json" \
  -d '{"logs": [{"source": "auth-service", "timestamp": "2024-01-01T00:00:00", "message": "Failed login", "metadata": {"event_type": "login_failed", "source_ip": "192.0.2.10"}}]}'
```

### List Incidents

```bash
curl http://localhost:8000/api/incidents/
```

## Simulated Log Generator

```python
from logs.simulator import generate_bruteforce_logs
logs = generate_bruteforce_logs(attempts=6)
```

## Demo Pipeline Execution

```bash
python manage.py migrate
python scripts/demo_pipeline.py
```

## Testing

```bash
python -m unittest tests/test_threat_detection.py
```

## Troubleshooting

- **`no such table: logs_log` or `incidents_incident`** → Run `python manage.py migrate` before executing the demo script or hitting the APIs.

## Agent Workflow

1. **MonitoringAgent** normalizes logs into a consistent schema.
2. **ThreatDetectionAgent** flags rule-based anomalies (e.g., repeated failed logins) and optionally uses Isolation Forest.
3. **InvestigationAgent** summarizes the threat and classifies attack type and severity.
4. **ResponseRecommendationAgent** provides defensive-only recommendations.
5. **MemoryAgent** stores incidents via Django ORM and keeps embeddings for similarity lookup.

## Extensibility

- Replace the LLM stub in `agents/llm.py` with a real OpenAI-compatible client.
- Swap the vector store with FAISS or Chroma by installing those libraries.
- Add async task processing with Celery for production use.

## Security Note

This project is designed strictly for defensive analysis and simulation. It does **not** execute attacks, exploit systems, or provide offensive tooling.
