"""Example end-to-end execution of the pipeline."""
import os
import sys

import django

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "agentic_ai.settings")

django.setup()

from agents.orchestrator import AgentOrchestrator
from logs.simulator import generate_bruteforce_logs


if __name__ == "__main__":
    orchestrator = AgentOrchestrator()
    logs = generate_bruteforce_logs()
    result = orchestrator.run(logs)
    print("Pipeline result:")
    print(result)
