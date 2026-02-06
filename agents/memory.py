"""Memory agent for storing and retrieving incidents."""
from __future__ import annotations

import importlib.util
import math
from dataclasses import dataclass

from incidents.models import Incident


@dataclass
class MemoryResult:
    incident: Incident
    similar_incidents: list[dict]


class SimpleVectorStore:
    """Simple in-memory vector store fallback."""

    def __init__(self) -> None:
        self.vectors: list[tuple[int, list[float], dict]] = []

    def upsert(self, incident_id: int, vector: list[float], metadata: dict) -> None:
        self.vectors.append((incident_id, vector, metadata))

    def query(self, vector: list[float], top_k: int = 3) -> list[dict]:
        scored = []
        for incident_id, stored_vector, metadata in self.vectors:
            score = self._cosine_similarity(vector, stored_vector)
            scored.append({"incident_id": incident_id, "score": score, "metadata": metadata})
        scored.sort(key=lambda item: item["score"], reverse=True)
        return scored[:top_k]

    @staticmethod
    def _cosine_similarity(vec_a: list[float], vec_b: list[float]) -> float:
        dot = sum(a * b for a, b in zip(vec_a, vec_b))
        norm_a = math.sqrt(sum(a * a for a in vec_a))
        norm_b = math.sqrt(sum(b * b for b in vec_b))
        if norm_a == 0 or norm_b == 0:
            return 0.0
        return dot / (norm_a * norm_b)


class MemoryAgent:
    """Store incidents and retrieve similar cases."""

    def __init__(self) -> None:
        self.vector_store = self._init_vector_store()

    def _init_vector_store(self) -> SimpleVectorStore:
        if importlib.util.find_spec("faiss"):
            return SimpleVectorStore()
        if importlib.util.find_spec("chromadb"):
            return SimpleVectorStore()
        return SimpleVectorStore()

    def _embed(self, text: str) -> list[float]:
        vector = [0.0] * 16
        for token in text.lower().split():
            idx = hash(token) % len(vector)
            vector[idx] += 1.0
        return vector

    def store_incident(self, incident_data: dict) -> MemoryResult:
        incident = Incident.objects.create(**incident_data)
        vector = self._embed(incident.summary)
        self.vector_store.upsert(incident.id, vector, {"summary": incident.summary})
        similar = self.vector_store.query(vector)
        return MemoryResult(incident=incident, similar_incidents=similar)
