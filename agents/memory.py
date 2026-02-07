"""
Memory agent for storing and retrieving similar security incidents.
"""
from __future__ import annotations

import importlib.util
import math
from dataclasses import dataclass
from typing import List, Dict

from incidents.models import Incident


@dataclass
class MemoryResult:
    incident: Incident
    similar_incidents: List[Dict]


class SimpleVectorStore:
    """
    Simple in-memory vector store.
    Can be replaced with FAISS / Chroma later.
    """

    def __init__(self) -> None:
        self.vectors: list[tuple[int, list[float], dict]] = []

    def upsert(self, incident_id: int, vector: list[float], metadata: dict) -> None:
        self.vectors.append((incident_id, vector, metadata))

    def query(self, vector: list[float], exclude_id: int, top_k: int = 3) -> list[dict]:
        scored = []

        for incident_id, stored_vector, metadata in self.vectors:
            if incident_id == exclude_id:
                continue

            score = self._cosine_similarity(vector, stored_vector)
            scored.append(
                {
                    "incident_id": incident_id,
                    "score": score,
                    "metadata": metadata,
                }
            )

        scored.sort(key=lambda x: x["score"], reverse=True)
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
    """
    Stores incidents and retrieves semantically similar past cases.
    """

    def __init__(self) -> None:
        self.vector_store = self._init_vector_store()

    def _init_vector_store(self) -> SimpleVectorStore:
        # Future extension point
        if importlib.util.find_spec("faiss"):
            return SimpleVectorStore()
        if importlib.util.find_spec("chromadb"):
            return SimpleVectorStore()
        return SimpleVectorStore()

    def _embed(self, text: str) -> list[float]:
        """
        Simple hashing-based embedding.
        Deterministic and offline-safe.
        """
        vector = [0.0] * 32
        for token in text.lower().split():
            idx = abs(hash(token)) % len(vector)
            vector[idx] += 1.0
        return vector

    def _flatten_field(self, value) -> str:
        """
        Safely flatten strings or list[str] into a single string.
        """
        if isinstance(value, list):
            return " ".join(str(v) for v in value if v)
        if isinstance(value, str):
            return value
        return ""

    def store_incident(self, incident_data: dict) -> MemoryResult:
        """
        Persist incident and store vector for similarity search.
        """

        incident = Incident.objects.create(**incident_data)

        # --- Build embedding context safely ---
        embedding_text = " ".join(
            filter(
                None,
                [
                    self._flatten_field(incident.attack_type),
                    self._flatten_field(incident.severity),
                    self._flatten_field(incident.summary),
                    self._flatten_field(incident.recommendations),
                ],
            )
        ).strip()

        if not embedding_text:
            embedding_text = "unknown incident"

        vector = self._embed(embedding_text)

        self.vector_store.upsert(
            incident.id,
            vector,
            {
                "attack_type": incident.attack_type,
                "severity": incident.severity,
                "summary": incident.summary,
            },
        )

        similar = self.vector_store.query(
            vector=vector,
            exclude_id=incident.id,
            top_k=3,
        )

        return MemoryResult(
            incident=incident,
            similar_incidents=similar,
        )
