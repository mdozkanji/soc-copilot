"""
Retriever abstraction for search_mitre.

Same lesson as agent/llm_types.py, applied proactively this time instead
of learned the hard way: decouple the thing that needs grounding
(search_mitre's tool dispatch, and the retrieval-quality eval) from any one
specific retrieval technology.

TfidfRetriever (tfidf_retriever.py) is the default -- pure scikit-learn, no
model download, no network dependency, works identically in this sandbox
and on your machine. ChromaRetriever (chroma_retriever.py) is the
"textbook" dense-embedding approach and is code-complete and unit-tested
against a fake embedding function, but this sandbox has no network path to
huggingface.co (where a real embedding model's weights would download
from), so its actual retrieval quality with a real model is unverified
from here -- see that module's docstring for the honest details.
"""

from __future__ import annotations

from typing import Protocol

from pydantic import BaseModel


class RetrievedTechnique(BaseModel):
    technique_id: str
    name: str
    tactics: list[str]
    description: str
    score: float  # higher = more relevant, regardless of backend


class Retriever(Protocol):
    def search(self, query: str, k: int = 5) -> list[RetrievedTechnique]: ...
