"""
The search_mitre tool's actual implementation: given a natural-language
query (the agent will typically pass an alert's rule name + description),
returns the top-k grounded technique matches from the real MITRE ATT&CK
corpus.

Defaults to TfidfRetriever since it's the backend this project can
actually verify end-to-end from this environment. Swap in ChromaRetriever
once you've verified it locally with real sentence-transformer embeddings
-- see rag/chroma_retriever.py.
"""

from __future__ import annotations

from soc_copilot.rag.mitre_loader import load_techniques
from soc_copilot.rag.retriever import Retriever
from soc_copilot.rag.tfidf_retriever import TfidfRetriever


def default_retriever() -> Retriever:
    return TfidfRetriever(load_techniques())


def search_mitre(query: str, retriever: Retriever, k: int = 5) -> list[dict]:
    return [r.model_dump() for r in retriever.search(query, k=k)]
