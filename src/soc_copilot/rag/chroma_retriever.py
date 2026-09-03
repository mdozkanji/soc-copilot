"""
Dense-embedding retriever using Chroma (a local, embedded vector DB) --
the "textbook" RAG approach, and the one worth understanding even though
this sandbox can't fully verify it end-to-end.

Why it can't be live-tested here: Chroma's default embedding function
downloads sentence-transformers/all-MiniLM-L6-v2 from huggingface.co on
first use, and this sandbox's network egress does not include
huggingface.co -- confirmed directly (a request there returns a
host_not_allowed deny reason), not assumed. That's a constraint of this
development environment, not of the code: on your machine, with normal
internet access, `pip install chromadb sentence-transformers` and this
class should work exactly as written. If you try it and something's off,
that's genuinely new information neither of us has yet -- please share
what you see, same as every other live-API step in this project.

Kept fully dependency-injectable regardless, so the *integration* logic
(indexing, querying, mapping results back to RetrievedTechnique) is
verified in this sandbox even though the *semantic quality* of real
embeddings isn't: pass any embedding_function implementing Chroma's
EmbeddingFunction interface (subclass chromadb.EmbeddingFunction). Tests
use a small deterministic fake instead of a real model -- same split as
every other live external dependency in this project (VirusTotal/
AbuseIPDB clients, the Groq client): mock what's testable, defer what
genuinely needs the real network/model to be verified live.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import chromadb
from chromadb import EmbeddingFunction
from chromadb.config import Settings

from soc_copilot.rag.mitre_loader import MitreTechnique
from soc_copilot.rag.retriever import RetrievedTechnique

REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_CHROMA_PATH = REPO_ROOT / "data" / "chroma_db"
COLLECTION_NAME = "mitre_attack_techniques"
_RESULT_DESCRIPTION_CHARS = 400


def _default_embedding_function() -> EmbeddingFunction:
    # Imported lazily so importing this module doesn't require
    # sentence-transformers (a real dependency, not installed by default
    # in this project) unless someone actually constructs a ChromaRetriever
    # without passing their own embedding_function.
    from chromadb.utils import embedding_functions

    return embedding_functions.SentenceTransformerEmbeddingFunction(model_name="all-MiniLM-L6-v2")


class ChromaRetriever:
    def __init__(
        self,
        persist_path: Path = DEFAULT_CHROMA_PATH,
        embedding_function: Optional[EmbeddingFunction] = None,
        client: Optional[chromadb.ClientAPI] = None,
    ):
        self._client = client or chromadb.PersistentClient(
            path=str(persist_path), settings=Settings(anonymized_telemetry=False)
        )
        ef = embedding_function or _default_embedding_function()
        self._collection = self._client.get_or_create_collection(name=COLLECTION_NAME, embedding_function=ef)

    def index(self, techniques: list[MitreTechnique]) -> None:
        """Upsert is idempotent by id, so re-running this to refresh the
        corpus after a MITRE ATT&CK update is always safe -- no need to
        drop and rebuild the collection."""
        if not techniques:
            return
        self._collection.upsert(
            ids=[t.technique_id for t in techniques],
            documents=[f"{t.name}. {t.description}" for t in techniques],
            metadatas=[{"name": t.name, "tactics": ",".join(t.tactics)} for t in techniques],
        )

    def search(self, query: str, k: int = 5) -> list[RetrievedTechnique]:
        result = self._collection.query(query_texts=[query], n_results=k)
        out: list[RetrievedTechnique] = []
        ids = result["ids"][0]
        for i in range(len(ids)):
            meta = result["metadatas"][0][i]
            distance = result["distances"][0][i]
            tactics_str = meta.get("tactics") or ""
            out.append(
                RetrievedTechnique(
                    technique_id=ids[i],
                    name=meta["name"],
                    tactics=tactics_str.split(",") if tactics_str else [],
                    description=result["documents"][0][i][:_RESULT_DESCRIPTION_CHARS],
                    # Chroma returns a distance (lower = more similar); invert
                    # to keep RetrievedTechnique.score's "higher = more
                    # relevant" contract consistent across every backend.
                    score=1.0 - distance,
                )
            )
        return out
