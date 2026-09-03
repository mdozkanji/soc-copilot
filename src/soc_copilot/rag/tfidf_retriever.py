"""
TF-IDF + cosine similarity retriever over the MITRE technique corpus.

Chosen as the default backend for a concrete, practical reason, not as a
compromise dressed up as a choice: this sandbox has no network path to
huggingface.co, where a real sentence-embedding model's weights would
download from, so a dense-embedding backend can't be verified from here at
all -- see chroma_retriever.py. TF-IDF needs nothing beyond scikit-learn,
works identically wherever it runs, and for a domain with fairly
canonical, specific terminology (MITRE's technique names and descriptions
are written consistently, not colloquially), lexical matching is a
reasonable, honest v1 -- not a toy stand-in for "real" RAG.

It has a real, known limitation worth stating plainly: it won't bridge a
genuine paraphrase that shares little vocabulary with the source text
(e.g. a query about "abusing the Windows task scheduler for persistence"
overlaps well with T1053.005's actual wording, but a more creatively
paraphrased query might not). That gap is exactly what dense embeddings
exist to close -- which is why chroma_retriever.py is a real upgrade path,
not a hypothetical one, once it can be verified against a real model.
"""

from __future__ import annotations

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from soc_copilot.rag.mitre_loader import MitreTechnique
from soc_copilot.rag.retriever import RetrievedTechnique

# Full description text is kept for indexing (more text = better lexical
# match) but truncated in returned results -- a tool result is context fed
# to an LLM, not documentation; the technique ID + name + a snippet is
# enough to ground a claim, and MITRE's own URL (dropped here to keep the
# tool payload small) is the place for the full text if truly needed.
_RESULT_DESCRIPTION_CHARS = 400


class TfidfRetriever:
    def __init__(self, techniques: list[MitreTechnique]):
        if not techniques:
            raise ValueError("TfidfRetriever requires a non-empty technique corpus")
        self._techniques = techniques
        corpus_texts = [f"{t.name}. {t.description}" for t in techniques]
        self._vectorizer = TfidfVectorizer(stop_words="english", max_features=20000)
        self._matrix = self._vectorizer.fit_transform(corpus_texts)

    def search(self, query: str, k: int = 5) -> list[RetrievedTechnique]:
        query_vec = self._vectorizer.transform([query])
        scores = cosine_similarity(query_vec, self._matrix)[0]
        top_idx = np.argsort(scores)[::-1][:k]
        return [
            RetrievedTechnique(
                technique_id=self._techniques[i].technique_id,
                name=self._techniques[i].name,
                tactics=self._techniques[i].tactics,
                description=self._techniques[i].description[:_RESULT_DESCRIPTION_CHARS],
                score=float(scores[i]),
            )
            for i in top_idx
        ]
