import tempfile
from pathlib import Path

from chromadb import EmbeddingFunction
from chromadb.utils.embedding_functions import register_embedding_function

from soc_copilot.rag.chroma_retriever import ChromaRetriever
from soc_copilot.rag.mitre_loader import MitreTechnique

SAMPLE_TECHNIQUES = [
    MitreTechnique(
        technique_id="T1059.001",
        name="PowerShell",
        tactics=["execution"],
        description="Adversaries may abuse PowerShell for execution.",
        is_subtechnique=True,
        url="https://attack.mitre.org/techniques/T1059/001",
    ),
    MitreTechnique(
        technique_id="T1021.002",
        name="SMB/Windows Admin Shares",
        tactics=["lateral-movement"],
        description="Adversaries may use SMB to move laterally between hosts.",
        is_subtechnique=True,
        url="https://attack.mitre.org/techniques/T1021/002",
    ),
]


@register_embedding_function
class DeterministicFakeEmbeddingFunction(EmbeddingFunction):
    """A tiny, fully local, non-network embedding stand-in: represents each
    text as [char_count, space_count]. Not semantically meaningful -- it
    exists purely so ChromaRetriever's indexing/querying/result-mapping
    logic can be verified without downloading a real model, which this
    sandbox has no network path to (see chroma_retriever.py's docstring).
    Real semantic retrieval quality needs a real model, verified on your
    machine, not this fake.

    name() must be a classmethod and the class must go through
    @register_embedding_function -- chromadb's own registration internals
    call cls.name() without an instance to build its embedding-function
    registry; an unregistered plain method previously caused a benign but
    noisy DeprecationWarning on every test run using this fake."""

    def __init__(self):
        pass

    def __call__(self, input):
        return [[float(len(text)), float(text.count(" "))] for text in input]

    @classmethod
    def name(cls):
        return "deterministic-fake"

    def get_config(self):
        return {}

    @staticmethod
    def build_from_config(config):
        return DeterministicFakeEmbeddingFunction()


def _retriever(tmp_path: Path) -> ChromaRetriever:
    return ChromaRetriever(persist_path=tmp_path / "chroma", embedding_function=DeterministicFakeEmbeddingFunction())


def test_index_then_search_returns_results_with_correct_shape(tmp_path):
    retriever = _retriever(tmp_path)
    retriever.index(SAMPLE_TECHNIQUES)

    results = retriever.search("some query", k=2)
    assert len(results) == 2
    ids = {r.technique_id for r in results}
    assert ids == {"T1059.001", "T1021.002"}


def test_search_maps_metadata_correctly(tmp_path):
    retriever = _retriever(tmp_path)
    retriever.index(SAMPLE_TECHNIQUES)

    results = retriever.search("query", k=2)
    by_id = {r.technique_id: r for r in results}
    assert by_id["T1059.001"].name == "PowerShell"
    assert by_id["T1059.001"].tactics == ["execution"]
    assert by_id["T1021.002"].name == "SMB/Windows Admin Shares"
    assert by_id["T1021.002"].tactics == ["lateral-movement"]


def test_scores_are_ordered_consistently_with_chroma_distance_ranking(tmp_path):
    """Chroma returns distance (lower = more similar) and already ranks
    results by ascending distance. ChromaRetriever inverts distance to a
    score so RetrievedTechnique.score keeps the same 'higher = more
    relevant' contract as TfidfRetriever -- verify that inversion actually
    preserves Chroma's own ranking rather than scrambling it."""
    retriever = _retriever(tmp_path)
    retriever.index(SAMPLE_TECHNIQUES)

    results = retriever.search("some query text", k=2)
    scores = [r.score for r in results]
    assert scores == sorted(scores, reverse=True)  # results already come back best-first; scores must agree


def test_index_is_idempotent_upsert(tmp_path):
    """Re-indexing (e.g. after a MITRE corpus update) must not create
    duplicate entries or fail -- upsert semantics, not insert."""
    retriever = _retriever(tmp_path)
    retriever.index(SAMPLE_TECHNIQUES)
    retriever.index(SAMPLE_TECHNIQUES)  # re-index the same data

    results = retriever.search("query", k=10)
    ids = [r.technique_id for r in results]
    assert len(ids) == len(set(ids))  # no duplicates


def test_index_with_empty_list_does_not_error(tmp_path):
    retriever = _retriever(tmp_path)
    retriever.index([])  # must not raise
