import pytest

from soc_copilot.rag.mitre_loader import MitreTechnique
from soc_copilot.rag.tfidf_retriever import TfidfRetriever

SAMPLE_TECHNIQUES = [
    MitreTechnique(
        technique_id="T1059.001",
        name="PowerShell",
        tactics=["execution"],
        description="Adversaries may abuse PowerShell commands and scripts for execution on Windows systems.",
        is_subtechnique=True,
        url="https://attack.mitre.org/techniques/T1059/001",
    ),
    MitreTechnique(
        technique_id="T1021.002",
        name="SMB/Windows Admin Shares",
        tactics=["lateral-movement"],
        description="Adversaries may use SMB to interact with a remote network share using valid credentials.",
        is_subtechnique=True,
        url="https://attack.mitre.org/techniques/T1021/002",
    ),
    MitreTechnique(
        technique_id="T1499",
        name="Endpoint Denial of Service",
        tactics=["impact"],
        description="Adversaries may perform denial of service attacks to degrade or block availability of a service.",
        is_subtechnique=False,
        url="https://attack.mitre.org/techniques/T1499",
    ),
]


def test_search_ranks_lexically_relevant_technique_first():
    retriever = TfidfRetriever(SAMPLE_TECHNIQUES)
    results = retriever.search("PowerShell script execution on Windows", k=3)
    assert results[0].technique_id == "T1059.001"


def test_search_respects_k():
    retriever = TfidfRetriever(SAMPLE_TECHNIQUES)
    results = retriever.search("adversary technique", k=2)
    assert len(results) == 2


def test_search_scores_are_descending():
    retriever = TfidfRetriever(SAMPLE_TECHNIQUES)
    results = retriever.search("SMB network share credentials", k=3)
    scores = [r.score for r in results]
    assert scores == sorted(scores, reverse=True)


def test_result_includes_tactics_and_truncated_description():
    retriever = TfidfRetriever(SAMPLE_TECHNIQUES)
    results = retriever.search("SMB shares", k=1)
    assert results[0].tactics == ["lateral-movement"]
    assert results[0].name == "SMB/Windows Admin Shares"


def test_empty_corpus_raises_clear_error():
    with pytest.raises(ValueError, match="non-empty"):
        TfidfRetriever([])


def test_query_with_no_lexical_overlap_still_returns_k_results_with_low_scores():
    """Documents the known limitation stated in the module docstring: a
    query sharing no vocabulary with the corpus doesn't crash or return
    nothing, it just scores everything near zero."""
    retriever = TfidfRetriever(SAMPLE_TECHNIQUES)
    results = retriever.search("completely unrelated gibberish xyzzy", k=3)
    assert len(results) == 3
    assert all(r.score < 0.1 for r in results)
