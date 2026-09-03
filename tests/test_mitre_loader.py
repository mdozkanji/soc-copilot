import json
from pathlib import Path

from soc_copilot.rag.mitre_loader import DEFAULT_OUTPUT_PATH, _clean_description, load_techniques, parse_techniques

# A small, hand-built STIX-shaped fixture -- not the real 48MB MITRE bundle.
# Covers exactly the filtering/cleaning cases that matter: a normal
# technique, a revoked one, a deprecated one, a sub-technique, and an
# attack-pattern missing the mitre-attack external reference (shouldn't
# happen in real data, but the parser must not crash on it).
FIXTURE_BUNDLE = {
    "type": "bundle",
    "objects": [
        {
            "type": "attack-pattern",
            "name": "PowerShell",
            "revoked": False,
            "x_mitre_deprecated": False,
            "x_mitre_is_subtechnique": True,
            "description": "Adversaries may abuse PowerShell.(Citation: TechNet PowerShell) See <code>Start-Process</code>.",
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T1059.001", "url": "https://attack.mitre.org/techniques/T1059/001"}
            ],
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}],
        },
        {
            "type": "attack-pattern",
            "name": "A Revoked Technique",
            "revoked": True,
            "external_references": [{"source_name": "mitre-attack", "external_id": "T9999", "url": "x"}],
            "kill_chain_phases": [],
            "description": "Should be excluded.",
        },
        {
            "type": "attack-pattern",
            "name": "A Deprecated Technique",
            "revoked": False,
            "x_mitre_deprecated": True,
            "external_references": [{"source_name": "mitre-attack", "external_id": "T9998", "url": "x"}],
            "kill_chain_phases": [],
            "description": "Should be excluded.",
        },
        {
            "type": "attack-pattern",
            "name": "Missing MITRE Reference",
            "revoked": False,
            "external_references": [{"source_name": "some-other-source", "external_id": "X1", "url": "x"}],
            "kill_chain_phases": [],
            "description": "Should be skipped without crashing.",
        },
        {
            "type": "malware",  # not an attack-pattern -- must be ignored entirely
            "name": "Some Malware",
        },
    ],
}


def test_parse_techniques_extracts_valid_technique():
    techniques = parse_techniques(FIXTURE_BUNDLE)
    assert len(techniques) == 1  # only the one valid, non-revoked, non-deprecated technique
    t = techniques[0]
    assert t.technique_id == "T1059.001"
    assert t.name == "PowerShell"
    assert t.tactics == ["execution"]
    assert t.is_subtechnique is True


def test_parse_techniques_excludes_revoked_and_deprecated():
    techniques = parse_techniques(FIXTURE_BUNDLE)
    ids = {t.technique_id for t in techniques}
    assert "T9999" not in ids
    assert "T9998" not in ids


def test_parse_techniques_skips_objects_missing_mitre_reference_without_crashing():
    # already implicitly tested by the count above, but explicit for clarity
    techniques = parse_techniques(FIXTURE_BUNDLE)
    ids = {t.technique_id for t in techniques}
    assert "X1" not in ids


def test_clean_description_strips_citations_and_html():
    raw = "Adversaries may abuse PowerShell.(Citation: TechNet PowerShell) See <code>Start-Process</code> for details.[1]"
    cleaned = _clean_description(raw)
    assert "Citation" not in cleaned
    assert "<code>" not in cleaned
    assert "[1]" not in cleaned
    assert "Start-Process" in cleaned  # content inside the tag is kept, just the tag itself is stripped


def test_clean_description_collapses_whitespace_left_by_removal():
    raw = "Word1  (Citation: X)   Word2"
    cleaned = _clean_description(raw)
    assert "  " not in cleaned


# --------------------------------------------------------------------------
# the real, checked-in corpus
# --------------------------------------------------------------------------

def test_real_corpus_file_loads_and_has_reasonable_shape():
    if not DEFAULT_OUTPUT_PATH.exists():
        import pytest

        pytest.skip("data/mitre_attack_techniques.json not present in this checkout")

    techniques = load_techniques()
    assert len(techniques) > 500  # the real ATT&CK Enterprise matrix has several hundred techniques
    assert all(t.technique_id.startswith("T") for t in techniques)
    assert all(t.description for t in techniques)  # nothing should have an empty description after cleaning


def test_real_corpus_contains_every_ground_truth_technique_from_week1_labels():
    """The whole point of using the real MITRE dataset: every technique ID
    our own hand-authored ground truth (eval/labels.json) claims should
    actually exist in it. If this ever fails, either the corpus is stale
    or a label has a typo -- both worth knowing immediately."""
    if not DEFAULT_OUTPUT_PATH.exists():
        import pytest

        pytest.skip("data/mitre_attack_techniques.json not present in this checkout")

    repo_root = Path(__file__).resolve().parents[1]
    labels = json.loads((repo_root / "eval" / "labels.json").read_text())
    needed_ids = {v["true_mitre_technique"] for k, v in labels.items() if k != "_readme" and v.get("true_mitre_technique")}

    corpus_ids = {t.technique_id for t in load_techniques()}
    missing = needed_ids - corpus_ids
    assert not missing, f"Ground-truth technique IDs missing from the MITRE corpus: {missing}"
