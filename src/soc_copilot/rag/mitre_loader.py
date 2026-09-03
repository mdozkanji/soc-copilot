"""
Extracts a clean, RAG-ready technique corpus from MITRE's official ATT&CK
Enterprise STIX bundle.

Why real data, not hand-authored: unlike the Week 1 sample alerts (where
hand-authoring was the right call -- see docs/data-notes.md -- because the
point was testing our own normalization logic against deliberately messy
formats), MITRE ATT&CK is exactly the kind of reference knowledge where
using the real, official, versioned dataset matters. It's the actual
target the agent is grounding technique claims against; a fabricated
subset would undermine the whole point of RAG here.

Source: https://github.com/mitre/cti (STIX 2.1, public domain / Apache 2.0
licensed by MITRE). The bundle contains ~26,000 objects of many types
(techniques, software, groups, relationships, detections...) -- this
module extracts only `attack-pattern` objects (techniques and
sub-techniques), which is what "search_mitre" needs.

This is a one-time (or occasional, if MITRE publishes an update)
extraction step, not something run on every request: `python -m
soc_copilot.rag.mitre_loader` regenerates data/mitre_attack_techniques.json
from a fresh download. The cleaned file is what's actually checked into
the repo and what the retrievers load at runtime -- reproducible, and
readable by anyone browsing the repo without needing to fetch or parse the
full 48MB STIX bundle themselves.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import httpx
from pydantic import BaseModel

MITRE_ENTERPRISE_ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
)

REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_OUTPUT_PATH = REPO_ROOT / "data" / "mitre_attack_techniques.json"

_CITATION_PATTERN = re.compile(r"\(Citation:[^)]*\)")
_HTML_TAG_PATTERN = re.compile(r"</?[a-zA-Z][^>]*>")
_CITATION_MARKER_PATTERN = re.compile(r"\[\d+\]")


class MitreTechnique(BaseModel):
    technique_id: str  # e.g. "T1059.001"
    name: str
    tactics: list[str]  # e.g. ["execution"]
    description: str
    is_subtechnique: bool
    url: str


def _clean_description(raw: str) -> str:
    """STIX descriptions carry inline citation markers and light HTML
    (mainly <code> tags) meant for MITRE's own website rendering. Neither
    helps a retriever or an LLM reading this text -- strip both, and
    collapse the whitespace citation removal leaves behind."""
    text = _CITATION_PATTERN.sub("", raw)
    text = _CITATION_MARKER_PATTERN.sub("", text)
    text = _HTML_TAG_PATTERN.sub("", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def parse_techniques(bundle: dict[str, Any]) -> list[MitreTechnique]:
    techniques: list[MitreTechnique] = []
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        mitre_ref = next(
            (r for r in obj.get("external_references", []) if r.get("source_name") == "mitre-attack"), None
        )
        if mitre_ref is None or "external_id" not in mitre_ref:
            continue  # shouldn't happen for a real attack-pattern, but don't crash the whole extraction if it does

        tactics = sorted(
            {
                phase["phase_name"]
                for phase in obj.get("kill_chain_phases", [])
                if phase.get("kill_chain_name") == "mitre-attack"
            }
        )

        techniques.append(
            MitreTechnique(
                technique_id=mitre_ref["external_id"],
                name=obj.get("name", ""),
                tactics=tactics,
                description=_clean_description(obj.get("description", "")),
                is_subtechnique=bool(obj.get("x_mitre_is_subtechnique", False)),
                url=mitre_ref.get("url", ""),
            )
        )

    techniques.sort(key=lambda t: t.technique_id)
    return techniques


def fetch_and_extract(url: str = MITRE_ENTERPRISE_ATTACK_URL) -> list[MitreTechnique]:
    resp = httpx.get(url, timeout=60.0, follow_redirects=True)
    resp.raise_for_status()
    return parse_techniques(resp.json())


def main() -> None:
    techniques = fetch_and_extract()
    DEFAULT_OUTPUT_PATH.write_text(
        json.dumps([json.loads(t.model_dump_json()) for t in techniques], indent=2)
    )
    print(f"Extracted {len(techniques)} techniques -> {DEFAULT_OUTPUT_PATH}")


def load_techniques(path: Path = DEFAULT_OUTPUT_PATH) -> list[MitreTechnique]:
    """What retrievers actually call at runtime -- reads the checked-in
    cleaned corpus, never touches the network."""
    raw = json.loads(path.read_text())
    return [MitreTechnique.model_validate(t) for t in raw]


if __name__ == "__main__":
    main()
