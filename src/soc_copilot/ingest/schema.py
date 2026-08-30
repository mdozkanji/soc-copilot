"""
Normalized internal alert schema.

Design notes (see docs/data-notes.md for the full rationale):

- This is intentionally a *lossy, opinionated* subset of a real alert record —
  loosely inspired by OCSF (Open Cybersecurity Schema Framework) entity
  naming, but far smaller. The goal is a stable internal contract that every
  later stage (correlation, enrichment, the agent) can rely on, regardless of
  which upstream SIEM/EDR format the alert originally came from.
- `raw` always keeps the original, untouched source record. Nothing here is
  ever thrown away — normalization projects fields out, it doesn't delete
  the source of truth. This matters for auditability and for debugging when
  a normalizer mapping is wrong.
- Ground truth (benign/malicious, true MITRE technique) is deliberately
  NOT part of this schema. Real-world alerts never come with a ground-truth
  label attached — if we baked labels into the operational schema, we'd be
  quietly leaking the answer into a system that's supposed to have to work
  it out. Labels live separately in eval/labels.json, keyed by alert_id,
  and are only ever loaded by the evaluation harness, never by the agent.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, field_validator


class Severity(str, Enum):
    """Severity as reported by the *source* tool — not the agent's own
    assessment. The agent computes its own severity/confidence later and
    the two are allowed to disagree; that disagreement is itself useful
    signal (e.g. a source tool over-alerting on a known-noisy rule)."""

    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertSource(str, Enum):
    """Where the alert originated. Kept as an open-ish enum (add values as
    new normalizers are written) rather than a free string, so downstream
    code can reason about per-source quirks explicitly."""

    SIGMA_SYNTHETIC = "sigma_synthetic"   # hand-authored, Sigma-rule-styled seed alerts (Week 1)
    EDR_SYNTHETIC = "edr_synthetic"       # hand-authored EDR-style process/hash alerts (Week 1)
    MORDOR_SIGMA = "mordor_sigma"         # reserved: Sigma rules run against OTRF Mordor logs (stretch)


class Alert(BaseModel):
    """A single normalized alert, the unit everything downstream operates on."""

    alert_id: UUID = Field(default_factory=uuid4)
    ingested_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    source: AlertSource
    source_alert_id: str = Field(
        ..., description="The alert/event ID as assigned by the original source, for traceability."
    )
    rule_name: str = Field(..., description="Name of the detection rule/signature that fired.")
    occurred_at: datetime = Field(..., description="When the underlying event happened (not ingestion time).")
    severity: Severity
    description: str = Field(..., description="Human-readable summary as provided by the source tool.")

    # Entity fields — all optional because not every alert type populates
    # every entity (a DNS alert has no file hash, a file-drop alert may have
    # no destination port, etc). Downstream code must handle absence, not
    # assume presence.
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    user: Optional[str] = None
    host: Optional[str] = None
    process_name: Optional[str] = None
    command_line: Optional[str] = None
    file_hash_sha256: Optional[str] = None

    # Optional hint only — real detection tools sometimes tag a MITRE
    # technique on the rule itself, but it's frequently absent or wrong.
    # The agent must be able to work without it (that's what search_mitre
    # RAG in Week 5 is for) and should not treat this as ground truth.
    mitre_technique_hint: Optional[str] = Field(
        default=None, description="e.g. 'T1059.001' — vendor-provided hint, not verified ground truth."
    )

    raw: dict[str, Any] = Field(
        default_factory=dict, description="The untouched original source record, for traceability/debugging."
    )

    @field_validator("file_hash_sha256")
    @classmethod
    def _validate_sha256(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        v = v.lower().strip()
        if len(v) != 64 or any(c not in "0123456789abcdef" for c in v):
            raise ValueError(f"file_hash_sha256 must be a 64-char hex string, got: {v!r}")
        return v

    @field_validator("src_ip", "dst_ip")
    @classmethod
    def _validate_ip_shape(cls, v: Optional[str]) -> Optional[str]:
        # Deliberately light-touch: a full IP parser (ipaddress module) is
        # used at the enrichment stage in Week 2, where a malformed IP
        # actually blocks an API call. Here we just reject obvious garbage
        # so a bad normalizer mapping fails fast and loud in Week 1.
        if v is None:
            return v
        if v.count(".") != 3 and ":" not in v:
            raise ValueError(f"src_ip/dst_ip does not look like an IPv4 or IPv6 address: {v!r}")
        return v

    model_config = {
        "use_enum_values": False,
    }
