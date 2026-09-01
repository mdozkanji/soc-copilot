"""
A Case is what correlation produces: a group of alerts believed to be part
of the same activity, plus enough summary information to make that grouping
inspectable rather than a black box.

Every alert ends up in exactly one Case -- including alerts that share
nothing with anything else, which become a Case of size 1. This is a
deliberate consistency choice: everything downstream of correlation
(enrichment orchestration in a future week, the agent, the UI) can always
assume "I'm looking at a case" rather than having two code paths for
"a case" vs. "a lone alert".
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, Field


class Case(BaseModel):
    case_id: str
    alert_ids: list[UUID]
    source_alert_ids: list[str] = Field(
        default_factory=list, description="The original per-source IDs, for cross-referencing against eval/labels.json."
    )

    first_seen: datetime
    last_seen: datetime

    # Union of each entity type across every alert in the case -- this is
    # what makes a case explainable at a glance ("this case touches host
    # WKS-EU-0231, user jsmith, and 2 external IPs") without having to open
    # every individual alert.
    hosts: list[str] = Field(default_factory=list)
    users: list[str] = Field(default_factory=list)
    ips: list[str] = Field(default_factory=list)
    file_hashes: list[str] = Field(default_factory=list)

    # Which specific shared entities caused alerts to be linked together --
    # kept distinct from the summary fields above because "these alerts
    # share host X" is a claim about *why* they're grouped, which matters
    # for an analyst (or an agent) auditing the correlation decision itself,
    # not just describing the resulting group.
    link_reasons: list[str] = Field(default_factory=list)

    @property
    def alert_count(self) -> int:
        return len(self.alert_ids)
