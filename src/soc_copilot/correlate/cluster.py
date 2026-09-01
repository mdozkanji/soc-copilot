"""
Entity-based correlation.

The approach: two alerts get linked if they share a "join-worthy" entity
(host, user, IP, or file hash) AND occurred within `max_gap` of each other.
Cases are the connected components of the resulting graph.

This last part matters and is worth being explicit about: linking is
pairwise-within-window, but because case membership is a *connected
component*, a case can still span much longer than `max_gap` overall, as
long as each step in the chain is within the window of its neighbor. That's
what makes this a genuine "rolling window" rather than a fixed time bucket
-- it's exactly what lets an 8-alert, 17-minute intrusion chain (this
project's case-001 sample) cluster correctly without having to guess a
single window wide enough to cover a whole kill chain up front.

Two engineering decisions worth understanding, not just accepting:

1. Not every shared entity is evidence of a relationship. A small,
   explicit, documented denylist (NOISY_ENTITY_VALUES) excludes a handful
   of extremely common public DNS resolvers from acting as a join key --
   two unrelated alerts both mentioning 8.8.8.8 as a destination tells you
   nothing about whether they're related, and left in, it would silently
   merge otherwise-unconnected cases. This is a real, common failure mode
   in SIEM correlation rules, not a hypothetical: this project's own
   sample data has an internal-gateway IP (10.0.0.1) shared by two
   genuinely unrelated benign alerts, and it's only the time window --
   not any denylist -- that keeps them apart. If those two alerts had
   happened closer together, a fixed denylist for internal "hub"
   infrastructure would eventually be needed too; that's flagged as a
   Week 4+ concern once real asset-inventory context exists.

2. The time window is a judgment call, and this dataset actually contains
   a genuine boundary case that proves it: case-002 (an external recon
   scan) and case-003 (a malicious Office-macro incident on a different
   host) both involve the same external IP (45.146.164.12), roughly 2h45m
   apart. At the default 2-hour window, they correctly stay separate --
   but whether the same attacker infrastructure touching two different
   targets ~3 hours apart *should* be treated as one campaign or two
   incidents is a legitimate SOC judgment call, not a clear right answer.
   This is exactly the kind of threshold that should be revisited with
   real analyst feedback (Week 7), not tuned once and forgotten.
"""

from __future__ import annotations

from datetime import timedelta

import networkx as nx

from soc_copilot.correlate.models import Case
from soc_copilot.ingest.schema import Alert

DEFAULT_MAX_GAP = timedelta(hours=2)

# Well-known public DNS resolvers: extremely common as a destination IP,
# essentially never meaningful evidence that two alerts are related.
# Deliberately small and explicit rather than trying to auto-detect "noisy"
# entities by degree -- see the module docstring for why a degree-based
# approach would be wrong here (it would also strip out genuinely
# high-degree *legitimate* entities, like case-001's own host).
NOISY_ENTITY_VALUES: frozenset[str] = frozenset(
    {"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112"}
)


def _alert_entities(alert: Alert) -> set[tuple[str, str]]:
    """The set of (entity_type, value) pairs this alert can be joined on."""
    entities: set[tuple[str, str]] = set()
    if alert.host:
        entities.add(("host", alert.host))
    if alert.user:
        entities.add(("user", alert.user))
    for ip in filter(None, (alert.src_ip, alert.dst_ip)):
        if ip not in NOISY_ENTITY_VALUES:
            entities.add(("ip", ip))
    if alert.file_hash_sha256:
        entities.add(("file_hash", alert.file_hash_sha256))
    return entities


def correlate(alerts: list[Alert], max_gap: timedelta = DEFAULT_MAX_GAP) -> list[Case]:
    """Group alerts into Cases by shared entity + time-windowed connectivity.

    Every input alert appears in exactly one output Case, including
    singleton cases for alerts that share nothing with anything else.
    """
    graph = nx.Graph()
    for alert in alerts:
        graph.add_node(alert.alert_id, alert=alert)

    # Index alerts by entity first, rather than comparing every alert to
    # every other alert -- this mirrors how a real correlation engine would
    # do entity-indexed lookups instead of an O(n^2) full scan, and it's
    # also just a clearer way to express "alerts that could possibly be
    # linked" before applying the time-window check.
    entity_index: dict[tuple[str, str], list[Alert]] = {}
    for alert in alerts:
        for entity in _alert_entities(alert):
            entity_index.setdefault(entity, []).append(alert)

    for entity, group in entity_index.items():
        if len(group) < 2:
            continue
        entity_type, entity_value = entity
        for i in range(len(group)):
            for j in range(i + 1, len(group)):
                a, b = group[i], group[j]
                if abs(a.occurred_at - b.occurred_at) <= max_gap:
                    reason = f"shared {entity_type} '{entity_value}'"
                    if graph.has_edge(a.alert_id, b.alert_id):
                        graph[a.alert_id][b.alert_id]["reasons"].add(reason)
                    else:
                        graph.add_edge(a.alert_id, b.alert_id, reasons={reason})

    cases: list[Case] = []
    for i, component in enumerate(nx.connected_components(graph), start=1):
        component_alerts = [graph.nodes[alert_id]["alert"] for alert_id in component]
        component_alerts.sort(key=lambda a: a.occurred_at)

        link_reasons: set[str] = set()
        for u, v, data in graph.subgraph(component).edges(data=True):
            link_reasons |= data["reasons"]

        cases.append(
            Case(
                case_id=f"correlated-case-{i:03d}",
                alert_ids=[a.alert_id for a in component_alerts],
                source_alert_ids=[a.source_alert_id for a in component_alerts],
                first_seen=component_alerts[0].occurred_at,
                last_seen=component_alerts[-1].occurred_at,
                hosts=sorted({a.host for a in component_alerts if a.host}),
                users=sorted({a.user for a in component_alerts if a.user}),
                ips=sorted({ip for a in component_alerts for ip in (a.src_ip, a.dst_ip) if ip}),
                file_hashes=sorted({a.file_hash_sha256 for a in component_alerts if a.file_hash_sha256}),
                link_reasons=sorted(link_reasons),
            )
        )

    # Largest/earliest cases first -- purely for readability when a human
    # is scanning CLI output; carries no meaning downstream.
    cases.sort(key=lambda c: (-c.alert_count, c.first_seen))
    return cases
