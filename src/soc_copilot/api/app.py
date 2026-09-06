"""
Minimal analyst review UI.

Deliberately server-rendered Jinja2 templates + plain HTML forms instead
of a React/npm frontend: this project's actual differentiator is the
agent/correlation/enrichment pipeline, not frontend engineering, and a
FastAPI + Jinja2 app needs nothing beyond what's already a dependency of
the backend -- no separate JS build toolchain to install, pin, or explain
to someone cloning the repo. If a richer UI is ever worth the time, this
is a contained place to swap it in without touching the pipeline at all.

Cases come from actually running correlate() over the real Week 1 sample
data, every time -- not cached, since the underlying dataset is small and
static for now. Investigation results (verdict + trace) come from
AgentResultStore, which today only has the two Week 6 illustrative
examples seeded by api/seed.py, since live agent runs are blocked
(devlog/0009-*.md). A case with no stored result shows as "not yet
investigated" rather than the app pretending to have an answer.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, Form, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

from soc_copilot.agent.audit import audit_verdict
from soc_copilot.agent.models import RecommendedAction
from soc_copilot.agent.summary import render_summary
from soc_copilot.api.store import AgentResultStore, FeedbackStore
from soc_copilot.correlate.cluster import correlate
from soc_copilot.correlate.models import Case
from soc_copilot.ingest.schema import Alert, Severity

REPO_ROOT = Path(__file__).resolve().parents[3]
TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"

app = FastAPI(title="soc-copilot review UI")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


def get_result_store() -> AgentResultStore:
    return AgentResultStore()


def get_feedback_store() -> FeedbackStore:
    return FeedbackStore()


def _load_all_cases() -> list[Case]:
    alerts = [Alert.model_validate(a) for a in json.loads((REPO_ROOT / "data" / "normalized_alerts.json").read_text())]
    return correlate(alerts)


def _find_case(case_id: str) -> Optional[Case]:
    return next((c for c in _load_all_cases() if c.case_id == case_id), None)


@app.get("/")
def index():
    return RedirectResponse(url="/cases")


@app.get("/cases")
def list_cases(
    request: Request,
    result_store: AgentResultStore = Depends(get_result_store),
    feedback_store: FeedbackStore = Depends(get_feedback_store),
):
    cases = _load_all_cases()
    investigated_ids = result_store.all_case_ids()

    rows = []
    for case in cases:
        row = {"case": case, "investigated": case.case_id in investigated_ids, "verdict": None, "reviewed": None}
        if row["investigated"]:
            _, result = result_store.load(case.case_id)
            row["verdict"] = result.verdict
            latest = feedback_store.latest_decision_for(case.case_id)
            row["reviewed"] = latest["decision"] if latest else None
        rows.append(row)

    # Uninvestigated cases first (need attention), then by alert count --
    # purely a display convenience, not a claim about actual priority.
    rows.sort(key=lambda r: (r["investigated"], -r["case"].alert_count))

    return templates.TemplateResponse(request, "queue.html", {"rows": rows})


@app.get("/cases/{case_id}")
def case_detail(
    case_id: str,
    request: Request,
    result_store: AgentResultStore = Depends(get_result_store),
    feedback_store: FeedbackStore = Depends(get_feedback_store),
):
    case = _find_case(case_id)
    if case is None:
        return templates.TemplateResponse(request, "not_found.html", {"case_id": case_id}, status_code=404)

    loaded = result_store.load(case_id)
    report_html = None
    warnings: list[str] = []
    if loaded is not None:
        _, result = loaded
        report_html = render_summary(result, case)
        warnings = audit_verdict(result)

    history = [e for e in feedback_store.read_all() if e["case_id"] == case_id]

    return templates.TemplateResponse(
        request,
        "case_detail.html",
        {
            "case": case,
            "investigated": loaded is not None,
            "report_text": report_html,
            "warnings": warnings,
            "history": history,
            "severities": [s.value for s in Severity],
            "actions": [a.value for a in RecommendedAction],
        },
    )


@app.post("/cases/{case_id}/review")
def submit_review(
    case_id: str,
    decision: str = Form(...),
    reason: str = Form(""),
    corrected_severity: str = Form(""),
    corrected_action: str = Form(""),
    result_store: AgentResultStore = Depends(get_result_store),
    feedback_store: FeedbackStore = Depends(get_feedback_store),
):
    loaded = result_store.load(case_id)
    verdict_snapshot = json.loads(loaded[1].verdict.model_dump_json()) if loaded else {}

    feedback_store.append(
        case_id=case_id,
        decision=decision,
        verdict_snapshot=verdict_snapshot,
        reason=reason or None,
        corrected_severity=corrected_severity or None,
        corrected_action=corrected_action or None,
    )
    return RedirectResponse(url=f"/cases/{case_id}", status_code=303)


@app.get("/feedback")
def feedback_log(request: Request, feedback_store: FeedbackStore = Depends(get_feedback_store)):
    entries = list(reversed(feedback_store.read_all()))  # most recent first
    return templates.TemplateResponse(request, "feedback.html", {"entries": entries})
