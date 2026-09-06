import pytest
from fastapi.testclient import TestClient

from soc_copilot.agent.sample_cases import build_abstention_example, build_malicious_example
from soc_copilot.api.app import app, get_feedback_store, get_result_store
from soc_copilot.api.store import AgentResultStore, FeedbackStore


@pytest.fixture
def stores(tmp_path):
    result_store = AgentResultStore(results_dir=tmp_path / "results")
    feedback_store = FeedbackStore(path=tmp_path / "feedback.jsonl")
    app.dependency_overrides[get_result_store] = lambda: result_store
    app.dependency_overrides[get_feedback_store] = lambda: feedback_store
    yield result_store, feedback_store
    app.dependency_overrides.clear()


@pytest.fixture
def client(stores):
    return TestClient(app)


# --------------------------------------------------------------------------
# case queue
# --------------------------------------------------------------------------

def test_root_redirects_to_cases(client):
    response = client.get("/", follow_redirects=False)
    assert response.status_code in (302, 307)
    assert response.headers["location"] == "/cases"


def test_queue_lists_real_correlated_cases(client):
    response = client.get("/cases")
    assert response.status_code == 200
    # correlated-case-008 is the real 8-alert intrusion chain from Week 3
    assert "correlated-case-008" in response.text


def test_queue_shows_uninvestigated_cases_without_a_verdict(client):
    response = client.get("/cases")
    assert "not yet investigated" in response.text


def test_queue_shows_verdict_badge_for_investigated_case(client, stores):
    result_store, _ = stores
    case, result = build_malicious_example()
    result_store.save(case, result)

    response = client.get("/cases")
    assert case.case_id in response.text
    assert "critical" in response.text
    assert "88/100" in response.text


# --------------------------------------------------------------------------
# case detail
# --------------------------------------------------------------------------

def test_case_detail_for_unknown_case_returns_404(client):
    response = client.get("/cases/does-not-exist")
    assert response.status_code == 404


def test_case_detail_for_uninvestigated_real_case_shows_pending_state(client):
    response = client.get("/cases/correlated-case-008")
    assert response.status_code == 200
    assert "Not yet investigated" in response.text


def test_case_detail_for_investigated_case_shows_report_and_form(client, stores):
    result_store, _ = stores
    case, result = build_malicious_example()
    result_store.save(case, result)

    response = client.get(f"/cases/{case.case_id}")
    assert response.status_code == 200
    assert "VirusTotal" in response.text  # from the rendered report
    assert 'name="decision" value="accept"' in response.text
    assert 'name="decision" value="override"' in response.text


def test_case_detail_shows_audit_warnings_when_present(client, stores):
    """The abstention example is clean (no warnings) -- attach a
    deliberately ungrounded verdict to a real, seeded case to confirm the
    warning box actually renders when audit_verdict finds something."""
    from soc_copilot.agent.models import AgentResult, RecommendedAction, Verdict

    result_store, _ = stores
    case, _ = build_abstention_example()  # real correlated case
    ungrounded_verdict = Verdict(
        severity="critical",
        confidence=95,
        evidence_sufficient=True,
        recommended_action=RecommendedAction.RECOMMEND_ESCALATE_URGENT,
        reasoning="Trust me.",  # no tool calls back this up at all
    )
    result_store.save(case, AgentResult(case_id=case.case_id, verdict=ungrounded_verdict, trace=[], iterations=1))

    response = client.get(f"/cases/{case.case_id}")
    assert "Automated consistency check" in response.text


# --------------------------------------------------------------------------
# review submission
# --------------------------------------------------------------------------

def test_accept_review_is_logged_and_redirects(client, stores):
    result_store, feedback_store = stores
    case, result = build_malicious_example()
    result_store.save(case, result)

    response = client.post(f"/cases/{case.case_id}/review", data={"decision": "accept"}, follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == f"/cases/{case.case_id}"

    entries = feedback_store.read_all()
    assert len(entries) == 1
    assert entries[0]["decision"] == "accept"
    assert entries[0]["case_id"] == case.case_id
    assert entries[0]["verdict_snapshot"]["confidence"] == 88  # snapshotted at review time


def test_override_review_logs_reason_and_corrections(client, stores):
    result_store, feedback_store = stores
    case, result = build_abstention_example()
    result_store.save(case, result)

    response = client.post(
        f"/cases/{case.case_id}/review",
        data={
            "decision": "override",
            "reason": "Confirmed with the user this was an approved internal tool.",
            "corrected_severity": "informational",
            "corrected_action": "recommend_close_benign",
        },
        follow_redirects=False,
    )
    assert response.status_code == 303

    entry = feedback_store.read_all()[0]
    assert entry["decision"] == "override"
    assert entry["reason"] == "Confirmed with the user this was an approved internal tool."
    assert entry["corrected_severity"] == "informational"
    assert entry["corrected_action"] == "recommend_close_benign"


def test_review_history_appears_on_case_detail_page(client, stores):
    result_store, feedback_store = stores
    case, result = build_malicious_example()
    result_store.save(case, result)
    client.post(f"/cases/{case.case_id}/review", data={"decision": "accept", "reason": "Looks right."})

    response = client.get(f"/cases/{case.case_id}")
    assert "Looks right." in response.text


# --------------------------------------------------------------------------
# feedback log page
# --------------------------------------------------------------------------

def test_feedback_page_shows_empty_state_with_no_reviews(client):
    response = client.get("/feedback")
    assert "No reviews logged yet" in response.text


def test_feedback_page_lists_reviews_most_recent_first(client, stores):
    result_store, feedback_store = stores
    case, result = build_malicious_example()
    result_store.save(case, result)

    feedback_store.append(case_id=case.case_id, decision="accept", verdict_snapshot={})
    feedback_store.append(case_id=case.case_id, decision="override", verdict_snapshot={}, reason="second look")

    response = client.get("/feedback")
    # NOTE: a naive substring search for "accept" also matches base.html's
    # shared CSS ("button.accept { ... }"), which appears in every page's
    # <head> before any table content -- search for the actual table cell
    # instead of the bare word.
    assert response.text.index("second look") < response.text.index("<td>accept</td>")
