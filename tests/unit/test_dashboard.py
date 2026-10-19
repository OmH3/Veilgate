"""Unit tests for FastAPI dashboard REST endpoints."""

from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from veilgate.dashboard.app import create_dashboard_app
from veilgate.repositories.approval_repo import ApprovalRepository
from veilgate.repositories.audit_repo import AuditRepository
from veilgate.repositories.db import DatabaseManager
from veilgate.repositories.session_repo import SessionRepository


@pytest.fixture
def dashboard_client(tmp_path: Path) -> tuple[TestClient, DatabaseManager]:
    """Fixture providing initialized FastAPI test client and database manager."""
    db_file = tmp_path / "dashboard_test.db"
    mgr = DatabaseManager(db_file)

    import anyio
    anyio.run(mgr.initialize)

    app = create_dashboard_app(mgr)
    client = TestClient(app)
    return client, mgr


def test_dashboard_events_and_sessions(dashboard_client: tuple[TestClient, DatabaseManager]) -> None:
    """Verify events, sessions, and metrics endpoints."""
    client, mgr = dashboard_client

    import anyio

    async def _seed() -> None:
        s_repo = SessionRepository(mgr)
        await s_repo.create_or_touch("ses_dash_1", transport="stdio")

        a_repo = AuditRepository(mgr)
        await a_repo.record("evt_dash_1", "ses_dash_1", "cor_1", "LIST", "{}", "srv.tool")
        await a_repo.record("evt_dash_2", "ses_dash_1", "cor_1", "BLOCK", "{}", "srv.tool", reason="TOOL_NOT_ALLOWED")

    anyio.run(_seed)

    # Test /api/v1/events
    res_events = client.get("/api/v1/events?limit=10")
    assert res_events.status_code == 200
    events_data = res_events.json()
    assert len(events_data["items"]) == 2

    # Test /api/v1/sessions
    res_sessions = client.get("/api/v1/sessions")
    assert res_sessions.status_code == 200
    sessions_data = res_sessions.json()
    assert len(sessions_data["items"]) == 1

    # Test /api/v1/metrics/summary
    res_metrics = client.get("/api/v1/metrics/summary")
    assert res_metrics.status_code == 200
    metrics_data = res_metrics.json()
    assert metrics_data["total_events"] == 2
    assert metrics_data["active_sessions_count"] == 1
    assert "TOOL_NOT_ALLOWED" in metrics_data["blocks_by_reason"]


def test_dashboard_approvals_flow(dashboard_client: tuple[TestClient, DatabaseManager]) -> None:
    """Verify approvals listing and decision recording."""
    client, mgr = dashboard_client

    import anyio

    async def _seed_approval() -> None:
        repo = ApprovalRepository(mgr)
        await repo.create_request("appr_test_1", "ses_1", "mailer.send", "{}", "HIGH_RISK")

    anyio.run(_seed_approval)

    # List pending
    res_list = client.get("/api/v1/approvals")
    assert res_list.status_code == 200
    assert len(res_list.json()["items"]) == 1

    # Post decision
    res_decide = client.post(
        "/api/v1/approvals/appr_test_1/decision",
        json={"decision": "APPROVED", "decided_by": "alice"},
    )
    assert res_decide.status_code == 200
    assert res_decide.json()["status"] == "APPROVED"

    # Pending should now be 0
    res_list_after = client.get("/api/v1/approvals")
    assert len(res_list_after.json()["items"]) == 0
