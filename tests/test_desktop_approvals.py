"""Exercise desktop decisions against disposable approval state, without a GUI."""

import json
import sqlite3
from datetime import UTC, datetime, timedelta

import pytest

from veilgate.desktop_approvals import ApprovalStore


@pytest.fixture
def store(tmp_path):
    path = tmp_path / "approvals.db"
    with sqlite3.connect(path) as conn:
        conn.execute("CREATE TABLE approvals (approval_id TEXT PRIMARY KEY, session_id TEXT, "
                     "qualified_ref TEXT, summary_json TEXT, requested_at TEXT, status TEXT, "
                     "decided_at TEXT, decided_by TEXT, learned_grant TEXT)")
        now = datetime.now(UTC)
        conn.execute("INSERT INTO approvals VALUES (?,?,?,?,?,'PENDING',NULL,NULL,NULL)",
                     ("test", "session", "duckdb.query", json.dumps({"args": {"sql": "SELECT 1"},
                      "expires_at": (now + timedelta(seconds=120)).isoformat()}), now.isoformat()))
    return ApprovalStore(path)


@pytest.mark.parametrize("choice", ["APPROVED", "APPROVED_AND_SAVED", "DENIED"])
def test_decisions_are_single_use(store, choice):
    row = store.pending()[0]
    assert store.decide(row, choice)
    assert not store.decide(row, "APPROVED")
    with store.connect() as conn:
        result = conn.execute("SELECT * FROM approvals").fetchone()
    assert result["status"] == choice
    assert result["learned_grant"] == ("duckdb.query" if choice == "APPROVED_AND_SAVED" else None)


def test_expired_requests_cannot_be_approved(store):
    row = store.pending()[0]
    summary = json.loads(row["summary_json"])
    summary["expires_at"] = (datetime.now(UTC) - timedelta(seconds=1)).isoformat()
    row["summary_json"] = json.dumps(summary)
    with store.connect() as conn:
        conn.execute("UPDATE approvals SET summary_json=?", (row["summary_json"],))
    assert not store.pending()
    assert not store.decide(row, "APPROVED")


def test_changed_arguments_and_cancelled_requests_are_rejected(store):
    row = store.pending()[0]
    with store.connect() as conn:
        conn.execute("UPDATE approvals SET summary_json='{}'")
    assert not store.decide(row, "APPROVED")
    with store.connect() as conn:
        conn.execute("UPDATE approvals SET summary_json=?, status='EXPIRED'", (row["summary_json"],))
    assert not store.decide(row, "APPROVED")


def test_wrong_database_is_not_created(tmp_path):
    path = tmp_path / "missing.db"
    with pytest.raises(sqlite3.OperationalError):
        ApprovalStore(path).pending()
    assert not path.exists()


def test_legacy_deadline_and_invalid_choice(store):
    row = store.pending()[0]
    row["summary_json"] = "{}"
    assert store.deadline(row) == datetime.fromisoformat(row["requested_at"]) + timedelta(seconds=120)
    with pytest.raises(ValueError):
        store.decide(row, "anything")
