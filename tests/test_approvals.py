"""The approval channel fails closed: only an explicit 'approved' opens anything."""

import asyncio
import sqlite3

import pytest

from omotai.dashboard import db
from omotai.runtime import approvals


@pytest.fixture(autouse=True)
def temp_db(monkeypatch, tmp_path):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "a.db")
    monkeypatch.setattr(approvals, "POLL_SECONDS", 0.02)
    db.init_db()


def set_status(approval_id, status):
    with sqlite3.connect(db.DB_PATH) as conn:
        conn.execute("UPDATE approvals SET status = ? WHERE id = ?", (status, approval_id))


async def decide(status, timeout=2):
    approval_id = await approvals.create_approval("s", "why", "agent")
    asyncio.get_running_loop().call_later(0.05, set_status, approval_id, status)
    return await approvals.await_decision(approval_id, timeout)


def test_only_approved_is_approved():
    assert asyncio.run(decide("approved")) == "approved"
    assert asyncio.run(decide("denied")) == "denied"
    assert asyncio.run(decide("yes please, go ahead")) == "denied"  # anything else is a denial


def test_timeout_closes_the_row_as_denied():
    async def go():
        approval_id = await approvals.create_approval("s", "why", "runtime")
        return approval_id, await approvals.await_decision(approval_id, 0.1)

    approval_id, status = asyncio.run(go())
    assert status == "denied"
    with sqlite3.connect(db.DB_PATH) as conn:
        assert conn.execute(
            "SELECT status FROM approvals WHERE id = ?", (approval_id,)
        ).fetchone() == ("denied",)


def test_a_deleted_row_is_a_denial():
    async def go():
        approval_id = await approvals.create_approval("s", "why", "agent")
        with sqlite3.connect(db.DB_PATH) as conn:
            conn.execute("DELETE FROM approvals")
        return await approvals.await_decision(approval_id, 1)

    assert asyncio.run(go()) == "denied"
