"""Human approval channel: a row in `approvals` that the dashboard resolves. Fails closed.

Only "approved" or "denied" ever leaves this module, whatever the row says.
"""

import asyncio
from contextlib import closing

from omotai.dashboard import db

POLL_SECONDS = 1.0


def _insert(session_id: str, reason: str, source: str) -> int:
    with closing(db.get_connection()) as conn, conn:
        cur = conn.execute(
            "INSERT INTO approvals (session_id, reason, status, source)"
            " VALUES (?, ?, 'pending', ?)",
            (session_id, reason, source),
        )
        return cur.lastrowid


def _status(approval_id: int) -> str | None:
    with closing(db.get_connection()) as conn:
        row = conn.execute("SELECT status FROM approvals WHERE id = ?", (approval_id,)).fetchone()
    return row[0] if row else None


def _deny_if_pending(approval_id: int) -> None:
    with closing(db.get_connection()) as conn, conn:
        conn.execute(
            "UPDATE approvals SET status = 'denied' WHERE id = ? AND status = 'pending'",
            (approval_id,),
        )


async def create_approval(session_id: str, reason: str, source: str) -> int:
    return await asyncio.to_thread(_insert, session_id, reason, source)


async def await_decision(approval_id: int, timeout: float) -> str:
    async def poll() -> str | None:
        while True:
            status = await asyncio.to_thread(_status, approval_id)
            if status != "pending":
                return status
            await asyncio.sleep(POLL_SECONDS)

    try:
        status = await asyncio.wait_for(poll(), timeout)
    except TimeoutError:
        # Close the row, then read it back: a human answering at the last moment still counts.
        await asyncio.to_thread(_deny_if_pending, approval_id)
        status = await asyncio.to_thread(_status, approval_id)
    return "approved" if status == "approved" else "denied"
