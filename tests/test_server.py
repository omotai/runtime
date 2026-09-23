"""End to end over MCP stdio: the same way an agent harness will talk to the runtime."""

import asyncio
import os
import sys

import pytest
import yaml
from conftest import PASSWORD

from omotai.runtime.audit import verify

from mcp import ClientSession, StdioServerParameters  # isort: skip
from mcp.client.stdio import stdio_client  # isort: skip

pytestmark = pytest.mark.usefixtures("browser_available")


def text(result):
    return "\n".join(c.text for c in result.content if c.type == "text")


def test_agent_sees_only_the_runtime_tools_and_cannot_leave_the_origin(site, tmp_path):
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        yaml.safe_dump(
            {
                "allowed_origins": [site.portal_url],
                "login": {
                    "url": f"{site.portal_url}/login",
                    "user_field": "user",
                    "password_field": "password",
                    "user_env": "T_USER",
                    "password_env": "T_PASS",
                },
            }
        ),
        encoding="utf-8",
    )
    audit = tmp_path / "audit.jsonl"
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "omotai.runtime", "start", "--policy", str(policy), "--audit", str(audit)],
        env={**os.environ, "T_USER": "cliente", "T_PASS": PASSWORD},
    )

    async def go():
        async with stdio_client(params) as (r, w), ClientSession(r, w) as s:
            await s.initialize()
            names = {t.name for t in (await s.list_tools()).tools}
            assert names == {"navigate", "observe", "back", "act", "finish", "ask_human"}
            page = text(await s.call_tool("navigate", {"url": site.portal_url + "/orders/1"}))
            assert "[UNTRUSTED PAGE CONTENT" in page and "Status: Enviado" in page
            assert PASSWORD not in page
            denied = text(await s.call_tool("navigate", {"url": site.attacker_url + "/x"}))
            assert denied.startswith("DENIED (origin_not_allowed)")
            await s.call_tool("finish", {"answer": "Enviado"})

    asyncio.run(go())
    assert site.attacker_hits == [] and site.logins == 1
    assert verify(audit) and PASSWORD not in audit.read_text(encoding="utf-8")


def test_ask_human(tmp_path):
    import sqlite3

    from omotai.dashboard.db import DB_PATH, init_db

    # Initialize DB so the tables exist
    init_db()

    policy = tmp_path / "policy.yaml"
    policy.write_text("allowed_origins: []", encoding="utf-8")
    audit = tmp_path / "audit.jsonl"
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "omotai.runtime", "start", "--policy", str(policy), "--audit", str(audit)],
        env=os.environ,
    )

    async def go():
        async with stdio_client(params) as (r, w), ClientSession(r, w) as s:
            await s.initialize()

            # Create a task to call ask_human
            task = asyncio.create_task(s.call_tool("ask_human", {"reason": "Are you human?"}))

            # Wait a bit for the tool to insert into DB
            await asyncio.sleep(1)

            # Manually approve in the DB
            with sqlite3.connect(DB_PATH) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "UPDATE approvals SET status = 'approved' WHERE reason = 'Are you human?'"
                )
                conn.commit()

            result = text(await task)
            assert result == "approved"

            # Test timeout fallback (assuming we don't want to wait 30s, we mock or skip)
            # Actually we can't easily mock wait_for in the child process.
            # We'll just test the DB interaction for now.

    asyncio.run(go())


def test_confirmation_works_over_a_plain_stdio_run(site, tmp_path):
    """A fresh database and no dashboard: the runtime must create its own tables, and a submit
    waits for the operator (here: a row updated in the database) before it leaves the browser."""
    import sqlite3
    import time

    db = tmp_path / "run.db"
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        yaml.safe_dump(
            {
                "allowed_origins": [site.portal_url],
                "read_only": True,
                "confirm_writes": True,
                "login": {
                    "url": f"{site.portal_url}/login",
                    "user_field": "user",
                    "password_field": "password",
                    "user_env": "T_USER",
                    "password_env": "T_PASS",
                },
            }
        ),
        encoding="utf-8",
    )
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "omotai.runtime", "start", "--policy", str(policy)]
        + ["--audit", str(tmp_path / "audit.jsonl")],
        env={**os.environ, "T_USER": "cliente", "T_PASS": PASSWORD, "OMOTAI_DB": str(db)},
    )

    async def operator():
        deadline = time.time() + 30
        while time.time() < deadline:
            with sqlite3.connect(db) as conn:
                row = conn.execute("SELECT id FROM approvals WHERE status = 'pending'").fetchone()
                if row:
                    conn.execute("UPDATE approvals SET status = 'approved' WHERE id = ?", row)
                    return
            await asyncio.sleep(0.1)

    async def go():
        async with stdio_client(params) as (r, w), ClientSession(r, w) as s:
            await s.initialize()
            page = text(await s.call_tool("navigate", {"url": site.portal_url + "/orders/1"}))
            cancel = next(
                line.split()[0] for line in page.splitlines() if '"Cancelar pedido"' in line
            )
            op = asyncio.create_task(operator())
            out = text(await s.call_tool("act", {"action": "click", "ref": cancel}))
            await op
            assert "DENIED" not in out and "ERROR" not in out

    asyncio.run(go())
    assert site.cancelled == 1
    with sqlite3.connect(db) as conn:
        assert conn.execute("SELECT status, source FROM approvals").fetchall() == [
            ("approved", "runtime")
        ]
