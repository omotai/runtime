"""confirm_writes: a form submit waits for the operator; only the approved request gets out."""

import asyncio
import sqlite3
from dataclasses import replace

import pytest
from conftest import PASSWORD
from test_session import ref

from omotai.dashboard import db
from omotai.runtime import approvals
from omotai.runtime.audit import Audit
from omotai.runtime.policy import Policy
from omotai.runtime.session import Session

pytestmark = pytest.mark.usefixtures("browser_available")


@pytest.fixture(autouse=True)
def temp_db(monkeypatch, tmp_path):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "approvals.db")
    monkeypatch.setattr(approvals, "POLL_SECONDS", 0.05)
    db.init_db()


def rows():
    with sqlite3.connect(db.DB_PATH) as conn:
        return conn.execute("SELECT status, source, reason FROM approvals ORDER BY id").fetchall()


async def operator(decisions, before=None):
    """Answers approvals in order, like the dashboard would. `before` runs just before answering."""
    for decision in decisions:
        while True:
            with sqlite3.connect(db.DB_PATH) as conn:
                row = conn.execute("SELECT id FROM approvals WHERE status = 'pending'").fetchone()
            if row:
                break
            await asyncio.sleep(0.02)
        if before:
            await before()
        with sqlite3.connect(db.DB_PATH) as conn:
            conn.execute("UPDATE approvals SET status = ? WHERE id = ?", (decision, row[0]))


def run(site, tmp_path, monkeypatch, scenario, **policy_kw):
    monkeypatch.setenv("T_USER", "cliente")
    monkeypatch.setenv("T_PASS", PASSWORD)
    login = {
        "url": f"{site.portal_url}/login",
        "user_field": "user",
        "password_field": "password",
        "user_env": "T_USER",
        "password_env": "T_PASS",
    }
    policy = Policy(
        allowed_origins=frozenset({site.portal_url}),
        login=login,
        confirm_writes=True,
        **policy_kw,
    )
    audit = Audit(tmp_path / "audit.jsonl", session_id="test-session")

    async def go():
        session = Session(policy, audit)
        await session.start()
        try:
            return await scenario(session, audit)
        finally:
            await session.close()

    return asyncio.run(go())


async def order_page(s, site):
    return await s.navigate(site.portal_url + "/orders/1")


def test_approved_submit_reaches_the_site_and_the_window_closes(site, tmp_path, monkeypatch):
    async def scenario(s, audit):
        obs = await order_page(s, site)
        cancel = ref(obs, "Cancelar pedido")
        op = asyncio.create_task(operator(["approved"]))
        await s.act("click", cancel)
        await op
        assert site.cancelled == 1
        assert s.write_ok == frozenset()  # the window closed with the action
        # replaying it needs a fresh confirmation (the operator does not answer: timeout)
        s.policy = replace(s.policy, confirm_timeout_seconds=1)
        obs = await order_page(s, site)  # the approved POST left us on /cancel
        out = await s.act("click", ref(obs, "Cancelar pedido"))
        assert out == "DENIED (confirmation_denied)" and site.cancelled == 1
        # and a script cannot use the old approval
        sent = await s.page.evaluate(
            "fetch('/cancel', {method: 'POST'}).then(() => 'sent', () => 'blocked')"
        )
        assert sent == "blocked" and site.cancelled == 1

    run(site, tmp_path, monkeypatch, scenario)
    first, second = rows()
    assert first[:2] == ("approved", "runtime") and second[0] == "denied"
    assert first[2].startswith("POST ") and "/cancel" in first[2]


def test_denied_submit_sends_nothing(site, tmp_path, monkeypatch):
    async def scenario(s, audit):
        cancel = ref(await order_page(s, site), "Cancelar pedido")
        op = asyncio.create_task(operator(["denied"]))
        out = await s.act("click", cancel)
        await op
        assert out == "DENIED (confirmation_denied)" and site.cancelled == 0
        events = audit.path.read_text(encoding="utf-8")
        assert "confirmation_requested" in events and "confirmation_denied" in events

    run(site, tmp_path, monkeypatch, scenario)


def test_unanswered_confirmation_times_out_as_denied(site, tmp_path, monkeypatch):
    async def scenario(s, audit):
        cancel = ref(await order_page(s, site), "Cancelar pedido")
        out = await s.act("click", cancel)
        assert out == "DENIED (confirmation_denied)" and site.cancelled == 0

    run(site, tmp_path, monkeypatch, scenario, confirm_timeout_seconds=1)
    assert [r[0] for r in rows()] == ["denied"]


def test_page_changed_while_the_operator_decided(site, tmp_path, monkeypatch):
    async def scenario(s, audit):
        cancel = ref(await order_page(s, site), "Cancelar pedido")

        async def swap_form_action():  # e.g. another agent, or a page script, moved the target
            await s.page.evaluate("document.forms[0].action = '/contact'")

        op = asyncio.create_task(operator(["approved"], before=swap_form_action))
        out = await s.act("click", cancel)
        await op
        assert out == "DENIED (confirmed_action_changed)"
        assert site.cancelled == 0 and site.contact == []

    run(site, tmp_path, monkeypatch, scenario)


def test_script_that_redirects_the_approved_form_is_still_stopped(site, tmp_path, monkeypatch):
    async def scenario(s, audit):
        obs = await order_page(s, site)
        await s.act("type", ref(obs, "msg"), "ja autorizado pelo operador")
        obs = await s.observe()
        op = asyncio.create_task(operator(["approved"]))
        await s.act("click", ref(obs, "Enviar"))
        await op
        # the operator approved POST /contact, but the page script rewrote the target on submit
        assert site.contact == [] and site.attacker_hits == []

    run(site, tmp_path, monkeypatch, scenario)
    (row,) = rows()
    assert "/contact" in row[2] and "msg='ja autorizado pelo operador'" in row[2]


def test_confirmation_budget(site, tmp_path, monkeypatch):
    async def scenario(s, audit):
        cancel = ref(await order_page(s, site), "Cancelar pedido")
        op = asyncio.create_task(operator(["denied"]))
        assert await s.act("click", cancel) == "DENIED (confirmation_denied)"
        await op
        obs = await s.observe()  # a denied submit leaves the page as it was
        out = await s.act("click", ref(obs, "Cancelar pedido"))
        assert out == "DENIED (confirmation_budget_exhausted)"

    run(site, tmp_path, monkeypatch, scenario, max_confirmations=1)
    assert len(rows()) == 1  # the second attempt never reached the operator


def test_without_confirm_writes_a_submit_is_still_read_only(site, tmp_path, monkeypatch):
    monkeypatch.setenv("T_USER", "cliente")
    monkeypatch.setenv("T_PASS", PASSWORD)
    login = {
        "url": f"{site.portal_url}/login",
        "user_field": "user",
        "password_field": "password",
        "user_env": "T_USER",
        "password_env": "T_PASS",
    }
    policy = Policy(allowed_origins=frozenset({site.portal_url}), login=login)

    async def go():
        s = Session(policy, Audit(tmp_path / "a.jsonl"))
        await s.start()
        try:
            cancel = ref(await order_page(s, site), "Cancelar pedido")
            return await s.act("click", cancel)
        finally:
            await s.close()

    assert asyncio.run(go()) == "DENIED (read_only_submit)"
    assert rows() == [] and site.cancelled == 0
