"""Behavior against a real browser: what reaches the portal and the attacker origin."""

import asyncio
import re

import pytest
from conftest import PASSWORD

from omotai_runtime.audit import Audit, verify
from omotai_runtime.policy import Policy
from omotai_runtime.session import Denied, Session

pytestmark = pytest.mark.usefixtures("browser_available")


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
    policy = Policy(allowed_origins=frozenset({site.portal_url}), login=login, **policy_kw)
    audit = Audit(tmp_path / "audit.jsonl")

    async def go():
        session = Session(policy, audit)
        await session.start()
        try:
            return await scenario(session, audit)
        finally:
            await session.close()

    return asyncio.run(go())


def ref(obs, label):
    return re.search(rf'^(e\d+) \w+ "{re.escape(label)}"', obs, re.M).group(1)


def test_runtime_logs_in_then_closes_the_write_window(site, tmp_path, monkeypatch):
    async def scenario(s, audit):
        assert s.page.url.endswith("/orders") and site.logins == 1
        # after login, a page script trying the same POST is stopped by the network guard
        blocked = await s.page.evaluate(
            "fetch('/login', {method: 'POST', body: 'password=x'})"
            ".then(() => 'sent', () => 'blocked')"
        )
        assert blocked == "blocked" and site.logins == 1
        assert PASSWORD not in audit.path.read_text(encoding="utf-8")

    run(site, tmp_path, monkeypatch, scenario)


def test_navigating_to_the_attacker_origin_is_denied(site, tmp_path, monkeypatch):
    async def scenario(s, audit):
        out = await s.navigate(site.attacker_url + "/verify?password=x")
        assert out.startswith("DENIED (origin_not_allowed)")
        assert site.attacker_hits == []

    run(site, tmp_path, monkeypatch, scenario)


def test_subresources_cannot_reach_the_attacker(site, tmp_path, monkeypatch):
    async def scenario(s, audit):
        obs = await s.navigate(site.portal_url + "/orders/1")  # page embeds <img> to attacker
        assert "[UNTRUSTED PAGE CONTENT" in obs and "Status: Enviado" in obs
        assert "blocked by runtime" in obs and "origin_not_allowed" in obs
        assert site.attacker_hits == []

    run(site, tmp_path, monkeypatch, scenario)


def test_read_only_stops_writes_before_they_are_sent(site, tmp_path, monkeypatch):
    async def scenario(s, audit):
        obs = await s.navigate(site.portal_url + "/orders/1")
        assert await s.act("click", ref(obs, "Cancelar pedido")) == "DENIED (read_only_submit)"
        assert await s.act("click", ref(obs, "Enviar")) == "DENIED (read_only_submit)"
        assert site.cancelled == 0 and site.contact == []

    run(site, tmp_path, monkeypatch, scenario)


def test_agent_cannot_type_passwords_or_follow_foreign_links(site, tmp_path, monkeypatch):
    async def scenario(s, audit):
        obs = await s.navigate(site.portal_url + "/orders/1")
        assert await s.act("type", ref(obs, "pw2"), "x") == "DENIED (agent_cannot_type_passwords)"
        assert await s.act("click", ref(obs, "Verificar")) == "DENIED (link_origin_not_allowed)"
        assert site.attacker_hits == []

    run(site, tmp_path, monkeypatch, scenario)


def test_read_only_still_allows_reading_and_get_forms(site, tmp_path, monkeypatch):
    async def scenario(s, audit):
        obs = await s.navigate(site.portal_url + "/orders/1")
        await s.act("type", ref(obs, "q"), "abc")
        out = await s.act("click", ref(obs, "Buscar"))
        assert "Resultado da busca" in out and site.searches == 1

    run(site, tmp_path, monkeypatch, scenario)


def test_form_rewritten_by_javascript_is_stopped_by_the_guard(site, tmp_path, monkeypatch):
    """Writes allowed, DOM says same-origin, script redirects the POST to the attacker."""

    async def scenario(s, audit):
        obs = await s.navigate(site.portal_url + "/orders/1")
        out = await s.act("click", ref(obs, "Enviar"))
        assert site.attacker_hits == [] and site.contact == []
        assert "blocked by runtime" in out and "origin_not_allowed" in out

    run(site, tmp_path, monkeypatch, scenario, read_only=False)


def test_action_limit(site, tmp_path, monkeypatch):
    async def scenario(s, audit):
        await s.navigate(site.portal_url + "/orders")
        await s.navigate(site.portal_url + "/orders/1")
        with pytest.raises(Denied, match="max_actions"):
            await s.navigate(site.portal_url + "/orders")

    run(site, tmp_path, monkeypatch, scenario, max_actions=2)


def test_audit_chain_covers_the_whole_session(site, tmp_path, monkeypatch):
    async def scenario(s, audit):
        obs = await s.navigate(site.portal_url + "/orders/1")
        await s.act("click", ref(obs, "Cancelar pedido"))
        s.finish("Enviado")
        assert verify(audit.path)

    run(site, tmp_path, monkeypatch, scenario)


def test_redirect_from_an_allowed_origin_to_a_foreign_one_is_blocked(site, tmp_path, monkeypatch):
    async def scenario(s, audit):
        await s.navigate(site.portal_url + "/go")
        out = await s.navigate(site.portal_url + "/hop")  # each hop of a chain is judged
        assert site.attacker_hits == []
        assert "redirect to" in out or "blocked by runtime" in out

    run(site, tmp_path, monkeypatch, scenario)
