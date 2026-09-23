"""Domains: the dashboard API, the CLI, and the runtime applying the table on the next action."""

import time
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from test_session import run

from omotai.dashboard import db
from omotai.dashboard.server import app
from omotai.runtime.audit import Audit
from omotai.runtime.policy import Policy
from omotai.runtime.session import Denied, Session

TOKEN = "d" * 32  # noqa: S105  # test fixture
AUTH = {"Authorization": f"Bearer {TOKEN}"}


@pytest.fixture
def api():
    db.init_db()
    app.state.admin_token = TOKEN
    yield TestClient(app, headers=AUTH)
    app.state.admin_token = None
    app.state.session = None


def test_api_normalizes_upserts_lists_and_deletes(api):
    made = api.post(
        "/api/domains", json={"origin": "HTTP://Portal.TEST:80/orders", "action": "allow"}
    )
    assert made.status_code == 200 and made.json()["origin"] == "http://portal.test"
    again = api.post("/api/domains", json={"origin": "http://portal.test", "action": "deny"})
    assert again.json()["id"] == made.json()["id"]  # same origin: the action changes, no duplicate
    listed = api.get("/api/domains").json()["domains"]
    assert [(d["origin"], d["action"]) for d in listed] == [("http://portal.test", "deny")]
    assert api.delete(f"/api/domains/{made.json()['id']}").status_code == 200
    assert api.delete(f"/api/domains/{made.json()['id']}").status_code == 404
    assert api.get("/api/domains").json()["domains"] == []


@pytest.mark.parametrize(
    "origin", ["", "portal.test", "ftp://x.test", "http://", "http://x.test:99999"]
)
def test_api_rejects_what_is_not_an_http_origin(api, origin):
    assert api.post("/api/domains", json={"origin": origin, "action": "allow"}).status_code == 400
    assert (
        api.post("/api/domains", json={"origin": "http://x.test", "action": "maybe"}).status_code
        == 422
    )


def test_api_shows_the_policy_file_origins_when_the_runtime_is_in_this_process(api):
    assert api.get("/api/domains").json()["policy_origins"] == []
    origins = frozenset({"http://b.test", "http://a.test"})
    app.state.session = SimpleNamespace(
        policy=Policy(allowed_origins=origins, base_origins=origins)
    )
    assert api.get("/api/domains").json()["policy_origins"] == ["http://a.test", "http://b.test"]


def test_cli_normalizes_and_refuses_invalid_origins():
    import sqlite3

    from click.testing import CliRunner

    from omotai.runtime.server import cli

    r = CliRunner()
    assert r.invoke(cli, ["domain", "add", "HTTP://Portal.TEST:80/x", "--deny"]).exit_code == 0
    with sqlite3.connect(db.DB_PATH) as conn:
        assert conn.execute("SELECT origin, action FROM domains").fetchall() == [
            ("http://portal.test", "deny")
        ]
    assert r.invoke(cli, ["domain", "rm", "http://portal.test:80/"]).exit_code == 0
    with sqlite3.connect(db.DB_PATH) as conn:
        assert conn.execute("SELECT COUNT(*) FROM domains").fetchone() == (0,)
    assert r.invoke(cli, ["domain", "add", "not-an-origin", "--allow"]).exit_code == 1


def make_session(tmp_path, origins):
    s = Session(Policy(allowed_origins=frozenset(origins)), Audit(tmp_path / "a.jsonl"))
    s.started = time.time()
    return s


def set_domain(origin, action=None):
    import sqlite3

    with sqlite3.connect(db.DB_PATH) as conn:
        if action is None:
            conn.execute("DELETE FROM domains WHERE origin = ?", (origin,))
        else:
            conn.execute("INSERT INTO domains (origin, action) VALUES (?, ?)", (origin, action))


def test_the_next_step_applies_the_table_without_a_restart(tmp_path):
    db.init_db()
    s = make_session(tmp_path, ["http://a.test"])
    s._step("navigate")
    assert s.policy.origin_allowed("http://a.test/x")

    set_domain("http://a.test", "deny")  # what the dashboard or the CLI does
    assert s.policy.origin_allowed("http://a.test/x")  # nothing changes until the agent acts
    s._step("navigate")
    assert not s.policy.origin_allowed("http://a.test/x")

    set_domain("http://a.test", None)
    set_domain("http://new.test", "allow")
    s._step("act")
    assert s.policy.origin_allowed("http://a.test/x") and s.policy.origin_allowed(
        "http://new.test/"
    )
    log = s.audit.path.read_text(encoding="utf-8")
    assert log.count("domains_reloaded") == 2 and "http://new.test" in log


def test_an_unreadable_table_denies_instead_of_keeping_stale_rules(tmp_path, monkeypatch):
    s = make_session(tmp_path, ["http://a.test"])
    (tmp_path / "junk.db").write_bytes(b"this is not a sqlite file" * 10)
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "junk.db")
    with pytest.raises(Denied, match="domains_unreadable"):
        s._step("navigate")


@pytest.mark.usefixtures("browser_available")
def test_a_live_session_follows_the_table(site, tmp_path, monkeypatch):
    db.init_db()

    async def scenario(s, audit):
        assert "Pedidos" in await s.navigate(site.portal_url + "/orders")
        set_domain(site.portal_url, "deny")
        out = await s.navigate(site.portal_url + "/orders")
        assert out.startswith("DENIED (origin_not_allowed)")
        set_domain(site.portal_url, None)
        assert "Pedidos" in await s.navigate(site.portal_url + "/orders")

    run(site, tmp_path, monkeypatch, scenario)
