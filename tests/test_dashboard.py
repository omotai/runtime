import click
import pytest
from fastapi.testclient import TestClient

from omotai.dashboard.db import init_db
from omotai.dashboard.server import app, mask_api_key, start_dashboard

TOKEN = "t" * 32  # noqa: S105  # test fixture
AUTH = {"Authorization": f"Bearer {TOKEN}"}


@pytest.fixture(autouse=True)
def setup_db():
    init_db()
    app.state.admin_token = TOKEN
    yield
    app.state.admin_token = None


def test_mask_api_key_unit():
    # Standard omotai key
    full_key = "sk-omotai-0123456789abcdef0123456789abcdef"
    masked = mask_api_key(full_key)
    assert masked.startswith("sk-omotai-")
    assert masked.endswith("cdef")
    assert "*" * 28 in masked
    assert full_key != masked

    # Custom short key with prefix
    short_key = "sk-omotai-1234"
    assert mask_api_key(short_key) == "sk-omotai-****"

    # Key without prefix
    other_key = "1234567890"
    assert mask_api_key(other_key) == "******7890"


def test_create_and_list_agents_api():
    client = TestClient(app, headers=AUTH)

    # 1. Create agent
    agent_name = "test-agent-51"
    create_res = client.post("/api/agents", json={"name": agent_name})
    assert create_res.status_code == 200
    created_data = create_res.json()
    assert created_data["name"] == agent_name
    full_key = created_data["api_key"]
    assert full_key.startswith("sk-omotai-")
    agent_id = created_data["id"]

    # 2. List agents - key must be masked
    list_res = client.get("/api/agents")
    assert list_res.status_code == 200
    agents = list_res.json()

    target_agent = next((a for a in agents if a["id"] == agent_id), None)
    assert target_agent is not None
    assert target_agent["name"] == agent_name

    masked_key = target_agent["api_key"]
    assert masked_key != full_key
    assert "*" in masked_key
    assert masked_key.startswith("sk-omotai-")
    assert masked_key.endswith(full_key[-4:])

    # 3. Clean up
    del_res = client.delete(f"/api/agents/{agent_id}")
    assert del_res.status_code == 200


def _api_routes():
    for r in app.routes:
        path = getattr(r, "path", "")
        if path.startswith("/api/") and path != "/api/login":
            for method in r.methods - {"HEAD", "OPTIONS"}:
                yield (
                    method,
                    path.replace("{agent_id}", "1")
                    .replace("{secret_id}", "1")
                    .replace("{approval_id}", "1"),
                )


def test_every_api_route_rejects_requests_without_the_token():
    routes = list(_api_routes())
    assert len(routes) >= 9  # agents, secrets, approvals, logs, me: guards against a vacuous loop
    client = TestClient(app)
    for method, path in routes:
        assert client.request(method, path).status_code == 401, (method, path)
        r = client.request(method, path, headers={"Authorization": f"Bearer {'x' * 32}"})
        assert r.status_code == 401, (method, path)


def test_api_accepts_bearer_token():
    assert TestClient(app).get("/api/me", headers=AUTH).status_code == 200


def test_login_sets_a_cookie_that_opens_the_api():
    client = TestClient(app)
    assert client.post("/api/login", json={"token": "wrong" * 8}).status_code == 401
    ok = client.post("/api/login", json={"token": TOKEN})
    assert ok.status_code == 200
    assert "httponly" in ok.headers["set-cookie"].lower()
    assert "samesite=strict" in ok.headers["set-cookie"].lower()
    assert client.get("/api/me").status_code == 200  # cookie jar carries it


def test_no_configured_token_means_nothing_gets_in():
    app.state.admin_token = None
    client = TestClient(app)
    assert client.get("/api/me", headers={"Authorization": "Bearer "}).status_code == 401
    assert client.post("/api/login", json={"token": ""}).status_code == 401


def test_static_frontend_stays_public_and_start_rejects_weak_token():
    assert TestClient(app).get("/").status_code == 200
    with pytest.raises(click.ClickException):
        start_dashboard(admin_token="short")  # noqa: S106


def test_approvals_list_the_source_and_resolve_only_once():
    from omotai.dashboard.db import get_connection

    with get_connection() as conn:
        cur = conn.execute(
            "INSERT INTO approvals (session_id, reason, source) VALUES ('s', 'POST /x', 'runtime')"
        )
        conn.commit()
        approval_id = cur.lastrowid
    client = TestClient(app, headers=AUTH)
    listed = next(a for a in client.get("/api/approvals").json() if a["id"] == approval_id)
    assert listed["source"] == "runtime" and listed["status"] == "pending"
    assert (
        client.post(f"/api/approvals/{approval_id}", json={"status": "approved"}).status_code == 200
    )
    # a resolved approval cannot be flipped afterwards (e.g. approved after the runtime timed out)
    assert (
        client.post(f"/api/approvals/{approval_id}", json={"status": "denied"}).status_code == 409
    )
    assert client.post("/api/approvals/999999", json={"status": "approved"}).status_code == 409
    with get_connection() as conn:
        conn.execute("DELETE FROM approvals WHERE id = ?", (approval_id,))
