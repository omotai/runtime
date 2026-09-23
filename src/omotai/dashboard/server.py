import asyncio
import hmac
import os
import secrets
import threading
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal

import click
import uvicorn
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sse_starlette.sse import EventSourceResponse
from starlette.requests import HTTPConnection
from starlette.responses import PlainTextResponse

from omotai.dashboard.db import get_connection, init_db
from omotai.runtime.audit import current_agent_name
from omotai.runtime.policy import normalize_origin


@asynccontextmanager
async def app_lifespan(app: FastAPI):
    session = getattr(app.state, "session", None)
    if session:
        await session.start()
    yield
    if session:
        await session.close()


ADMIN_COOKIE = "omotai_admin"
LOOPBACK = ("127.0.0.1", "localhost", "::1")


def _admin_ok(app, presented: str | None) -> bool:
    token = getattr(app.state, "admin_token", None)
    if not token or not presented:
        return False
    return hmac.compare_digest(presented.encode(), token.encode())


class AdminAuthMiddleware:
    """Every /api/* route needs the admin token (Bearer header or cookie), so a route added later
    is protected by default. No token configured = nothing gets in. /mcp has its own agent keys."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        path = scope.get("path", "")
        if scope["type"] == "http" and path.startswith("/api/") and path != "/api/login":
            conn = HTTPConnection(scope)
            auth = conn.headers.get("authorization", "")
            presented = auth[7:] if auth.startswith("Bearer ") else conn.cookies.get(ADMIN_COOKIE)
            if not _admin_ok(scope["app"], presented):
                await PlainTextResponse("Unauthorized", status_code=401)(scope, receive, send)
                return
        await self.app(scope, receive, send)


app = FastAPI(title="Omotai Runtime Dashboard", lifespan=app_lifespan)
app.add_middleware(AdminAuthMiddleware)

# Initialize DB on startup
init_db()


# Models
class AgentCreate(BaseModel):
    name: str


class SecretCreate(BaseModel):
    key_name: str
    secret_value: str


class ApprovalUpdate(BaseModel):
    status: str


class Login(BaseModel):
    token: str


class DomainCreate(BaseModel):
    origin: str
    action: Literal["allow", "deny"]


def valid_origin(raw: str) -> str:
    try:
        return normalize_origin(raw)
    except ValueError as e:
        raise HTTPException(status_code=400, detail="Not a valid http(s) origin") from e


def mask_api_key(key: str) -> str:
    prefix = "sk-omotai-"
    if key.startswith(prefix):
        secret = key[len(prefix) :]
        if len(secret) > 4:
            return f"{prefix}{'*' * (len(secret) - 4)}{secret[-4:]}"
        return f"{prefix}{'*' * len(secret)}"
    if len(key) > 4:
        return f"{'*' * (len(key) - 4)}{key[-4:]}"
    return "*" * len(key)


# API Routes
@app.post("/api/login")
def login(body: Login, request: Request, response: Response):
    if not _admin_ok(request.app, body.token):
        raise HTTPException(status_code=401, detail="Invalid token")
    response.set_cookie(ADMIN_COOKIE, body.token, httponly=True, samesite="strict", path="/")
    return {"status": "ok"}


@app.get("/api/me")
def me():
    return {"status": "ok"}


@app.post("/api/agents")
def create_agent(agent: AgentCreate):
    api_key = f"sk-omotai-{uuid.uuid4().hex}"
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO agents (name, api_key) VALUES (?, ?)", (agent.name, api_key)
            )
            conn.commit()
            return {"id": cursor.lastrowid, "name": agent.name, "api_key": api_key}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


@app.get("/api/agents")
def list_agents():
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, name, api_key, created_at FROM agents ORDER BY id DESC")
        rows = cursor.fetchall()
        return [
            {"id": r[0], "name": r[1], "api_key": mask_api_key(r[2]), "created_at": r[3]}
            for r in rows
        ]


@app.delete("/api/agents/{agent_id}")
def delete_agent(agent_id: int):
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM agents WHERE id = ?", (agent_id,))
        conn.commit()
        return {"status": "ok"}


@app.get("/api/domains")
def list_domains():
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT id, origin, action, created_at FROM domains ORDER BY id DESC"
        ).fetchall()
    # the YAML origins are only known where the runtime runs in this process (SSE mode)
    session = getattr(app.state, "session", None)
    policy_origins = []
    if session is not None:
        base = session.policy.base_origins
        policy_origins = sorted(base if base is not None else session.policy.allowed_origins)
    return {
        "domains": [{"id": r[0], "origin": r[1], "action": r[2], "created_at": r[3]} for r in rows],
        "policy_origins": policy_origins,
    }


@app.post("/api/domains")
def add_domain(domain: DomainCreate):
    origin = valid_origin(domain.origin)
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO domains (origin, action) VALUES (?, ?) "
            "ON CONFLICT(origin) DO UPDATE SET action = excluded.action",
            (origin, domain.action),
        )
        conn.commit()
        row = conn.execute("SELECT id FROM domains WHERE origin = ?", (origin,)).fetchone()
    return {"id": row[0], "origin": origin, "action": domain.action}


@app.delete("/api/domains/{domain_id}")
def delete_domain(domain_id: int):
    with get_connection() as conn:
        cursor = conn.execute("DELETE FROM domains WHERE id = ?", (domain_id,))
        conn.commit()
    if cursor.rowcount == 0:
        raise HTTPException(status_code=404, detail="Domain not found")
    return {"status": "ok"}


@app.post("/api/secrets")
def create_secret(secret: SecretCreate):
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO secrets (key_name, secret_value) VALUES (?, ?)",
                (secret.key_name, secret.secret_value),
            )
            conn.commit()
            return {"id": cursor.lastrowid, "key_name": secret.key_name}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e)) from e


@app.get("/api/secrets")
def list_secrets():
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, key_name, created_at FROM secrets ORDER BY id DESC")
        rows = cursor.fetchall()
        return [{"id": r[0], "key_name": r[1], "created_at": r[2]} for r in rows]


@app.delete("/api/secrets/{secret_id}")
def delete_secret(secret_id: int):
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM secrets WHERE id = ?", (secret_id,))
        conn.commit()
        return {"status": "ok"}


@app.get("/api/approvals")
def list_approvals():
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, session_id, reason, status, created_at, source "
            "FROM approvals ORDER BY id DESC LIMIT 50"
        )
        rows = cursor.fetchall()
        return [
            {
                "id": r[0],
                "session_id": r[1],
                "reason": r[2],
                "status": r[3],
                "created_at": r[4],
                "source": r[5],
            }
            for r in rows
        ]


@app.post("/api/approvals/{approval_id}")
def update_approval(approval_id: int, update: ApprovalUpdate):
    if update.status not in ("approved", "denied"):
        raise HTTPException(status_code=400, detail="Invalid status")
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE approvals SET status = ? WHERE id = ? AND status = 'pending'",
            (update.status, approval_id),
        )
        conn.commit()
        if cursor.rowcount == 0:  # unknown id, or already resolved (answered or timed out)
            raise HTTPException(status_code=409, detail="Approval is not pending")
        return {"status": "ok"}


@app.get("/api/logs/stream")
async def stream_logs():
    async def log_generator():
        log_path = Path("runs/audit.jsonl")
        if not log_path.exists():
            log_path.parent.mkdir(parents=True, exist_ok=True)
            log_path.touch()

        with open(log_path, encoding="utf-8") as f:
            while True:
                line = f.readline()
                if not line:
                    await asyncio.sleep(0.2)
                    continue
                yield {"data": line.strip()}

    return EventSourceResponse(log_generator())


class SseAuthMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        headers = dict(scope.get("headers", []))
        auth_header = headers.get(b"authorization", b"").decode("utf-8")

        if not auth_header.startswith("Bearer "):
            await self._send_401(send)
            return

        token = auth_header.split(" ")[1]

        with get_connection() as conn:
            cursor = conn.cursor()
            # Fetch all to use compare_digest (avoids timing attacks)
            cursor.execute("SELECT name, api_key FROM agents")
            rows = cursor.fetchall()

            valid_agent = None
            for row in rows:
                if hmac.compare_digest(row[1], token):
                    valid_agent = row[0]
                    break

            if not valid_agent:
                await self._send_401(send)
                return

        current_agent_name.set(valid_agent)
        await self.app(scope, receive, send)

    async def _send_401(self, send):
        await send(
            {
                "type": "http.response.start",
                "status": 401,
                "headers": [(b"content-type", b"text/plain")],
            }
        )
        await send(
            {
                "type": "http.response.body",
                "body": b"Unauthorized",
            }
        )


# Static files (Frontend)
static_dir = Path(__file__).parent / "static"
os.makedirs(static_dir, exist_ok=True)

# Important: ensure index.html exists, otherwise StaticFiles returns 404
if not (static_dir / "index.html").exists():
    with open(static_dir / "index.html", "w", encoding="utf-8") as f:
        f.write("<html><body>Dashboard Loading...</body></html>")

app.mount("/", StaticFiles(directory=str(static_dir), html=True), name="static")


def start_dashboard(
    port: int = 8080,
    mcp_server=None,
    session=None,
    host: str = "127.0.0.1",
    admin_token: str | None = None,
):
    token = admin_token or os.environ.get("OMOTAI_ADMIN_TOKEN")
    if token and len(token) < 16:
        raise click.ClickException("OMOTAI_ADMIN_TOKEN must have at least 16 characters")
    if not token:
        token = secrets.token_urlsafe(32)
        click.secho(f"Dashboard admin token (this run only): {token}", fg="yellow", err=True)
    app.state.admin_token = token
    if host not in LOOPBACK:
        click.secho(
            f"WARNING: dashboard reachable from the network on {host}:{port}; /api/* needs the "
            "admin token, /mcp needs an agent key. Prefer TLS in front of it.",
            fg="yellow",
            err=True,
        )

    if mcp_server:
        # Mount the MCP SSE app protected by the Auth Middleware
        # We must insert it before the static catch-all route
        mcp_app = SseAuthMiddleware(mcp_server.sse_app())

        # We can use FastAPI's mount
        from starlette.routing import Mount

        mcp_mount = Mount("/mcp", app=mcp_app)

        # Insert at the beginning so it precedes the "/" static mount
        app.routes.insert(0, mcp_mount)

    app.state.mcp_server = mcp_server
    app.state.session = session

    uvicorn.run(app, host=host, port=port, log_level="info")


def run_in_background(port: int = 8080):
    t = threading.Thread(target=start_dashboard, args=(port,), daemon=True)
    t.start()
