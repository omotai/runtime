import asyncio
import hmac
import os
import threading
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sse_starlette.sse import EventSourceResponse

from omotai.dashboard.db import get_connection, init_db
from omotai.runtime.audit import current_agent_name


@asynccontextmanager
async def app_lifespan(app: FastAPI):
    session = getattr(app.state, "session", None)
    if session:
        await session.start()
    yield
    if session:
        await session.close()


app = FastAPI(title="Omotai Runtime Dashboard", lifespan=app_lifespan)

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


# API Routes
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
        return [{"id": r[0], "name": r[1], "api_key": r[2], "created_at": r[3]} for r in rows]


@app.delete("/api/agents/{agent_id}")
def delete_agent(agent_id: int):
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM agents WHERE id = ?", (agent_id,))
        conn.commit()
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
            "SELECT id, session_id, reason, status, created_at "
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
            }
            for r in rows
        ]


@app.post("/api/approvals/{approval_id}")
def update_approval(approval_id: int, update: ApprovalUpdate):
    if update.status not in ("approved", "denied"):
        raise HTTPException(status_code=400, detail="Invalid status")
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE approvals SET status = ? WHERE id = ?", (update.status, approval_id))
        conn.commit()
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


def start_dashboard(port: int = 8080, mcp_server=None, session=None):
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

    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")  # noqa: S104


def run_in_background(port: int = 8080):
    t = threading.Thread(target=start_dashboard, args=(port,), daemon=True)
    t.start()
