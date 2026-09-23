"""SSE transport end to end: the runtime as a network service, agent keys, admin token, audit."""

import asyncio
import json
import os
import socket
import sqlite3
import subprocess
import sys
import time
import urllib.error
import urllib.request

import pytest
from mcp import ClientSession
from mcp.client.sse import sse_client

ADMIN = "admin-token-for-the-sse-test-0123"  # noqa: S105  # test fixture


def http(method, url, headers=None, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(  # noqa: S310
        url,
        data=data,
        method=method,
        headers={"Content-Type": "application/json", **(headers or {})},
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as r:  # noqa: S310
            return r.status, json.loads(r.read() or b"null")
    except urllib.error.HTTPError as e:
        return e.code, None


@pytest.fixture
def server(tmp_path):
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    policy = tmp_path / "policy.yaml"
    policy.write_text("allowed_origins: []", encoding="utf-8")
    db, audit, logfile = tmp_path / "omotai.db", tmp_path / "audit.jsonl", tmp_path / "server.log"
    env = {**os.environ, "OMOTAI_DB": str(db), "OMOTAI_ADMIN_TOKEN": ADMIN}
    log = logfile.open("wb")
    proc = subprocess.Popen(  # noqa: S603
        [sys.executable, "-m", "omotai.runtime", "start", "--policy", str(policy)]
        + ["--audit", str(audit), "--mode", "sse", "--port", str(port)],
        cwd=tmp_path,
        env=env,
        stdout=log,
        stderr=subprocess.STDOUT,
    )
    base = f"http://127.0.0.1:{port}"
    try:
        deadline = time.time() + 90  # the browser launches in the app lifespan
        while True:
            assert proc.poll() is None, logfile.read_text(errors="replace")
            try:
                http("GET", f"{base}/api/me")
                break
            except OSError:
                assert time.time() < deadline, "server did not come up"
                time.sleep(0.5)
        yield base, db, audit
    finally:
        proc.terminate()
        try:
            proc.wait(20)
        except subprocess.TimeoutExpired:
            proc.kill()
        log.close()


def test_sse_needs_an_agent_key_and_attributes_the_audit(server):
    base, db, audit = server
    admin = {"Authorization": f"Bearer {ADMIN}"}
    status, created = http("POST", f"{base}/api/agents", admin, {"name": "smoke-agent"})
    assert status == 200
    key = created["api_key"]

    # no key, a wrong key and the admin token are all refused on /mcp
    for headers in ({}, {"Authorization": "Bearer sk-omotai-wrong"}, admin):
        assert http("GET", f"{base}/mcp/sse", headers)[0] == 401
    # and an agent key does not open the admin API
    assert http("GET", f"{base}/api/agents", {"Authorization": f"Bearer {key}"})[0] == 401

    async def go():
        async with sse_client(f"{base}/mcp/sse", headers={"Authorization": f"Bearer {key}"}) as (
            r,
            w,
        ):
            async with ClientSession(r, w) as s:
                await s.initialize()
                names = {t.name for t in (await s.list_tools()).tools}
                assert names == {"navigate", "observe", "back", "act", "ask_human", "finish"}
                # a tool call travels over the POST /mcp/messages/ leg, not just the handshake
                await s.call_tool("finish", {"answer": "done"})

    asyncio.run(go())

    with sqlite3.connect(db) as conn:
        rows = conn.execute("SELECT agent_name FROM audit_logs WHERE tool = 'finish'").fetchall()
        everything = str(conn.execute("SELECT * FROM audit_logs").fetchall())
    assert rows == [("smoke-agent",)]
    assert key not in everything and key not in audit.read_text(encoding="utf-8")
