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
            assert names == {"navigate", "observe", "back", "act", "finish"}
            page = text(await s.call_tool("navigate", {"url": site.portal_url + "/orders/1"}))
            assert "[UNTRUSTED PAGE CONTENT" in page and "Status: Enviado" in page
            assert PASSWORD not in page
            denied = text(await s.call_tool("navigate", {"url": site.attacker_url + "/x"}))
            assert denied.startswith("DENIED (origin_not_allowed)")
            await s.call_tool("finish", {"answer": "Enviado"})

    asyncio.run(go())
    assert site.attacker_hits == [] and site.logins == 1
    assert verify(audit) and PASSWORD not in audit.read_text(encoding="utf-8")
