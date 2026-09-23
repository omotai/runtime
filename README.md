# Omotai Runtime

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/release/python-3120/)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)

> **Status: pre-alpha (v0.1 in progress).** Not ready for use. Nothing here is a security guarantee yet.

An MCP server that sits between an AI agent and the browser. **The model proposes, the runtime decides.**

## Hypothesis

A deterministic runtime between the LLM and the browser can drastically reduce harmful actions under prompt injection and keep credentials entirely out of the model's context, without destroying the success rate on normal tasks. This repository exists to test that hypothesis, measured with [omotai/eval](https://github.com/omotai/eval).

## Planned components

| Component | Responsibility |
| --- | --- |
| Tool server (MCP) | Exposes `navigate`, `observe`, `act`, `extract`, `fill_secret`, `finish`; page content is always marked untrusted |
| Policy engine | Decides `allow`, `deny` or `confirm` per action, from YAML rules |
| Secret vault | Secrets bound to origins, filled directly into the page, never shown to the model |
| Network guard | Blocks writes to non-allowlisted origins and any secret leaving to an unbound origin |
| Human confirmation | Approval through a channel the model cannot reach |
| Audit log | Append-only, hash-chained record of what the agent saw, asked and was allowed to do |

**Core rule:** policies may only *allow* actions based on facts that require no interpretation (origins, HTTP method, form target, field types, secret bindings). Semantic classification may only make a decision *stricter*.

## What v0.1 implements

| Component | v0.1 |
| --- | --- |
| Tool server (MCP, stdio) | `navigate`, `observe`, `act` (click / type / press Enter), `back`, `finish`. Page content comes back marked `[UNTRUSTED PAGE CONTENT]` |
| Network guard | Two layers, both default-deny by origin. `page.route()` judges every request (any method, any resource type, WebSockets). A **forced proxy** judges every hop, including redirects, which the browser follows without asking the route again. Writes only in the runtime's own login window |
| Policy | YAML: allowed origins, `read_only` (default), action and time limits. Decisions use only scheme, origin, method, field type, form destination |
| Login | Done by the runtime from environment variables; the agent never sees or types a credential, and `type` into password fields is denied |
| Audit log | Append-only JSONL with a SHA-256 hash chain; `omotai_runtime.audit.verify` detects edits and deleted records |

Known limits of the guard: HTTPS through the proxy is judged by host and port only (methods on HTTPS are covered by `page.route()`); DNS and non-HTTP traffic are not controlled. For production, add a network-level firewall around the browser container.

Not in v0.1: human confirmation channel (everything is allow or deny), `fill_secret` for mid-task credentials, any semantic layer, per-task capabilities beyond read-only, multi-origin sites (third-party assets and SSO must be listed in `allowed_origins` or they are blocked).

```bash
# policy for the eval mock portal; credentials come from the environment
export OMOTAI_LOGIN_USER=... OMOTAI_LOGIN_PASSWORD=...
uv run python -m omotai_runtime --policy policies/eval-portal.yaml --audit runs/audit.jsonl
```

**Dashboard security.** `omotai start --dashboard` / `--mode sse` binds to `127.0.0.1` by default; pass `--host 0.0.0.0` to serve the network (Docker does). Every `/api/*` route needs the admin token: set `OMOTAI_ADMIN_TOKEN` (16+ characters) or read the one printed on startup, then sign in on the dashboard (cookie) or send `Authorization: Bearer <token>`. `/mcp` is separate and uses agent API keys. Docker Compose requires `OMOTAI_ADMIN_TOKEN` in `.env`.

Tests that drive a real browser need Chromium: `uv run playwright install chromium`, or set `OMOTAI_BROWSER` to an existing executable.

## Initial Benchmark: Runtime v0.1 vs. Playwright MCP

First comparative utility measurement on the benign task (`clean`, n=5) operating with the local **Qwen 2.5 7B** model (quantized via Ollama, GTX 1660 Super GPU):

| Metric | Playwright MCP (Baseline) | Omotai Runtime v0.1 | Runtime Impact |
| :--- | :---: | :---: | :---: |
| **Success Rate** | **0 / 5 (0%)** | **4 / 5 (80%)** | **Made the task viable (+80 p.p.)** |
| **Average Tokens** | 29,600 tokens | **5,000 tokens** | **-83% context consumption** |
| **Average Time** | 413 s (~7 min) | **60 s** | **7x faster** |

### Why did Omotai Runtime make the 7B model viable?
- **Context bloat reduction:** Playwright MCP accumulates ~30k tokens of raw accessibility tree across 3 to 4 navigation steps, drowning the reasoning of local 7B/8B models.
- **Compact structured representation:** The Omotai Runtime snapshot keeps the context controlled at ~5k tokens, allowing the model to plan, navigate with the `back` tool, and complete the flow successfully.

## Security Evaluation Reports

The empirical results of the Omotai Runtime's security and performance guarantees are thoroughly documented in our scientific evaluation reports. These tests map directly to the OWASP AI Testing Guide (AITG).

- [Consolidated Security Evaluation Report](docs/security-evaluation-report.md)
- [Qwen 3.8 Flash & 2.5 7B: Runtime vs. Baseline](docs/results-qwen-runtime-vs-baseline.md)
- [DeepSeek V4 Flash: Runtime vs. Baseline](docs/results-deepseek-runtime-vs-baseline.md)


## Non-goals

- A new browser engine. Chromium via Playwright is the substrate.
- A protocol for websites or a new action DSL.
- Cross-session browsing memory.
- Payments, CAPTCHA solving or bot-detection evasion.
- Many concurrent agents, multi-browser adapters or a GUI.

Requests in these areas will be closed with a pointer to this list.

## Development

```bash
uv sync
uv run ruff check .
uv run pytest
```

## License

Apache-2.0. Security issues: see [SECURITY](https://github.com/omotai/.github/blob/main/SECURITY.md).
