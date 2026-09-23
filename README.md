# Omotai Runtime

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/release/python-3120/)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)

> **Status: pre-alpha.** Not ready for production use. Nothing here is a security guarantee yet.

An MCP server that sits between an AI agent and the browser. **The model proposes, the runtime decides.**

## Hypothesis

A deterministic runtime between the LLM and the browser can drastically reduce harmful actions under prompt injection and keep credentials entirely out of the model's context, without destroying the success rate on normal tasks. This repository exists to test that hypothesis, measured with [omotai/eval](https://github.com/omotai/eval).

## Components

| Component | State |
| --- | --- |
| Tool server (MCP, stdio and SSE) | **Implemented**: `navigate`, `observe`, `back`, `act` (click / type / press Enter), `ask_human`, `finish`. Page content always comes back marked `[UNTRUSTED PAGE CONTENT]`. Planned: `extract`, `fill_secret` |
| Policy engine | **Implemented**: `allow` / `deny` / `confirm` from YAML facts (scheme, origin, method, form destination, field type) plus dynamic domains. No semantic layer yet |
| Network guard | **Implemented**: two layers, both default-deny by origin (`page.route()` for every request, and a forced proxy that judges every redirect hop) |
| Human confirmation | **Implemented**: form submits wait for the operator on the dashboard (`confirm_writes`); `ask_human` is a voluntary extra channel |
| Secret vault | **Partial**: secrets live in a table of the local SQLite database, **in plain text** (encryption is planned). Used for the runtime's own login at startup, and every stored secret is redacted from what the model sees. Planned: `fill_secret`, secrets bound to origins |
| Audit | **Implemented**: append-only JSONL with a SHA-256 hash chain, plus an `audit_logs` table in SQLite (not tamper-evident) |
| Dashboard | **Implemented**: live telemetry, agent API keys, human approvals, domains, secrets. Admin token required |

**Core rule:** policies may only *allow* actions based on facts that require no interpretation (origins, HTTP method, form target, field types, secret bindings). Semantic classification may only make a decision *stricter*.

## Quick start

The fastest way to see it work is the Docker setup with the mock portal of [omotai/eval](https://github.com/omotai/eval): the agent browses the portal through the runtime, and you approve or deny its writes on the dashboard. Step by step in [docs/how-to-use.md](docs/how-to-use.md).

```bash
# .env (not committed): OMOTAI_ADMIN_TOKEN=<16+ characters>
docker compose run --rm omotai-runtime omotai secret add portal-login <portal password>
docker compose up -d --build     # runtime + dashboard on http://127.0.0.1:8000
```

Without Docker:

```bash
uv sync && uv run playwright install chromium
export OMOTAI_LOGIN_USER=... OMOTAI_LOGIN_PASSWORD=...
uv run omotai start --policy policies/eval-portal.yaml --audit runs/audit.jsonl   # stdio
uv run omotai start --mode sse --policy policies/eval-portal-confirm.yaml         # SSE + dashboard on 127.0.0.1:8080
```

Connecting a client (Claude Code, Claude Desktop, ...) is in [docs/mcp-setup.md](docs/mcp-setup.md).

## How it behaves

**Human confirmation.** With `read_only: true` and `confirm_writes: true` (see `policies/eval-portal-confirm.yaml`), a form submit to an allowed origin is not denied but waits for the operator on the dashboard (Human Approvals). The runtime, not the model, asks: the text shown is built from facts (method, form URL, field names and values), and only `approved` or `denied` ever reaches the agent. An approval opens a write window for that exact request during that one action; if the page changed while the operator decided, or nobody answers within `confirm_timeout_seconds`, the action is denied. `max_confirmations` caps how often a session can ask. Writes that do not come from a form in the DOM (fetch/JS) stay denied. The `ask_human` tool remains as a voluntary extra channel; it does not gate anything by itself.

**Dynamic domains.** Besides `allowed_origins` in the policy file, origins can be allowed or denied at runtime from the dashboard (Domains tab) or with `omotai domain add <origin> --allow|--deny` (`rm`, `list`). Deny wins over any allow, origins are normalized (`HTTP://Portal.TEST:80/x` becomes `http://portal.test`), and the runtime rereads the table at every agent action, so a change applies to the agent's next action without a restart. If the table cannot be read, the action is denied (`domains_unreadable`). The runtime's login at startup still needs its origin in the policy file or the table before it starts.

**Login and secrets.** The login is done by the runtime at startup, from the vault (`login.secret_id` in the policy) or from environment variables. The agent never sees or types a credential: `type` into password fields is denied and any stored secret in page text is replaced by `[redacted]`.

**Two credentials, two doors.** The dashboard (`/api/*`) needs the admin token (`OMOTAI_ADMIN_TOKEN`, or the one printed on startup). The MCP endpoint (`/mcp` in SSE mode) needs an agent API key created on the dashboard. One does not open the other. Both `omotai start --dashboard` and `--mode sse` bind to `127.0.0.1` unless you pass `--host 0.0.0.0`.

**Data.** The SQLite database (agents, secrets, domains, approvals, audit table) lives at `runs/omotai.db`, relative to the working directory. Set `OMOTAI_DB=/path/to/file.db` to use another file, e.g. one database per evaluation run or a Docker volume.

## Documentation

| Document | What it covers |
| --- | --- |
| [docs/how-to-use.md](docs/how-to-use.md) | End-to-end walkthrough (Docker and local), scenarios to try, troubleshooting (in Portuguese) |
| [docs/mcp-setup.md](docs/mcp-setup.md) | Transports, tools, connecting clients, credentials (in Portuguese) |
| [docs/policy-reference.md](docs/policy-reference.md) | Every policy key, decision rules and `DENIED (...)` codes (in Portuguese) |
| [docs/reference.md](docs/reference.md) | CLI, environment variables, dashboard API, database tables, audit events (in Portuguese) |
| [Security evaluation reports](#security-evaluation-reports) | Empirical results against the OWASP AI Testing Guide |

Known limits of the guard: HTTPS through the proxy is judged by host and port only (methods on HTTPS are covered by `page.route()`); DNS and non-HTTP traffic are not controlled. For production, add a network-level firewall around the browser container. In SSE mode all agents share one browser session, and the action and time limits are per process, not per connection. Not implemented: `fill_secret` for mid-task credentials, encrypted vault, any semantic layer, per-task capabilities beyond read-only, multi-origin sites (third-party assets and SSO must be listed in `allowed_origins` or they are blocked).

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
- Many concurrent agents, multi-browser adapters or a general-purpose GUI (the dashboard is a small operator console).

Requests in these areas will be closed with a pointer to this list.

## Development

```bash
uv sync
uv run playwright install chromium   # or set OMOTAI_BROWSER to an existing executable
uv run ruff check .
uv run pytest
```

Tests never touch `runs/omotai.db`: an autouse fixture points the database at a temporary file. Tests that drive a real browser need Chromium.

## License

Apache-2.0. Security issues: see [SECURITY](https://github.com/omotai/.github/blob/main/SECURITY.md).
