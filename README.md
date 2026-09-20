# Omotai Runtime

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
| Tool server (MCP, stdio) | `navigate`, `observe`, `act` (click / type), `finish`. Page content comes back marked `[UNTRUSTED PAGE CONTENT]` |
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

Tests that drive a real browser need Chromium: `uv run playwright install chromium`, or set `OMOTAI_BROWSER` to an existing executable.

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
