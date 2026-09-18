# Omotai Runtime

> **Status: pre-alpha.** Not ready for use. Nothing here is a security guarantee yet.

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
