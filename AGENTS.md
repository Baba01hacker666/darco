# AGENTS.md

Guidance for AI agents (and humans) working in this repository.

## Project overview

Darco is a CLI-first HTTP toolkit for AI-assisted security testing. It ingests
requests from curl commands, raw HTTP text, and HAR files; maintains per-target
session state (cookies + CSRF headers); sends/replays requests with Burp-style
mutations (`--strip-session`, `--flip-param`, etc.); diffs and analyzes
responses; runs a record-only forward proxy; and crawls targets via `discover`.
All state lives in a per-target workspace (`*.darco/` directory).

This is an offensive-security tool. It has **no guardrails by design** — the
user owns authorization. Do not add scope enforcement, rate-limit policing, or
approval gates unless explicitly asked.

## Commands

```bash
.venv/bin/python -m pytest -q          # run the full test suite
.venv/bin/python -m darco --help        # run the CLI without installing
.venv/bin/python -m compileall -q darco # syntax check
```

- The venv is `.venv` (Python 3.12; `requires-python >= 3.11`). Use
  `UV_CACHE_DIR=/tmp/uv-cache uv pip install ...` if adding dependencies.
- Integration tests (`test_engine.py`, `test_proxy.py`, `test_discovery.py`,
  `test_cli.py`) bind localhost sockets; sandboxed environments may need
  network/bind approval.
- Dependencies: `httpx`, `pydantic>=2`, `click`, `beautifulsoup4`, `pyyaml` (declared in
  `pyproject.toml`). No formatter/linter is configured — keep style consistent
  with existing modules.

## Architecture

- `darco/models.py` — all Pydantic v2 data models (`Request`, `Response`,
  `HistoryRecord`, `WorkspaceConfig`, `SessionState`, `Finding`, `SiteMap`,
  `Endpoint`, `Form`, `AdminPanel`, `AttackTemplate`). Serialize with `to_json(model)` / `model_dump(mode="json")`.
- `darco/workspace.py` — `Workspace` class: config, session, history
  (`history.jsonl` with zero-padded ids `0001`...), bodies, findings, sitemap.
  `next_id()` reserves an id; `add_history()` syncs the counter.
- `darco/ingest/` — `curl.py`, `raw.py`, `har.py` parse external formats into
  `Request` models. The curl tokenizer is intentionally hand-rolled; keep it
  dependency-free and add test cases for new flags.
- `darco/engine.py` — HTTP execution. `execute()` is the low-level path (returns
  the raw `httpx.Response` for the proxy); `send_request()` / `send_and_record()`
  wrap it. Session capture (Set-Cookie, CSRF headers) lives here via
  `update_session()`.
- `darco/mutate.py` — mutation transforms (`Mutation` ops) applied to a request
  copy with lineage (`parent_id`, `mutations` list).
- `darco/diff.py`, `darco/analyze.py` — response diffing (volatile-token
  normalization) and signal heuristics (findings).
- `darco/login.py` — login form discovery, SQLi auth-bypass tests, smart
  domain-derived and discovered-email credential generator.
- `darco/admin.py` — administrative portal & dashboard discovery, auth
  classification (`login_form`, `exposed_dashboard`, `basic_auth`), and credential audit.
- `darco/templates/` — Nuclei-compatible attack template engine: YAML/JSON loader,
  async multi-target execution engine, matchers (`status`, `word`, `regex`),
  extractors (`regex`, `kval`, `json`), and template scaffolder.
- `darco/proxy.py` — record-only asyncio forward proxy; HTTPS is tunneled
  (CONNECT), not decrypted.
- `darco/discovery/` — async crawler: same-origin BFS, form/JS/email extraction,
  `robots.txt`/`sitemap.xml` seeding, endpoint inventory + signals.
- `darco/cli.py` — click CLI wiring; every command emits JSON to stdout and logs
  to stderr. Expected failures raise `DarcoError` (from `darco/errors.py`).

## Conventions

- Output: JSON on stdout is the agent contract. Human-readable tables only via
  `--format table`. Never print diagnostics to stdout.
- Errors: raise `DarcoError` for expected failures; the CLI catches it and exits
  `1`. Keep `click` usage errors for malformed CLI input.
- Bodies: `history.jsonl` stores a capped body preview; full bodies go to
  `bodies/<id>.body` (`BODY_PREVIEW_CAP` in `workspace.py`).
- Add tests for every new parser flag, mutation op, and signal heuristic —
  the fixture app in `tests/conftest.py` is the standard integration target
  (login, rate-limited OTP, CSRF echo, CAPTCHA, error leaks).
- Don't commit workspaces (`*.darco/`), the venv, or build artifacts —
  `.gitignore` already covers them.

## Testing expectations

Before finishing a change:

1. Add/update focused unit tests (parsers, mutations, diff, analyze, workspace).
2. Add an integration test if the change touches request flow, discovery, proxy,
   or CLI behavior.
3. Run the full suite with `.venv/bin/python -m pytest -q` and confirm green.
