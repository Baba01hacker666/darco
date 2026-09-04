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
.venv/bin/python -m ruff check darco/   # lint
.venv/bin/python -m bandit -r darco/    # security scan
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
  `update_session()`. Supports `proxy` parameter.
- `darco/mutate.py` — mutation transforms (`Mutation` ops) applied to a request
  copy with lineage (`parent_id`, `mutations` list).
- `darco/diff.py`, `darco/analyze.py` — response diffing (volatile-token
  normalization) and signal heuristics (findings).
- `darco/login.py` — login form discovery, SQLi auth-bypass tests, smart
  domain-derived and discovered-email credential generator.
- `darco/admin.py` — administrative portal & dashboard discovery, auth
  classification (`login_form`, `exposed_dashboard`, `basic_auth`), and credential audit.
- `darco/templates/` — Nuclei-compatible attack template engine: YAML/JSON loader,
  async multi-target execution engine, native matchers (`status`, `word`,
  `regex`, `size`, `dsl`), extractors (`regex`, `kval`, `json` with dot-path
  nesting), extractor chaining (`internal: true` feeds values to later
  requests), and a scaffolder. Extra matcher/extractor types live in the
  custom-type registry (`templates/custom.py`: `binary`, `xpath`, `json`;
  plugins contribute more — e.g. `timing` provides `delay`). DSL expressions
  are evaluated by the safe parser in `templates/dsl.py`.
  - **Passive templates**: templates with `passive: true` fire during crawl
    (Step 4 in scanner.py) without sending extra requests — they analyze
    responses already fetched. Great for detecting debug modes, API keys, and
    framework fingerprints.
- `darco/plugins/` — scan plugin registry. Built-ins register on import
  (`xml_inject`, `timing`, `evilspider_plugin`); external `*.py` plugins load
  from `--plugin-dir` or `DARCO_PLUGIN_PATH`. Plugins can also register custom
  template types via `template_matcher_types()` / `template_extractor_types()`
  hooks.
  - `evilspider_plugin.py` — wraps `evilspider` CLI as a subprocess, crawling
    the target and importing discovered endpoints, forms, secrets, and security
    signals as Darco findings. Gracefully disables itself if evilspider is not
    installed. Supports proxy via `configure(proxy=...)`.
- `darco/proxy.py` — record-only asyncio forward proxy; HTTPS is tunneled
  (CONNECT), not decrypted.
- `darco/discovery/` — async crawler: same-origin BFS, form/JS/email extraction,
  `robots.txt`/`sitemap.xml` seeding, endpoint inventory + signals. Supports
  `proxy` parameter.
- `darco/cli/` — click CLI wiring, split into focused modules: `_group` (root
  group + `main()`), `_output` (`--format` JSON/md/table contract),
  `_context` (workspace resolution), `_rawio` (raw HTTP serialization),
  `_oneshot` (shared on-the-fly request building), and one `cmd_*` module per
  command family (`send`, `sqli`, `xss`, `auth`, `crawl`, `template`, ...).
  Every command emits JSON to stdout and logs to stderr. Expected failures
  raise `DarcoError` (from `darco/errors.py`).

## Smart Defaults (Opt-Out Architecture)

All scan/audit commands run the FULL audit suite by default. Use `--no-*`
flags to disable individual audits:

- `darco discover <url>` — runs crawl + ALL audits (sqli, xss, fuzz, upload, redirect, traversal, stored-xss, default-creds, passive templates)
- `--no-sqli`, `--no-xss`, `--no-fuzz`, `--no-upload`, `--no-redirect`, `--no-traversal`, `--no-stored-xss` — disable individual audits
- `--plugin NAME` — run only these plugins
- `--skip-plugin NAME` — skip these plugins

**Never make the user type `--sqli --xss --fuzz` to get a full scan — that's
opt-in, user hates it.**

## Proxy Support

- `--proxy http://127.0.0.1:8080` on root CLI group routes all requests through
  a proxy
- Also respects `HTTP_PROXY` / `HTTPS_PROXY` env vars
- Passed through to: engine (`httpx.Client`), discovery crawler, evilspider
  plugin subprocess

## Template Command

- `darco template <url>` — run ALL templates against target
- `darco template <url> sql-error-based` — run specific template
- `darco template <url> --tags exposure` — filter by tag
- `darco template list` — list available templates
- `darco template new <id>` — scaffold new template

**No prefix needed** — `darco template <url>` not `darco template run <url>`.

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
- **Run linters before claiming work is done**: `.venv/bin/python -m ruff check
  darco/` and `.venv/bin/python -m bandit -r darco/`. Fix all medium/high issues.
  For bandit B314/B405/B501 (`xml.etree.ElementTree` on untrusted XML), this is
  intentional in security auditing tools — add `# nosec BXXX` with a comment
  explaining why (attacker-controlled input must be parsed to detect the
  vulnerability).

## Testing expectations

Before finishing a change:

1. Add/update focused unit tests (parsers, mutations, diff, analyze, workspace).
2. Add an integration test if the change touches request flow, discovery, proxy,
   or CLI behavior.
3. Run the full suite with `.venv/bin/python -m pytest -q` and confirm green.
4. Run linters: `.venv/bin/python -m ruff check darco/` and `.venv/bin/python -m bandit -r darco/`.
