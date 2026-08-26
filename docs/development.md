# Development

How to extend Darco without breaking its contracts.

## Environment

```bash
python3 -m venv .venv
UV_CACHE_DIR=/tmp/uv-cache uv pip install --python .venv/bin/python -e . pytest
.venv/bin/python -m pytest -q
```

- Python ≥ 3.11; deps are `httpx`, `pydantic>=2`, `click`, `beautifulsoup4`.
- No formatter/linter is configured. Match the existing style: type hints on
  public functions, Pydantic models for any new persisted structure, JSON-safe
  output.

## Adding a feature — where it goes

| Change | Module |
| --- | --- |
| New curl flag | `darco/ingest/curl.py` (add to flag sets + `apply_value_flag`) |
| New request shape/field | `darco/models.py` + serialization test |
| New mutation op | `darco/mutate.py` (op handling + `describe()`) + CLI flag in `darco/cli.py` |
| New finding heuristic | `darco/analyze.py` |
| New crawl signal | `darco/discovery/crawler.py` or `darco/analyze.py` |
| New fuzz variant | `darco/fuzz.py` (`build_variants`) + `tests/test_fuzz.py` |
| New SQLi heuristic | `darco/sqli.py` (`scan_sqli`, add a test in `tests/test_sqli.py`) |
| New audit command | `darco/<name>.py` (typed result model in `models.py`) + CLI command in `darco/cli.py` + md renderer in `darco/render.py` + debrief notes in `darco/guidance.py` |
| New login/auth logic | `darco/login.py` + `tests/test_login.py` |
| New CLI command | `darco/cli.py` (markdown to stdout by default, `--json` for the agent contract; `DarcoError` on failure) |
| Persistent findings | `darco/analyze.py` (`analyze --save`) + `darco/cli.py` (`findings` group) + `workspace.add_findings` |
| Proxy behavior | `darco/proxy.py` (keep `_serialize` hop-by-hop rules intact) |

## Contracts to preserve

1. **stdout = markdown by default, `--json`/`‑J` = agent contract; stderr = logs.** Never `print()` diagnostics to stdout.
2. **`DarcoError` for expected failures.** The CLI wrapper in `main()`
   converts it to `error: ...` on stderr and exit `1`. Don't let tracebacks
   escape for expected conditions.
3. **Ids via `workspace.next_id()`.** Never hand-roll record ids.
4. **Bodies: preview in `history.jsonl`, full body in `bodies/`.**
5. **Non-destructive mutations**: `apply_mutations` returns a deep copy with
   lineage; original requests are immutable after ingest.
6. **Session updates only through `engine.update_session`.** Cookie/CSRF
   capture must stay in one place (or the proxy/crawler/CLI diverge).
7. **No guardrails.** Do not add scope enforcement, rate limiting, or approval
   gates to Darco core without an explicit user request.
8. **Human debriefs come last, never instead.** Add `build_notes` support in
   `darco/guidance.py` for new audit commands so output stays both machine-
   readable and human-helpful. Do not overwrite existing result fields
   (`debrief` is the reserved key — model fields named `notes` must survive).

## Testing

- **Unit tests** (`tests/test_ingest.py`, `test_mutate.py`,
  `test_diff_analyze.py`, `test_workspace.py`) are dependency-light and run
  anywhere.
- **Integration tests** (`test_engine.py`, `test_proxy.py`,
  `test_discovery.py`, `test_cli.py`) spin up the fixture app in
  `tests/conftest.py` — a stdlib `ThreadingHTTPServer` with:
  - `/login` (session cookie), `/otp` (rate limit after 3 attempts per
    cookie bucket), `/csrf` (X-CSRF-Token header),
  - `/debug?enabled=` boolean reflection, `/error` (stack trace),
    `/captcha`, `/robots.txt`, `/js/app.js` (endpoint refs), `/echo`.
- **Audit tests** (`test_sqli.py`, `test_xss.py`, `test_login.py`,
  `test_upload.py`, `test_fuzz.py`, `test_guidance.py`) cover heuristics and
  output contracts with mocked HTTP plus the fixture app.
- These bind `127.0.0.1` sockets — sandboxed environments may need bind/network
  permission.
- Add a test for **every** new parser flag, mutation op, and signal heuristic;
  add an integration test whenever request flow, proxy, discovery, or CLI
  behavior changes.

## Roadmap hooks

- **v2 fuzz engine (done)**: `darco/fuzz.py` builds smart variants (flip,
  type-confuse numerics, boundary IDs, SQL/XSS) and fires them concurrently;
  `_classify` surfaces status flips, body changes, error leaks, and new
  auth-cookie issuance. `tests/test_fuzz.py` covers it.
- **v3 MCP server**: wrap the CLI commands as MCP tools; keep the JSON
  contract as the wire format.
