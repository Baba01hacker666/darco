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
| New CLI command | `darco/cli.py` (JSON to stdout, `DarcoError` on failure) |
| Proxy behavior | `darco/proxy.py` (keep `_serialize` hop-by-hop rules intact) |

## Contracts to preserve

1. **stdout = JSON, stderr = logs.** Never `print()` diagnostics to stdout.
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
- These bind `127.0.0.1` sockets — sandboxed environments may need bind/network
  permission.
- Add a test for **every** new parser flag, mutation op, and signal heuristic;
  add an integration test whenever request flow, proxy, discovery, or CLI
  behavior changes.

## Roadmap hooks

- **v2 playbooks**: build on `mutate.py` — auto-suggest `Mutation` lists from
  `analyze.py` findings (e.g. `rate_limited` → try `strip_session`).
- **v3 fuzzer**: reuse `rebuild_url`/body construction and the diff engine to
  detect response divergence per payload.
- **v4 MCP server**: wrap the CLI commands as MCP tools; keep the JSON
  contract as the wire format.
