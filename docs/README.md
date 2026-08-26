# Darco Documentation

Guides to how Darco works internally. Start with
[architecture.md](architecture.md) for the big picture, then dive into the area
you care about.

## Index

| Doc | What it covers |
| --- | --- |
| [architecture.md](architecture.md) | System overview, module map, request data flow |
| [data-models.md](data-models.md) | Every Pydantic model and what it holds |
| [workspace.md](workspace.md) | The per-target workspace: history, session, findings, sitemap |
| [request-lifecycle.md](request-lifecycle.md) | Ingest → mutate → send → record: one request's journey |
| [mutations.md](mutations.md) | The mutation engine: ops, lineage, flip semantics |
| [diff-and-analysis.md](diff-and-analysis.md) | Response diffing and signal/finding heuristics |
| [proxy.md](proxy.md) | The record-only forward proxy: HTTP + CONNECT tunneling |
| [discovery.md](discovery.md) | The async crawler: BFS, seeds, parsing, endpoint inventory |
| [fuzz.md](fuzz.md) | Smart fuzz engine: build_variants, background dispatch, anomaly classification |
| [login.md](login.md) | Login form finder + SQLi auth-bypass audit (`darco login`) |
| [development.md](development.md) | Extending Darco: conventions, testing, adding features |

## Quick map

```
darco/
  cli.py          click command wiring, JSON output contract
  models.py       Pydantic v2 data models (Request, Response, ...)
  workspace.py    Workspace storage: history.jsonl, session.json, bodies/
  engine.py       HTTP execution + session capture/replay
  mutate.py       request transforms (strip-session, flip-param, ...)
  fuzz.py         smart variant engine: build_variants, run_fuzz, _classify
  login.py        login form finder + SQL auth-bypass audit
  guidance.py     human-readable debrief notes for structured output
  diff.py         response diffing with volatile-token normalization
  analyze.py      signal heuristics -> Finding objects
  configfile.py   darco.toml / darco.json discovery + load
  proxy.py        record-only asyncio forward proxy
  ingest/         curl / raw HTTP / HAR parsers -> Request
  discovery/      async crawler -> SiteMap
tests/            fixture app + unit/integration tests
```

All commands emit Markdown to stdout by default; `--json` / `-J` emits the
agent contract. Diagnostics go to stderr. Expected failures raise `DarcoError`
and exit `1`.
