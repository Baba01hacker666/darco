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
| [admin.md](admin.md) | Admin panel finder, auth classification, and smart email credentials (`darco admin`) |
| [templates.md](templates.md) | Nuclei-compatible attack template engine: YAML/JSON syntax, matchers, extractors (`darco template`) |
| [plugins.md](plugins.md) | Scan plugin system: hooks, registry, `xml_inject` WAF-bypass example |
| [development.md](development.md) | Extending Darco: conventions, testing, adding features |

## Quick map

```
darco/
  cli/            click command wiring, one cmd_* module per family, JSON output contract
  models.py       Pydantic v2 data models (Request, Response, ...)
  workspace.py    Workspace storage: history.jsonl, session.json, bodies/
  engine.py       HTTP execution + session capture/replay
  mutate.py       request transforms (strip-session, flip-param, ...)
  fuzz.py         smart variant engine: build_variants, run_fuzz, _classify
  login.py        login form finder + SQL auth-bypass + smart credential generator
  admin.py        admin panel & console discovery + authentication classification
  templates/      Nuclei-compatible attack template engine, matchers, and built-in catalog
  plugins/        scan plugin registry + built-ins (xml_inject, timing); loads external *.py plugins
  xmlinject.py    XML body parsing/entity-encoding primitives
  guidance.py     human-readable debrief notes for structured output
  diff.py         response diffing with volatile-token normalization
  analyze.py      signal heuristics -> Finding objects
  configfile.py   darco.toml / darco.json discovery + load
  proxy.py        record-only asyncio forward proxy
  ingest/         curl / raw HTTP / HAR parsers -> Request
  discovery/      async crawler -> SiteMap (endpoints, forms, JS, emails)
tests/            fixture app + unit/integration tests
```

All commands emit Markdown to stdout by default; `--json` / `-J` emits the
agent contract. Diagnostics go to stderr. Expected failures raise `DarcoError`
and exit `1`.
