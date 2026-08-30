# Architecture

Darco is a request-engine toolkit for AI-assisted security testing. Its core
idea: give an agent a durable, inspectable "session lab" for a target —
capture requests from multiple sources, replay them with mutations, and get
structured evidence (diffs, findings, site maps) back as JSON.

## Design goals

- **Agent contract is JSON on stdout.** Every CLI command returns structured
  data; nothing human-oriented pollutes it.
- **Per-target workspace.** State is durable on disk (`*.darco/` dir), so an
  agent can run commands across invocations and diff its own progress.
- **Session is stateful by default.** `Set-Cookie` and CSRF headers are
  captured from responses and replayed automatically — unless a mutation
  explicitly strips them (`--strip-session`).
- **Mutations are non-destructive.** Every transform produces a *copy* of a
  request with lineage (`parent_id` + description list), never an in-place edit.
- **Output is annotated, not replaced.** Structured JSON stays the contract;
  `darco/guidance.py` adds a human-readable `debrief` block (verdict,
  highlights, next steps) so output also reads like a teammate's notes.

## Module map

```
                    ┌──────────────┐
  curl command ────▶│ ingest/      │
  raw HTTP ────────▶│ (curl/raw/   │
  HAR file ────────▶│  har)        │
  live proxy ──────▶│ proxy.py     │  ─┐
  crawler ─────────▶│ discovery/   │   │ Request models
                    └──────┬───────┘   │
                           ▼           │
                    ┌──────────────┐   │
                    │ mutate.py    │   │ copies + lineage
                    └──────┬───────┘   │
                           ▼           ▼
                    ┌──────────────────────────┐
                    │ fuzz.py                  │
                    │ smart variant engine     │
                    │ (background anomaly scan)│
                    └──────┬───────────────────┘
                           ▼
                           ▼
                    ┌──────────────────────────┐
                    │ engine.py                │
                    │  httpx client + session  │──▶ target
                    │  capture (cookies/CSRF)  │
                    └──────┬───────────────────┘
                           ▼
                    ┌──────────────────────────┐
                    │ workspace.py             │
                    │ history.jsonl + bodies/  │
                    │ session.json             │
                    └──────┬───────────────────┘
                           ▼
        ┌──────────────────┼───────────────────┐
        ▼                  ▼                   ▼
   diff.py           analyze.py          discovery/
   response diff      findings           sitemap.json
```

## The request pipeline

1. **Ingest** (`darco/ingest/`, `darco/proxy.py`): turn external formats
   (curl, raw HTTP, HAR, proxied traffic) into a `Request` model.
2. **Mutate** (`darco/mutate.py`): apply transforms to a deep copy; record what
   changed in `request.mutations`.
3. **Send** (`darco/engine.py`): merge session state (cookies, CSRF headers,
   base headers), execute with httpx, parse the response, capture new session
   state.
4. **Record** (`darco/workspace.py`): append a `HistoryRecord` to
   `history.jsonl`; write oversized bodies to `bodies/`.
5. **Fuzz** (`darco/fuzz.py`): `build_variants` turns a request into smart
   mutations (flip booleans, type-confuse numerics, boundary IDs, SQL/XSS);
   `run_fuzz` fires them concurrently and classifies anomalies vs baseline.
6. **Audit** (`darco/sqli.py`, `darco/xss.py`, `darco/login.py`,
   `darco/upload.py`): active SQLi/XSS/auth-bypass/upload probes over a
   baseline response, returning typed result models. `scan_sqli` dispatches
   to registered scan plugins (`darco/plugins/`) for extra parameters and
   channel-specific probes — see [plugins.md](plugins.md).
7. **Analyze** (`darco/analyze.py`, `darco/diff.py`, `darco/discovery/`):
   derive findings, diffs, and site maps from recorded requests/responses.

## Audit modules

| Module | Command | What it probes |
| --- | --- | --- |
| `darco/sqli.py` | `darco sql` | Quote balancing, arithmetic evaluation, boolean differential, OR-logic / hidden data (`sql_logic`), DB error leaks |
| `darco/plugins/` | `darco plugins` | Scan plugin registry + hooks; `xml_inject` (XML entity SQLi), `timing` (delay matcher). External `*.py` plugins via `--plugin-dir` / `DARCO_PLUGIN_PATH`; plugins can register custom template types |
| `darco/xmlinject.py` | — | Low-level XML parse / entity-encode / behavioral probes used by `xml_inject` |
| `darco/xss.py` | `darco xss` | Parameter reflection, context classification, encoding audit |
| `darco/login.py` | `darco login` / `darco auth` | Login form discovery + SQL auth-bypass payloads |
| `darco/upload.py` | `darco upload` | File-upload MIME/extension/header defenses |
| `darco/fuzz.py` | `darco fuzz` | Smart mutation dispatch + anomaly classification |
| `darco/state_fields.py` | — | Shared skip-list for framework state fields + validation-error signatures |

`darco/guidance.py` turns any of these result models into a `debrief` block.

## Key cross-cutting rules

- **IDs** are zero-padded sequential (`0001`, `0002`, ...) per workspace.
  Mutated sends keep `parent_id` so the agent can trace request evolution.
- **Body storage**: `history.jsonl` keeps a preview capped at
  `BODY_PREVIEW_CAP` (1 MB); the full body is written to `bodies/<id>.body`.
- **No guardrails**: Darco never enforces scope or approval. Authorization is
  the user's responsibility (see README warning).
- **TLS**: verified by default; `--insecure` / `-k` opts out per request.
  The proxy tunnels HTTPS without decryption in v1.
