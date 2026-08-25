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
5. **Analyze** (`darco/analyze.py`, `darco/diff.py`, `darco/discovery/`):
   derive findings, diffs, and site maps from recorded requests/responses.

## Key cross-cutting rules

- **IDs** are zero-padded sequential (`0001`, `0002`, ...) per workspace.
  Mutated sends keep `parent_id` so the agent can trace request evolution.
- **Body storage**: `history.jsonl` keeps a preview capped at
  `BODY_PREVIEW_CAP` (1 MB); the full body is written to `bodies/<id>.body`.
- **No guardrails**: Darco never enforces scope or approval. Authorization is
  the user's responsibility (see README warning).
- **TLS**: verified by default; `--insecure` / `-k` opts out per request.
  The proxy tunnels HTTPS without decryption in v1.
