# The Workspace

A workspace is a directory (default `<host>.darco/`) that holds everything
Darco knows about one target. Created by `darco init <target>`. Every command
auto-detects the single `*.darco` dir in the CWD, or you can pass
`--workspace <path>` explicitly.

```
target.test.darco/
  workspace.json    # WorkspaceConfig
  session.json      # SessionState (cookies + CSRF headers)
  history.jsonl     # append-only HistoryRecord lines
  bodies/           # full response bodies: <id>.body
  findings.json     # accumulated Finding list
  sitemap.json      # latest SiteMap from discover
```

## `Workspace` class (`darco/workspace.py`)

### Creation & open
- `Workspace.create(target, path, ...)` builds the layout and writes an empty
  `SessionState`. Refuses to overwrite an existing `workspace.json`.
- `Workspace.open(path)` validates `workspace.json` exists and seeds the record
  counter from the number of non-empty lines in `history.jsonl`.

### History ids
- `next_id()` **reserves** an id by incrementing the counter and returning
  `f"{count:04d}"` (`0001`, `0002`, ...).
- `add_history(record)` appends a JSON line and syncs the counter with
  `max(counter, int(record.id))` — so records written with explicit ids keep
  the sequence sane.
- `get_record(id)` / `iter_records()` / `list_records()` read back records.
  Unknown ids raise `DarcoError`.

### Body preview vs. full body
`history.jsonl` must stay lean for agents. When a response body exceeds
`BODY_PREVIEW_CAP` (1,000,000 bytes):

1. the full bytes are written to `bodies/<id>.body`,
2. `response.body_file` is set to that relative path,
3. `response.body` holds the first 1 MB plus a
   `...[truncated N bytes; full body in bodies/<id>.body]` marker.

### Session persistence
- `load_session()` / `save_session()` round-trip `SessionState` from
  `session.json`. A corrupt/missing file falls back to an empty session.
- `merge_cookies(base, incoming, host)` merges `Set-Cookie` results,
  **replacing by `(domain, name)`** — a refreshed cookie value supersedes the
  old one instead of accumulating.

### Findings
- `load_findings()` / `save_findings()` / `add_findings()`.
- `add_findings` deduplicates on `(type, location, evidence)` and returns how
  many new findings were added — so re-running `discover` never duplicates
  the signal store.

### Status
`status()` summarizes the workspace for agents: path, target, history count,
cookie names + domains, CSRF hosts, findings count, whether a sitemap exists.

## Concurrency

v1 is single-process: no locking. Don't run two commands against the same
workspace concurrently — the proxy is the only long-running process and it owns
its workspace while running.
