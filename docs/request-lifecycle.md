# Request Lifecycle

What happens to one request from ingestion to recorded history.

## 1. Ingest → `Request`

| Source | Module | Notes |
| --- | --- | --- |
| curl command | `ingest/curl.py` | Hand-rolled tokenizer; supports quoting, `-H/-d/-F/-b/-u/-A/-e/-L/-k/-G/-X/-I`, `--data-urlencode`, `--data-json`, `--max-time`. Query string is split into `params`; the URL stored without query. |
| raw HTTP text | `ingest/raw.py` | Parses request line + headers + body. `Cookie` header moves into `request.cookies`. Content-Type drives `body_type` (json/form/raw). |
| HAR file | `ingest/har.py` | One `Request` per entry; `postData.mimeType` drives `body_type`. |
| proxy flow | `proxy.py` | Builds a `Request` with `source="proxy"`, `follow_redirects=False`, raw body preserved byte-for-byte via `body_encoding="latin-1"`. |

## 2. Mutate → modified copy

`mutate.apply_mutations(base, ops)` deep-copies the request, applies each
`Mutation`, and appends human-readable descriptions to `request.mutations`.
The copy keeps `parent_id` pointing at the base record (when sent with
`--from <id>`). See [mutations.md](mutations.md).

## 3. Send → `engine.execute()`

`darco/engine.py:execute()` is the single choke point every path uses
(send, replay, proxy, crawler).

1. **Rebuild URL** — `rebuild_url()` re-encodes `params` into the query string
   (replacing any existing query).
2. **Effective cookies** — `effective_cookies()` merges explicit
   `request.cookies` with session cookies for the host. If
   `request.session_stripped`, **both are dropped**.
3. **Effective headers** — `effective_headers()` starts with the request's
   headers; unless stripped, it injects the host's captured CSRF headers (only
   if the request doesn't already set them), then base headers from
   `workspace.json`. Stripped requests additionally filter out
   `AUTH_HEADER_NAMES` (`authorization`, `cookie`, `x-api-key`, `x-csrf-token`,
   ...).
4. **Body** — `body_type` maps to httpx `json=`, `data=`, or `content=`
   (raw bytes encoded with `body_encoding`).
5. **Execute** — one `httpx.Client` per send
   (`verify=request.verify`, `timeout=request.timeout`, `trust_env=False`,
   cookies on the client instance). Redirects are followed per
   `request.follow_redirects`; the chain is captured from `resp.history`.
6. **Parse response** — status, reason, headers, body text
   (`utf-8` with `errors="replace"`), byte length, elapsed ms, final URL,
   redirects, and `set_cookies` from `resp.cookies.jar` (preserving
   domain/path).

## 4. Session capture → `engine.update_session()`

After a successful send:

- **Cookies**: every `Set-Cookie` is merged into `session.cookies`
  (replace-by-domain+name). Stripped requests never update the session.
- **CSRF headers**: response headers named `x-csrf-token`, `x-xsrf-token`,
  `xsrf-token`, or `csrf-token` are stored per **host** (port stripped) and
  replayed on later requests to that host.

The CLI persists the session after every `send`; the proxy persists after
every flow.

## 5. Record → `workspace.add_history()`

A `HistoryRecord` (id, timestamp, request, response-or-error) is appended to
`history.jsonl`. Bodies larger than 1 MB spill to `bodies/<id>.body`.

## 6. Evidence → diff / analyze / discover

- `darco diff <a> <b>` compares two stored responses
  ([diff-and-analysis.md](diff-and-analysis.md)).
- `darco analyze <id>` runs heuristics over a stored request+response and
  returns findings.
- `darco send --diff <id>` sends, records, then diffs against the stored
  record in one step — the fast loop for "did my mutation change anything?".

## Failure handling

`httpx.HTTPError` (connect refused, timeout, DNS) becomes
`_EngineError` → recorded as `record.error` (no `response`), and `send` exits
`1` after printing `{"id": ..., "error": ...}`. The proxy converts the same
errors into `502 Bad Gateway` to the client.
