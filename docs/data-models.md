# Data Models

All models live in `darco/models.py` and use Pydantic v2. Serialize with
`to_json(model)` (`model_dump(mode="json")`) so enums become strings and all
output is JSON-safe.

## Core request/response

### `Request`
The unit of work. Everything Darco sends is a `Request`.

| Field | Type | Notes |
| --- | --- | --- |
| `method` | `str` | Default `GET` |
| `url` | `str` | **Without** query string; query lives in `params` |
| `headers` | `list[NameValue]` | Ordered, case preserved, duplicates allowed |
| `cookies` | `list[Cookie]` | Explicit cookies for this request |
| `params` | `list[NameValue]` | Query parameters, re-encoded on send |
| `body_type` | `BodyType` | `none` / `json` / `form` / `raw` |
| `body_json` | `Any` | Used when `body_type == json` |
| `body_form` | `list[NameValue]` | Used when `body_type == form` |
| `body_raw` | `str` | Used when `body_type == raw` |
| `body_encoding` | `str` | Wire encoding for raw body (proxy uses `latin-1`) |
| `follow_redirects` | `bool` | Default `True` |
| `timeout` | `float` | Seconds, default `10.0` |
| `verify` | `bool` | TLS verification, default `True` |
| `source` | `str` | `curl` / `raw` / `har` / `proxy` / `manual` / `crawl` |
| `parent_id` | `str \| None` | History id this request evolved from |
| `mutations` | `list[str]` | Human-readable description of applied transforms |
| `session_stripped` | `bool` | When `True`, session cookies + auth headers are dropped |

### `Response`
What the engine returns and stores.

| Field | Type | Notes |
| --- | --- | --- |
| `status_code` | `int` | |
| `reason` | `str` | Reason phrase |
| `headers` | `list[NameValue]` | As received (httpx merges duplicates) |
| `body` | `str` | Text preview; capped in `history.jsonl` |
| `body_len` | `int` | Exact byte length of the raw body |
| `body_file` | `str \| None` | Relative path to the full body in `bodies/` |
| `url` | `str` | Final URL after redirects |
| `elapsed_ms` | `int` | Round-trip time |
| `redirects` | `list[str]` | Redirect chain (when followed) |
| `set_cookies` | `list[Cookie]` | Parsed from `Set-Cookie` |

### `HistoryRecord`
One line of `history.jsonl`.

- `id` — zero-padded sequential (`0001`)
- `ts` — ISO-8601 UTC timestamp
- `request` — the `Request` that was sent
- `response` — `Response | None` (None when the send errored)
- `error` — `str | None` (e.g. `request failed: ...`)

## State

### `WorkspaceConfig` (`workspace.json`)
`target`, `created_at`, `base_headers` (applied to every send unless the
request already has the header), `follow_redirects`, `timeout`, `insecure`.

### `SessionState` (`session.json`)
- `cookies` — `list[Cookie]` with domain/path scoping (merged from
  `Set-Cookie` on every response)
- `csrf_headers` — `dict[str, list[NameValue]]` keyed by **host** (port
  stripped), e.g. `{"127.0.0.1": [NameValue("X-CSRF-Token", "tok123")]}`
- `updated_at`

## Findings & site map

### `Finding`
`id`, `type` (snake_case, e.g. `rate_limited`, `error_leak`, `reflection`,
`captcha`, `boolean_param`, `interesting_path`), `severity`
(`info`/`low`/`medium`/`high`), `location` (request summary), `evidence`
(truncated to 500 chars), `suggestion`, `request_id`.

### `SiteMap` (`sitemap.json`)
- `endpoints` — `list[Endpoint]`: `url` (**path-only**, query merged into
  `params`), `methods`, `params`, `status`, `content_type`, `auth_required`,
  `source` (`link`/`form`/`js`/`robots`/`sitemap`/`seed`), `notes`
- `forms` — `list[Form]`: `action`, `method`, `inputs` (`FormInput`: name,
  type, hidden, default, interesting), `captcha`
- `js_files` — `list[JsFile]`: url + extracted endpoint refs (absolute)
- `signals` — `list[Finding]`
- `robots` — `list[str]` of `Disallow` paths
- `stats` — visited/errors/endpoints/forms/js_files/signals/max_urls_reached

### `NameValue` / `Cookie`
`NameValue` is an ordered `(name, value)` pair used for headers, params, and
form fields. `Cookie` adds `domain` and `path` for scoping.
