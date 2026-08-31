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

## Audit results

Active audit commands return a result model that is serialized to JSON
verbatim (`to_json(model)`).

### `SqliScanResult` (`darco sql`)
`target`, `tested_params`, `vulnerabilities` — `list[SqliFinding]`:
`param`, `param_type` (`query`/`form`/`json`/`xml`), `injection_type`
(`error_based`, `quote_balancing`, `arithmetic_evaluation`,
`boolean_differential`, `sql_logic`, `status_anomaly`,
`xml_entity_decoding`, `xml_encoded_sqli`), `db_engine`, `confidence`
(`confirmed`/`high`/`medium`/`potential`), `payload`, `baseline_status`,
`payload_status`, `evidence`, `suggestion`, `curl` (copy-paste replay
command for manual verification).

- `sql_logic` = OR-injection (`' OR 1=1--`) expanded the result set while the
  `AND 1=2` control shrank/errored it — filter bypass / hidden-data retrieval.
- `xml_entity_decoding` / `xml_encoded_sqli` come from the `xml_inject` scan
  plugin (XML-body endpoints + entity-encoded WAF bypass) — see
  [plugins.md](plugins.md).
- Framework state fields (`__VIEWSTATE`, CSRF tokens, …) are skipped unless
  `include_state_fields=True`; state-validation error pages are never
  classified as SQLi.

### `XssScanResult` (`darco xss`)
`target`, `tested_params`, `reflections` — `list[XssReflection]`: `param`,
`param_type`, `context` (`html_body`/`html_attribute`/`script_context`/…),
`confidence`, `payload`, `unencoded_chars`, `encoded_chars`, `snippet`,
`evidence`, `suggestion`.

### `UploadAuditResult` (`darco upload`)
`target`, `tested_field`, `tests_run`, `accepted_formats`,
`findings` — `list[UploadFinding]` (`param`, `filename`, `content_type`,
`status_code`, `file_url`, `vulnerability_type`, `confidence`, `evidence`,
`suggestion`).

### `LoginAuditResult` (`darco login` / `darco auth`)
`target`, `forms_found` — `list[LoginForm]` (`url`, `action`, `method`,
`username_field`, `password_field`, `csrf_field`, `captcha`), `tested_forms`,
`bypasses` — `list[LoginBypassFinding]` (`param`, `payload`, `confidence`,
`success_indicator` (`redirect_to_account`/`authenticated_content`/
`unexpected_redirect`/`new_session_cookie`/`content_change`), `evidence`,
`suggestion`), `notes`.

### `AutoScanReport` (`darco scan` / `discover --sqli --xss ...`)
`target`, `crawled_endpoints`, `crawled_forms`, `emails` (`list[str]`),
`admin_panels` (`list[AdminPanel]`), `fuzzed_requests`,
`anomalies` (`list[dict]`), `sqli_vulnerabilities`, `xss_reflections`,
`upload_findings`, `login_bypasses`, `technologies`, `wafs`, `findings`.

### `AdminPanelReport` (`darco admin`)
`target`, `scanned_paths`, `panels_found` — `list[AdminPanel]` (`path`, `url`,
`status_code`, `title`, `auth_type` (`exposed_dashboard`/`login_form`/`basic_auth`/`portal_redirect`/`forbidden`),
`redirect_url`, `login_form`), `tested_creds`, `bypasses` (`list[LoginBypassFinding]`),
`emails_used` (`list[str]`), `findings` (`list[Finding]`).

### `TemplateScanReport` (`darco template run`)
`target`, `templates_loaded`, `templates_executed`, `requests_sent`,
`matched_results` — `list[TemplateMatchResult]` (`template_id`, `template_name`,
`severity`, `matched_url`, `matcher_type`, `matched_words`, `extracted_data`,
`curl`, `evidence`, `remediation`, `verified`, `verification`, `access`),
`findings` (`list[Finding]`).

The engine's `Verified` fields capture **smart POC verification**:
- `verified` (bool) — whether an active proof-of-concept proved real access.
- `verification` (str) — human-readable detail of the verification outcome.
- `access` (list[str]) — normalized listing of what access was demonstrated
  (e.g. the exploit steps that succeeded, or `"logged in as 'admin' using leaked
  credential"`).

Templates may attach a `poc:` block (model `TemplatePoC`) with `verify_access`,
`requests` (explicit exploit steps that must all match), `auto_login` (reuse
leaked credential-like secrets against the discovered login form), and
`fails_if_no_credentials`. See `docs/templates.md`.

## Debrief notes

Every emitted payload that Darco can interpret gets a `debrief` object next to
the structured data (both JSON and markdown output):

```json
"debrief": {
  "verdict": "Found 3 potential SQL injection point(s) on ...",
  "highlights": ["`HIGH` — `category` looks injectable via `sql_logic` (...)"],
  "next_steps": ["Replay the probe payloads in a browser/curl ..."]
}
```

Generated by `darco/guidance.py` (`build_notes` / `render_notes`) for `sql`,
`xss`, `fuzz`, `scan`, `login`, `detect`, `passive`, `discover`, and
`analyze`. It reads like a teammate's debrief — what was found, how sure we
are, and exactly how to verify it manually. It never replaces the structured
fields; it annotates them.
