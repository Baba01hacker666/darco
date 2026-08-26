# Discovery (Crawler)

`darco discover <url>` crawls a same-origin target and produces a `SiteMap`
(endpoints, forms, JS endpoint refs, signals) saved to `sitemap.json` and
printed as JSON. It is a **crawl-and-parse** engine: no wordlists, no
brute-force — just structured recon an agent can act on.

Module: `darco/discovery/` — `crawler.py` (orchestration), `parsers.py`
(HTML), `js_extractor.py` (JS endpoint regexes).

## Pipeline

1. **Normalize** the start URL (`normalize_url`): keep scheme/host/path/query,
   drop fragments and default ports.
2. **Seed sources** (`_load_seeds`, async, best-effort):
   - `robots.txt` → `Disallow` paths become endpoints with `source="robots"`
     and note `path listed in robots.txt (Disallow); not crawled` (they are
     **not** fetched).
   - `sitemap.xml` → `<loc>` URLs become crawl seeds.
   - `--seed <file>` lines are added as additional seeds.
3. **BFS with a worker pool**: `asyncio.Queue[(url, depth)]` + N worker tasks
   (default 5). A `pending` counter + `queue.empty()` guard prevents the
   classic worker-exit race: a worker only exits when nothing is in flight and
   nothing is queued.
4. **Per page** (`_process`):
   - fetch with `follow_redirects=True` (final URL becomes the base),
   - record/merge the endpoint (`_endpoint_key` = **path-only**, so
     `/debug?enabled=true` and `/debug?enabled=false` merge into one endpoint
     with `params=[enabled]`),
   - capture status, content-type, `auth_required` (401/403 or
     login redirect), 429 → `rate_limited` signal,
   - if HTML: parse links + meta-refresh (same-origin only, enqueued up to
     `--depth`), forms (action/method/inputs incl. hidden fields + CAPTCHA
     marker), and `script[src]` (same-origin JS fetched and scanned),
   - forms with a `type=password` input raise a `login_form_detected`
     signal (`medium`) pointing at the form action,
   - page-level signals from `analyze_response` + path heuristics.
5. **Limits**: `--depth` (default 3), `--max-urls` (default 500, stops
   enqueueing new children once reached — in-flight queue is drained, not
   abandoned), `--workers`.

## Parsers (`parsers.py`)

| Function | Extracts |
| --- | --- |
| `extract_links` | `<a>`/`<area href>` + `<iframe>`/`<frame src>`, resolved with `urljoin` |
| `extract_meta_refresh` | `http-equiv=refresh` `content="N; url=..."` |
| `extract_scripts` | `script[src]` URLs |
| `extract_forms` | `Form` with all `<input>` (type/hidden/default), `<select>`, `<textarea>`; CAPTCHA detection on the form markup |
| `is_html` | content-type contains `html` or body starts with `<!doctype`/`<html` |

## JS extraction (`js_extractor.py`)

Regex patterns over fetched JS text:

- `fetch(...)` / `axios.get|post|put|delete|patch|head(...)`
- `new WebSocket(...)`
- `url:` / `url=` string literals
- bare literals matching `/api|v\d|admin|internal|ws|graphql|rest...` or
  `*.php|asp|aspx|jsp|json`

Filters: skips template strings (`${...}`), `data:`/`javascript:`/`blob:`,
CDN `//host` refs, and asset extensions. Reflected refs are resolved against
the JS file URL and recorded as absolute endpoints (`source="js"`).

## Output

`SiteMap.stats` reports visited/errors/endpoints/forms/js_files/signals and
`max_urls_reached`. Signals are also appended to `findings.json` (deduped) by
`workspace.add_findings()`. The CLI prints the full sitemap JSON to stdout —
the agent's recon contract.
