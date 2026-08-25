# Diff & Analysis

Two evidence generators: `darco/diff.py` (response comparison) and
`darco/analyze.py` (signal heuristics → `Finding`s).

## Diff engine (`darco/diff.py`)

`diff_responses(a: Response, b: Response) -> dict` compares two **stored**
responses and returns a structured JSON diff:

```json
{
  "status": {"a": 200, "b": 429, "changed": true},
  "headers": [{"name": "retry-after", "a": null, "b": "60"}],
  "body": {
    "changed": true,
    "json": false,
    "added_lines": 2,
    "removed_lines": 1,
    "hunks": ["@@ ...", "-foo", "+bar"],
    "json_changes": null
  },
  "elapsed_ms": {"a": 4, "b": 5},
  "body_len": {"a": 10, "b": 20}
}
```

### Rules

- **Volatile headers** (`date`, `set-cookie`, `age`) are excluded from the
  header diff — they change on every request and would drown real signals.
- **Body normalization** (`normalize_body`) runs before comparing, replacing
  volatile tokens with placeholders:
  - 10–13 digit numbers → `<ts>` (unix timestamps)
  - hex strings ≥ 24 chars → `<hex>` (tokens/ids)
  - `token`/`csrf`/`xsrf`/`nonce` values → `<tok>`
- **JSON bodies**: recursive path diff (`_json_path_diff`) produces
  `path.changed 1 -> 2`, `path.added 3`, `path.removed ...` lines.
- **Text bodies**: `difflib.unified_diff` over normalized lines, capped at 40
  hunks, with added/removed counts.

This is the core "did the mutation change anything?" signal — e.g. OTP
rate-limit `200 -> 429`, or `--strip-session` flipping a guarded response.

## Analyzer (`darco/analyze.py`)

Two entry points:

- `analyze_request(request)` — what to probe:
  - `interesting_param_name`: param names matching
    `admin|debug|bypass|role|verified|is_|enable|allow|flag|token|secret|otp|pin|test|dev|internal`
  - `boolean_param`: value in `true/false/1/0/yes/no/on/off`
  - `interesting_path`: path matching
    `/(admin|internal|debug|backup|api/v\d?|swagger|docs|env|\.git|config|test|dev|console|actuator)`
- `analyze_response(request, response)` — what came back:

| Finding type | Trigger |
| --- | --- |
| `auth_required` | 401/403, or a redirect containing `login`/`signin` |
| `rate_limited` | 429, `Retry-After` header, or rate-limit wording in body |
| `server_anomaly` | status ≥ 500 |
| `error_leak` | stack-trace / SQL / exception patterns (list in `ERROR_PATTERNS`) |
| `captcha` | reCAPTCHA / hCaptcha / Turnstile / Geetest / Cloudflare markers |
| `auth_token_cookie` | `Set-Cookie` name matching `session|token|jwt|auth|sid|remember` |
| `interesting_header` | `server`, `x-powered-by`, `x-backend`, `via`, `www-authenticate`, ... |
| `reflection` | a request param value appears verbatim in the response body |

Severity: `error_leak` = high; most behavioral findings = medium; naming
heuristics = low; info for auth/captcha markers.

`analyze.py` is pure — it never sends requests. The crawler reuses
`analyze_response` per page (wrapping httpx responses via
`_response_from_httpx`), so crawl findings and single-request findings use the
same rules.
