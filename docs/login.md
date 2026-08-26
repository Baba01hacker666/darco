# Login Finder & SQLi Auth-Bypass Audit

`darco login` (alias `darco auth`) finds login forms on a target and probes
them with classic SQL authentication-bypass payloads — no browser needed.

Module: `darco/login.py`.

## What it does

1. **Find** — fetches the target page plus common auth paths
   (`/login`, `/signin`, `/logon`, `/auth`, `/account/login`, `/admin/login`,
   `/wp-login.php`, …) and picks out login forms (a `type=password` input, or
   an action containing `login`/`signin`/`signon`/`logon`/`auth`).
2. **Map** — for each form it records the username field, password field,
   CSRF token field, and whether a CAPTCHA is present.
3. **Audit** — replays each form with bypass payloads and compares every
   response against a **baseline failed login** (bogus user + wrong password).

## Payloads (`LOGIN_BYPASS_PAYLOADS`)

```python
"' OR 1=1--", "administrator'--", "admin'--",
"' OR '1'='1", "' OR '1'='1'--", "' OR 1=1 #",
"' OR '1'='1' #", '" OR "1"="1', "1' OR '1'='1", "'='"
```

Add your own with `--payload` (repeatable). By default payloads are tried in
the **username** field; `--test-password` also probes the password field
(with `administrator` as the username).

## CSRF & session handling

Before each probe the audit re-fetches the form page, extracts every hidden
input (CSRF tokens, viewstate, …) and includes them in the POST. The HTTP
client keeps the session cookie jar across requests, so token-bound sessions
work without extra setup.

## Success signals

Each payload response is classified against the failed-login baseline, in
strength order:

| Signal | What it means | Confidence |
| --- | --- | --- |
| `redirect_to_account` | Redirect to an account-ish path (`/my-account`, `/dashboard`, …) | high |
| `authenticated_content` | Body contains login keywords (`logout`, `log out`, `sign out`, `welcome`, `logged in`, `my account`, `dashboard`) with no error hints | high |
| `unexpected_redirect` | Redirected where the baseline didn't (and not back to `/login`) | medium |
| `new_session_cookie` | A cookie appeared that the failed-login baseline didn't set | medium |
| `content_change` | Body diverges strongly from the failed-login page without error hints | medium |

For redirect signals the audit **follows the redirect with the session
cookie** and keyword-matches the actual landing page, so the evidence names
exactly which login markers appeared (e.g. `logout, log out, my account`).

## CLI

```bash
darco login https://target/                     # find + audit login forms
darco auth https://target/login                 # alias
darco login https://target/ --find-only         # just enumerate login forms
darco login https://target/login --test-password
darco login https://target/ --payload "' OR 1=1#" --insecure --save
```

Options: `-u/--url`, `--find-only`, `--username`, `--password`, `--payload`,
`--test-password`, `--save`, `--insecure`, `--timeout`.

## Output

`LoginAuditResult` is emitted as JSON (agent contract) or markdown:

- `forms_found` — `LoginForm` list (`url`, `action`, `method`,
  `username_field`, `password_field`, `csrf_field`, `captcha`)
- `tested_forms` — how many forms got probed
- `bypasses` — `LoginBypassFinding` list (`param`, `payload`, `confidence`,
  `success_indicator`, `evidence`, `suggestion`)
- `notes` — e.g. forms with no recognizable credential fields

## Integration

- **`darco scan` / `discover --sqli`** — after crawling, discovered login
  forms are audited automatically; results land in `report.login_bypasses`
  and as `login_sqli_bypass` findings.
- **Crawler** — pages containing a password input get a
  `login_form_detected` signal (`medium`).
- **Debrief** — `build_notes` in `darco/guidance.py` appends a plain-English
  verdict with manual verification steps ("replay the payload in a browser").
