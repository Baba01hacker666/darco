# Attack & Vulnerability Scanning Templates

Darco includes a declarative, Nuclei-compatible attack template engine in `darco/templates/`. This allows security engineers and agents to write, execute, and share custom HTTP vulnerability detection templates in YAML or JSON.

## Template Anatomy

```yaml
id: git-config-disclosure
info:
  name: Git Configuration Exposure
  author: darco
  severity: high
  description: Detects publicly accessible .git/config repository files.
  tags: git,config,exposure,vcs
  remediation: Restrict access to all .git directories in web server configuration.

requests:
  - method: GET
    path:
      - "{{BaseURL}}/.git/config"
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
          - "[core]"
          - "repositoryformatversion"
        part: body
        condition: and
    extractors:
      - type: regex
        name: repo_version
        regex:
          - 'repositoryformatversion\s*=\s*([0-9]+)'
```

## Features

### 1. Variables & Dynamic Placeholders
- `{{BaseURL}}`: Full target base URL (e.g. `http://example.com/app`)
- `{{RootURL}}`: Target root URL (`http://example.com`)
- `{{Hostname}}`: Target host and port (`example.com:8080`)
- `{{Host}}`: Target hostname (`example.com`)
- `{{Port}}`: Port number (`8080`, `443`, `80`)
- `{{Scheme}}`: Protocol scheme (`http` or `https`)
- `{{randstr}}`: Random 8-character alphabetic string
- `{{rand_int}}`: Random 6-digit integer
- Custom variables defined in template `variables:` map.

### 2. Matchers
- **Native types:**
  - `status`: Match response HTTP status codes (`status: [200, 301]`)
  - `word`: Match substrings in response (`words: ["admin", "dashboard"]`)
  - `regex`: Match regular expression patterns (`regex: ["root:x:0:0"]`)
  - `size`: Match body length in bytes (`sizes: [1234]`)
  - `dsl`: Nuclei-style boolean expressions (see below)
- **Custom types** (from the registry in `darco/templates/custom.py` and plugins):
  - `binary`: Hex-encoded byte patterns (`binary: ["89504e47"]`)
  - `xpath`: XPath expressions over an XML body (`xpath: ["/users/user[@role='admin']"]`)
  - `json`: JSON key paths with dot notation; pin values with `path=value`
    (`json: ["user.role=admin", "user.tokens.1"]`)
  - `delay`: Response took >= `min_ms` milliseconds (contributed by the
    built-in `timing` plugin — time-based blind detection)
- **Parts:** `body`, `header`, `status`, `all` (default: `body`)
- **Conditions:** `or` (default), `and`
- **Negative:** Set `negative: true` to match if the pattern is NOT found.
- **Matchers Condition:** `matchers-condition: and` / `or` across all declared matchers in a request.

#### DSL expressions

```yaml
matchers:
  - type: dsl
    dsl:
      - "status_code == 200 && contains(body, 'root:') && !contains(header, 'X-Blocked')"
```

Variables: `status_code`, `content_length`, `body`, `header`, `all`, `url`,
`elapsed_ms`. Functions: `contains`, `contains_any`, `startswith`,
`endswith`, `to_lower`, `to_upper`, `len`, `regex`. Operators: `&&`, `||`,
`!`, comparisons, parentheses. Evaluated by a safe parser — no `eval`.

### 3. Extractors
- `regex`: Extract matched regex capture groups into findings (`group: 1`)
- `kval`: Extract specific HTTP response headers
- `json`: Extract JSON properties by key — supports nested dot paths
  (`json: ["user.role", "items.0.id"]`)
- `xpath`: Extract node text from XML bodies (`xpath: ["//title"]`)
- `internal: true`: feed the extracted value as a variable to subsequent
  requests of the same template without showing it in the report output.
  All extractor values are available as `{{name}}` variables to later
  requests — enabling multi-step attack chains (fetch token -> replay).

### 4. Registering your own types

```python
from darco.templates.custom import register_matcher_type

@register_matcher_type("shaprefix")
def match_shaprefix(matcher, resp, elapsed_ms=0.0):
    ...  # return (matched: bool, matched_items: list[str])
```

Scan plugins can do the same via the `template_matcher_types()` /
`template_extractor_types()` hooks (see `darco/plugins/timing.py` for the
`delay` matcher), and external plugin directories loaded with
`--plugin-dir` or `DARCO_PLUGIN_PATH` register automatically on load.

### 5. Smart POC verification (`poc:`)

Detection only proves *something looks off*. By default Darco's template engine
additionally runs a **proof-of-concept** to prove *real access* — this is the
"smart" mode and is **enabled by default**. Two styles are supported, and a
matched template is marked `verified: true` only when access is actually
demonstrated. Detection-only matches (that failed verification) are downgraded
to `low` severity so confirmed findings stand out.

#### Style A — explicit exploit steps

Declare `poc.requests`; every step must match for the finding to be verified:

```yaml
requests:
  - method: GET
    path: ["{{BaseURL}}/.env"]
    matchers:
      - type: word
        words: [DB_PASSWORD]
poc:
  verify_access: true
  requests:
    - method: POST
      path: ["{{BaseURL}}/api/import"]
      body: "token={{db_token}}"
      matchers:
        - type: status
          status: [200]
        - type: word
          words: ["imported"]
          condition: and
```

#### Style B — auto-login with leaked credentials

Set `auto_login: true`. When the matched response leaks credential-like values
(`DB_PASSWORD`, `API_KEY`, `SECRET_KEY`, `DATABASE_URL`, …), the engine
automatically extracts them and reuses them against the target's discovered
login form. If we land in an authenticated state (account redirect, logged-in
markers, or a new session cookie vs. the failed-login baseline), the finding is
verified and the gained access is recorded in the report.

```yaml
requests:
  - method: GET
    path: ["{{BaseURL}}/debug?enabled=true"]
    matchers:
      - type: word
        words: ["SECRET"]
poc:
  verify_access: true
  auto_login: true
```

`poc` keys:
- `verify_access` (bool, default `true`): master switch for active verification.
- `requests` (list): explicit exploit steps that must all match.
- `auto_login` (bool, default `false`): reuse leaked credentials against a login form.
- `fails_if_no_credentials` (bool): if no secrets are found to test, treat the
  match as unverified (this is already the default behavior for `auto_login`).

On each matched finding the engine sets `verified`, `verification` (detail),
and `access` (list of access gained), e.g. `"logged in as 'admin' using leaked
credential"`.

## CLI Commands

```bash
# Run all built-in security templates against a target
darco template run https://target.test

# Run custom templates or an entire directory of templates
darco template run https://target.test -t ./my-templates/

# Filter by tags and severity
darco template run https://target.test --tags config,git --severity high,critical

# Inject extra template variables (usable as {{team}})
darco template run https://target.test --var team=pentest

# Load plugins that contribute custom matcher/extractor types
darco template run https://target.test --plugin-dir ./my-plugins/

# Disable smart POC verification (detection-only)
darco template run https://target.test --no-poc

# List available templates
darco template list

# Scaffold a new template YAML file
darco template new api-token-leak -n "API Token Leak" -s high -p "{{BaseURL}}/api/config" -w "access_token" -o api-token.yaml
```
