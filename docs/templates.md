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
- **Types:**
  - `status`: Match response HTTP status codes (`status: [200, 301]`)
  - `word`: Match substrings in response (`words: ["admin", "dashboard"]`)
  - `regex`: Match regular expression patterns (`regex: ["root:x:0:0"]`)
- **Parts:** `body`, `header`, `status`, `all` (default: `body`)
- **Conditions:** `or` (default), `and`
- **Negative:** Set `negative: true` to match if the pattern is NOT found.
- **Matchers Condition:** `matchers-condition: and` / `or` across all declared matchers in a request.

### 3. Extractors
- `regex`: Extract matched regex capture groups into findings (`group: 1`)
- `kval`: Extract specific HTTP response headers
- `json`: Extract JSON properties by key

## CLI Commands

```bash
# Run all built-in security templates against a target
darco template run https://target.test

# Run custom templates or an entire directory of templates
darco template run https://target.test -t ./my-templates/

# Filter by tags and severity
darco template run https://target.test --tags config,git --severity high,critical

# List available templates
darco template list

# Scaffold a new template YAML file
darco template new api-token-leak -n "API Token Leak" -s high -p "{{BaseURL}}/api/config" -w "access_token" -o api-token.yaml
```
