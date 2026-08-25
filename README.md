# Darco

Darco is a CLI-first HTTP toolkit that gives AI agents (and humans) Burp-style
control over web requests during authorized security testing. Agents can feed
it requests from curl commands, raw HTTP text, HAR files, or a live recording
proxy; Darco keeps per-target session state, replays and mutates requests,
diffs and analyzes responses, and runs crawl-based discovery — all stored in a
per-target workspace that an agent can inspect and resume.

**v1 scope:** request engine core (ingest → session → send/modify → diff/analyze),
recording proxy, and the `discover` module. Mutation playbooks and fuzzing come
in later slices.

> ⚠️ Darco is a pentest tool. It has **no guardrails** by design: you own
> authorization. Only use it against targets you are explicitly permitted to test.

## Documentation

Detailed docs on how Darco works internally live in
[`docs/`](docs/README.md): architecture, data models, workspace layout,
request lifecycle, the mutation engine, diff/analysis heuristics, the proxy,
the crawler, and a development guide.

## Install

```bash
python3 -m venv .venv
.venv/bin/pip install -e .
darco --help
```

## Quickstart & Direct Execution

Hit any URL directly — no `init` or `send` subcommand required:

```bash
# 1. Direct one-shot request (curl / httpie style)
darco https://target.test/api/user -X POST -d "user=admin"
darco -u https://target.test/login

# 2. Replay stored requests or auto-fuzz directly
darco 0001 --strip-session
darco https://target.test/debug?enabled=true --fuzz

# 3. Direct crawl discovery (auto-creates workspace)
darco discover https://target.test
```

### Burp-style Workspace Testing:

```bash
# 1. Create a workspace for the target
darco init http://target.test

# 2. Agent hands over a curl command; Darco parses it into history id 0001
darco ingest curl "curl -X POST http://target.test/otp -d otp_code=000000"

# 3. Send it (session is captured automatically)
darco 0001

# 4. Repeat a few times; Darco flags the rate limit
darco analyze 0003            # -> rate_limited finding (429 / Retry-After)

# 5. The Burp-style trick: replay WITHOUT the session
darco 0003 --strip-session

# 6. Compare the two responses
darco diff 0003 0004
```

Other mutation primitives:

```bash
darco 0001 --flip-param enabled            # true -> false, 1 -> 0
darco 0001 --set-header X-Admin: 1
darco 0001 --unset-header Authorization
darco 0001 --set-param user=admin
darco 0001 --unset-param otp_code
darco 0001 --modify-file ops.json          # JSON list of mutation ops
```

## Smart Fuzz Engine, Config Files, & Direct Mode

```bash
# One-shot: hit a URL directly, no workspace / init needed
darco https://app.test/admin
darco -u https://app.test/admin
darco fuzz https://app.test/user?id=5        # auto-mutate & report anomalies

# Smart defaults: fuzz is automatic on --fuzz (flip booleans, type-confuse
# numbers with words, boundary IDs, SQL/XSS probes) and fires in the background
darco https://app.test/user?id=5 --fuzz

# Config file (darco.toml / darco.json) drives target, format, base headers,
# and fuzz behavior — no flags needed every run
darco fuzz          # reads ./darco.toml
```

## Command reference

| Command | Purpose |
| --- | --- |
| `darco <url>` / `darco -u <url>` | Direct request execution (curl / httpie style) |
| `darco <id>` / `darco send [id\|url]` | Send or replay a request (with mutations like `--strip-session`, `--flip-param`) |
| `darco passive [domain\|url]` | Passive OSINT: DNS records, SPF/DMARC email posture, CT log subdomains, security.txt, security headers |
| `darco detect [url\|id]` | Detect WAF shields and web technologies (servers, frameworks, CMS, frontend) |
| `darco waf [url\|id]` | Inspect active WAF / CDN shields protecting the target |
| `darco tech [url\|id]` | Fingerprint web servers, languages, frameworks, CMS, and frontend libraries |
| `darco fuzz [url\|id]` | Smart-default fuzz: flip booleans, type-confuse numerics, boundary IDs, SQL/XSS; report anomalies |
| `darco discover [url]` | Crawl & parse: endpoints, forms, JS refs, robots, technologies, WAFs, signals |
| `darco init <target>` | Create a workspace (`<host>.darco/`) |
| `darco ingest curl "<curl ...>"` | Parse a curl command into history |
| `darco ingest raw <file>` | Parse a raw HTTP request (Burp style) |
| `darco ingest har <file>` | Import requests from a HAR file |
| `darco repeat <id> --count N` | Replay a stored request N times (rate-limit / OTP loops) |
| `darco diff <idA> <idB>` | Structured response diff (status/headers/body/JSON) |
| `darco analyze <id> [--save]` | Signals: reflections, error leaks, rate limits, CAPTCHA, auth cookies, WAF & tech detections; `--save` persists to `findings.json` |
| `darco findings list\|clear` | Inspect or wipe the workspace's accumulated findings |
| `darco proxy --port 8080` | Record-only forward proxy; flows land in history |
| `darco status` / `darco session list\|clear` | Inspect or reset session state |
| `darco export <id> [--raw]` | Export a request for Burp/curl round-trips |

Workspace layout:

```
target.test.darco/
  workspace.json    # config (base headers, redirects, timeout)
  session.json      # cookies + CSRF headers, updated on every send
  history.jsonl     # request/response records (ids 0001, 0002, ...)
  bodies/           # full response bodies
  findings.json     # accumulated signals
  sitemap.json      # discovery output
```

## Configuration

Darco reads an optional `darco.toml` / `.darco.toml` / `darco.json` from the
current directory (`--config <path>` overrides):

```toml
target = "https://app.test"
format = "md"                       # md | json | table (default md)

[fuzz]
enabled = true                     # master switch for `darco fuzz`
auto = false                       # if true, `send` also runs fuzz variants
concurrency = 6
mutations = ["flip", "type_confusion", "boundary", "sql", "xss"]

headers = ["X-API-Key: deadbeef"]  # base headers on every request
follow_redirects = true
timeout = 10.0
insecure = false
```

## Design notes

- **Session state**: `Set-Cookie` and CSRF headers (`X-CSRF-Token`, `X-XSRF-TOKEN`,
  `csrf-token`) are captured from responses and replayed on subsequent requests.
  `--strip-session` removes cookies and auth headers for a single request — the
  primitive behind session-removal bypasses.
- **Smart fuzz engine**: `darco fuzz` (and `send --fuzz`) builds variants with
  zero configuration — it flips boolean params, **puts words into numeric fields**
  (type confusion), tries boundary IDs (`0`, `-1`, `9999999999`, `NaN`), and
  injects SQL/XSS probes into search-like params. Variants fire concurrently in
  the background and are classified against the baseline: status flips
  (200→500, 403→200), big body changes, error/stack-trace leaks, and new
  auth-cookie issuance all surface as "interesting". See `darco/fuzz.py`.
- **Lineage**: every mutated send records `parent_id` and the applied mutation
  list, so agents can trace how a request evolved.
- **Proxy**: `darco proxy` is record-only in v1. Plain HTTP is forwarded through
  the engine and recorded; HTTPS is tunneled (CONNECT) and noted as a tunnel
  event, not decrypted.
- **Discovery**: same-origin crawl with depth/URL caps, form + hidden-input
  parsing, JS endpoint extraction, `robots.txt`/`sitemap.xml` seeding, and
  signal heuristics (boolean-ish params, sensitive paths, CAPTCHA, error leaks,
  rate limits).
- **Repeat**: `darco repeat <id> --count N` replays a stored request N
  times (with optional `--strip-session`/`--set-param`/interval) — the
  rate-limit and OTP-verification loop without re-typing the request.
- **Persistent findings**: `darco analyze <id> --save` accumulates
  `Finding`s into `findings.json` (deduped); `darco findings list|clear`
  inspect them. The crawler's signals also land here.
- **Output**: Markdown on stdout by default (human contract); `--json` / `-J`
  emits the machine contract for agents. Logs go to stderr.

## Development

```bash
.venv/bin/python -m pytest -q
```

Tests spin up a local fixture app (login, OTP with rate limiting, CSRF echo,
CAPTCHA, error leaks) and exercise ingest, session capture, mutations,
diffing, proxy recording, discovery, fuzzing, and the CLI end-to-end.

## Roadmap

- v1: request engine core (ingest → session → send/modify → diff/analyze),
  recording proxy, `discover`, `repeat`, persistent findings.
- v2 (done): **smart fuzz engine** (`darco fuzz` / `send --fuzz`) with
  automatic param mutation + background anomaly detection; **config files**
  (`darco.toml`) for target/format/headers/fuzz defaults; **on-the-fly mode**
  (`-u`) with no workspace needed; **markdown-default** output.
- v3: MCP server + optional `--scope` allowlist.
