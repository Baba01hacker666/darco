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

## Quickstart (OTP rate-limit bypass scenario)

```bash
# 1. Create a workspace for the target
darco init http://target.test

# 2. Agent hands over a curl command; Darco parses it into history id 0001
darco ingest curl "curl -X POST http://target.test/otp -d otp_code=000000"

# 3. Send it (session is captured automatically)
darco send --from 0001

# 4. Repeat a few times; Darco flags the rate limit
darco analyze 0003            # -> rate_limited finding (429 / Retry-After)

# 5. The Burp-style trick: replay WITHOUT the session
darco send --from 0003 --strip-session

# 6. Compare the two responses
darco diff 0003 0004
```

Other mutation primitives:

```bash
darco send --from 0001 --flip-param enabled            # true -> false, 1 -> 0
darco send --from 0001 --set-header X-Admin: 1
darco send --from 0001 --unset-header Authorization
darco send --from 0001 --set-param user=admin
darco send --from 0001 --unset-param otp_code
darco send --from 0001 --modify-file ops.json          # JSON list of mutation ops
```

## Command reference

| Command | Purpose |
| --- | --- |
| `darco init <target>` | Create a workspace (`<host>.darco/`) |
| `darco ingest curl "<curl ...>"` | Parse a curl command into history |
| `darco ingest raw <file>` | Parse a raw HTTP request (Burp style) |
| `darco ingest har <file>` | Import requests from a HAR file |
| `darco send --from <id>` | Send a stored request (or `--curl`, `--raw-file`) |
| `darco diff <idA> <idB>` | Structured response diff (status/headers/body/JSON) |
| `darco analyze <id>` | Signals: reflections, error leaks, rate limits, CAPTCHA, auth cookies |
| `darco proxy --port 8080` | Record-only forward proxy; flows land in history |
| `darco discover <url>` | Crawl & parse: endpoints, forms, JS refs, robots, signals |
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

## Design notes

- **Session state**: `Set-Cookie` and CSRF headers (`X-CSRF-Token`, `X-XSRF-TOKEN`,
  `csrf-token`) are captured from responses and replayed on subsequent requests.
  `--strip-session` removes cookies and auth headers for a single request — the
  primitive behind session-removal bypasses.
- **Lineage**: every mutated send records `parent_id` and the applied mutation
  list, so agents can trace how a request evolved.
- **Proxy**: `darco proxy` is record-only in v1. Plain HTTP is forwarded through
  the engine and recorded; HTTPS is tunneled (CONNECT) and noted as a tunnel
  event, not decrypted.
- **Discovery**: same-origin crawl with depth/URL caps, form + hidden-input
  parsing, JS endpoint extraction, `robots.txt`/`sitemap.xml` seeding, and
  signal heuristics (boolean-ish params, sensitive paths, CAPTCHA, error leaks,
  rate limits).
- **Output**: JSON on stdout by default (the agent contract); logs on stderr.

## Development

```bash
.venv/bin/python -m pytest -q
```

Tests spin up a local fixture app (login, OTP with rate limiting, CSRF echo,
CAPTCHA, error leaks) and exercise ingest, session capture, mutations,
diffing, proxy recording, discovery, and the CLI end-to-end.

## Roadmap

- v2: playbooks — auto-suggested mutation recipes (OTP bypass, session removal)
  generated from signals.
- v3: targeted fuzzer with rate-limit-aware strategies.
- v4: MCP server + optional `--scope` allowlist.
