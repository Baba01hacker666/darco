# Smart Fuzz Engine

`darco fuzz` (and `darco send --fuzz`) is the automatic "break things and watch
what changes" layer. It needs **no flags and no recipe definitions** — given a
base request it generates interesting variants and fires them in the background,
then reports only what diverged from the baseline.

Module: `darco/fuzz.py`.

## What it generates (`build_variants`)

For every query param / form field it inspects the value and emits variants:

| Trigger | Variant label | Example |
| --- | --- | --- |
| value is boolean-ish (`true/false/1/0/yes/no/on/off`) | `flip:<name>` | `enabled=true` → `enabled=false` |
| value looks numeric (`id=5`, `page=2`) | `type-confuse:<name>=<word>` | `id=5` → `id=abc`, `id=root`, `id=null` |
| value looks numeric / name is `id/user_id/uid/page/...` | `boundary:<name>=<b>` | `id=5` → `id=0`, `id=-1`, `id=9999999999`, `id=NaN` |
| name is search/filter-like (`q/search/name/username/category/type/filter/tag/sort/status/group/...`) | `sql:<name>` / `xss:<name>` | injects `' OR '1'='1`, `<script>alert(1)</script>`, `${jndi:...}` |
| always | `strip-session` | removes cookies + auth headers (broken-auth probe) |

Duplicates are de-duplicated by label.

Opaque framework state fields (`__VIEWSTATE`, `__EVENTVALIDATION`, CSRF
tokens, …) are skipped by default — tampering with them only produces
framework MAC/validation errors. Pass `include_state_fields=True`
(CLI: `--include-state` on `fuzz`/`sql`/`xss`/`scan`/`discover`) to audit
them explicitly.

## Execution (`run_fuzz`)

- Variants are dispatched concurrently via a `ThreadPoolExecutor`
  (`concurrency` from config, capped at 16).
- The clean request is sent first as the **baseline**.
- Each variant is classified against the baseline by `_classify`:

| Anomaly | When |
| --- | --- |
| `status_change` | variant status differs from baseline (200→500, 403→200, …) |
| `error_leak` | stack trace / SQL / Java exception pattern in body |
| `new_auth_cookie` | a new auth token/credential cookie appeared vs baseline (or a fresh session cookie after `strip-session`; routine session-ID rotation is ignored) |
| `body_changed` | response body similarity < 0.85 (something echoed differently) |
| `request_error` | the variant itself failed to send |

Only anomalies are returned — boring "same as baseline" variants are dropped.

If no baseline is supplied, `run_fuzz` fetches one itself before dispatching
variants, so a server that hands out a fresh session cookie to every anonymous
request doesn't make every variant look like an auth anomaly.

## Config

`[fuzz]` in `darco.toml` / `darco.json`:

```toml
[fuzz]
enabled = true      # master switch for `darco fuzz`
auto = false        # if true, `send` also runs fuzz variants
concurrency = 6
mutations = ["flip", "type_confusion", "boundary", "sql", "xss"]
```

`fuzz.enabled = false` makes `darco fuzz` refuse; pass nothing to force (the
flag was removed in favor of config — set `enabled = true`).

## CLI

```bash
darco fuzz -u https://app.test/user?id=5
darco send -u https://app.test/user?id=5 --fuzz     # send + auto-fuzz
darco fuzz --from 0001 --concurrency 8             # fuzz a stored request
```

Output is Markdown by default (`--json` for the machine contract). Each
interesting result shows **what happened** (the anomaly) and **did** (the
mutations applied) — i.e. "I flipped `enabled`, got status 200 and the debug
secret disappeared."
