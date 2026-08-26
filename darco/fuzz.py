from __future__ import annotations

"""Smart default fuzzing engine.

Given a base Request, ``build_variants`` produces a set of interesting mutated
requests WITHOUT the user specifying anything (flip booleans, type-confuse
numeric fields with words, boundary IDs, SQL/XSS probe strings). ``run_fuzz``
fires them concurrently ("in the background") via ``engine.execute`` and
classifies each response against the baseline so the interesting ones surface:

    - status change vs baseline (200 -> 500, 403 -> 200, etc.)
    - big body-length delta (content changed / leaked)
    - new auth-like cookie appeared
    - error/stack-trace leak in body
    - response body differs from baseline (normalized)
"""

import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from difflib import SequenceMatcher

from . import mutate as _mutate
from .engine import execute
from .models import NameValue, Request, Response, SessionState
from .mutate import Mutation
from .state_fields import is_state_field

BOOLEAN_VALUES = {"true", "false", "1", "0", "yes", "no", "on", "off"}
SQL_PROBES = ["' OR '1'='1", "1' OR '1'='1' --", "admin'--", "1; DROP TABLE users--"]
XSS_PROBES = [
    "<script>alert(1)</script>",
    '"><svg/onload=alert(1)>',
    "${jndi:ldap://x/}",
]
BOUNDARY_IDS = ["0", "-1", "9999999999", "1e9", "NaN", "0000001", "1.0"]
TYPE_CONFUSION_WORDS = [
    "abc",
    "xyz",
    "root",
    "admin",
    "NaN",
    "null",
    "true",
    "[]",
    "{}",
]

ERROR_PATTERNS = [
    r"Traceback \(most recent call last\)",
    r"SQL syntax",
    r"You have an error in your SQL",
    r"Fatal error",
    r"Unhandled Exception",
    r"Undefined variable",
    r"syntax error",
    r"java\.lang\.",
    r"NullPointerException",
    r"Stack trace",
    r"Exception in thread",
]
# Strong auth indicators: a brand-new token/credential cookie is always
# interesting, unlike session-ID cookies which rotate on every anonymous
# request on classic ASP / PHP targets.
AUTH_COOKIE = re.compile(r"token|jwt|auth|remember|apikey|api_key", re.IGNORECASE)
SESSION_COOKIE = re.compile(
    r"session|jsessionid|phpsessid|aspsession|cfid|cftoken", re.IGNORECASE
)
_AUTH_HEADERS = {
    "authorization",
    "cookie",
    "x-api-key",
    "x-auth-token",
    "proxy-authorization",
}


def _is_probably_numeric(v: str) -> bool:
    v = v.strip()
    if not v:
        return False
    try:
        float(v)
        return True
    except ValueError:
        return False


def build_variants(
    req: Request, include_state_fields: bool = False
) -> list[tuple[str, Request, list[str]]]:
    """Return [(label, mutated_request, descriptions), ...] for smart defaults."""
    variants: list[tuple[str, Request, list[str]]] = []
    all_params: list[NameValue] = [
        p
        for p in list(req.params) + list(req.body_form)
        if include_state_fields or not is_state_field(p.name)
    ]
    seen_labels = set()

    def add(label: str, ops: list[Mutation]):
        if label in seen_labels:
            return
        seen_labels.add(label)
        mreq, desc = _mutate.apply_mutations(req, ops)
        variants.append((label, mreq, desc))

    for p in all_params:
        if p.value.lower() in BOOLEAN_VALUES:
            add(f"flip:{p.name}", [Mutation("flip_param", name=p.name)])
        if _is_probably_numeric(p.value):
            for w in TYPE_CONFUSION_WORDS[:3]:
                add(
                    f"type-confuse:{p.name}={w}",
                    [Mutation("set_param", name=p.name, value=w)],
                )
            for b in BOUNDARY_IDS[:3]:
                add(
                    f"boundary:{p.name}={b}",
                    [Mutation("set_param", name=p.name, value=b)],
                )
        if p.name.lower() in {
            "id",
            "user_id",
            "uid",
            "account",
            "page",
            "offset",
            "limit",
        }:
            for b in BOUNDARY_IDS:
                add(
                    f"boundary:{p.name}={b}",
                    [Mutation("set_param", name=p.name, value=b)],
                )

    for p in all_params:
        if p.name.lower() in {
            "q",
            "search",
            "name",
            "username",
            "input",
            "term",
            "category",
            "type",
            "filter",
            "tag",
            "sort",
            "status",
            "group",
        }:
            for sq in SQL_PROBES:
                add(f"sql:{p.name}", [Mutation("set_param", name=p.name, value=sq)])
            for x in XSS_PROBES:
                add(f"xss:{p.name}", [Mutation("set_param", name=p.name, value=x)])

    # strip-session variant (broken-auth check)
    add("strip-session", [Mutation("strip_session")])
    return variants


def _classify(
    label: str, baseline: Response | None, resp: Response | None, error: str | None
) -> dict | None:
    if error:
        return {"label": label, "anomaly": "request_error", "detail": error}
    if resp is None:
        return None
    base_status = baseline.status_code if baseline else None
    out = {"label": label, "status": resp.status_code, "body_len": resp.body_len}

    if base_status is not None and resp.status_code != base_status:
        out["anomaly"] = "status_change"
        out["detail"] = f"baseline {base_status} -> {resp.status_code}"
        return out

    # error leak
    for pat in ERROR_PATTERNS:
        if re.search(pat, resp.body):
            out["anomaly"] = "error_leak"
            out["detail"] = f"error pattern matched: {pat[:40]}"
            return out

    # new auth token / credential cookie
    base_cookies = {c.name for c in (baseline.set_cookies if baseline else [])}
    for c in resp.set_cookies:
        if AUTH_COOKIE.search(c.name) and c.name not in base_cookies:
            out.setdefault("anomaly", "new_auth_cookie")
            out["detail"] = f"new cookie {c.name}="
            return out

    # session-ID rotation is expected unless the session itself was stripped
    if label == "strip-session":
        for c in resp.set_cookies:
            if SESSION_COOKIE.search(c.name) and c.name not in base_cookies:
                out.setdefault("anomaly", "new_auth_cookie")
                out["detail"] = f"new session cookie {c.name}="
                return out

    # body delta vs baseline
    if baseline is not None and baseline.body:
        base_body = baseline.body
        resp_body = resp.body or ""
        if base_body == resp_body:
            ratio = 1.0
        elif not resp_body:
            ratio = 0.0
        else:
            ratio = SequenceMatcher(
                None, base_body[:4000], resp_body[:4000]
            ).ratio()
        if ratio < 0.85:
            out["anomaly"] = "body_changed"
            out["detail"] = (
                f"similarity {ratio:.2f} (baseline {baseline.body_len}B -> {resp.body_len}B)"
            )
            return out

    return None  # boring, same as baseline


def run_fuzz(
    req: Request,
    session: SessionState,
    *,
    baseline_response: Response | None = None,
    concurrency: int = 6,
    variants: list[tuple[str, Request, list[str]]] | None = None,
    include_state_fields: bool = False,
) -> dict:
    """Dispatch variants in the background and return anomalies + summary."""
    if variants is None:
        variants = build_variants(req, include_state_fields=include_state_fields)

    if baseline_response is None:
        # Establish a clean-request baseline so routine session-cookie
        # rotation (e.g. classic ASP issuing a fresh ASPSESSIONID to every
        # anonymous request) isn't misreported as an auth anomaly.
        try:
            _, baseline_response, _ = execute(req, session.model_copy(deep=True))
        except Exception:  # noqa: BLE001
            baseline_response = None

    def _do(item):
        label, mreq, desc = item
        try:
            _, resp, _ = execute(mreq, session.model_copy(deep=True))
            return label, desc, resp, None
        except Exception as exc:  # noqa: BLE001
            return label, desc, None, str(exc)

    results: list[dict] = []
    with ThreadPoolExecutor(max_workers=max(1, min(concurrency, 16))) as ex:
        futures = {ex.submit(_do, v): v[0] for v in variants}
        for fut in as_completed(futures):
            label, desc, resp, err = fut.result()
            c = _classify(label, baseline_response, resp, err)
            if c is not None:
                c["mutations"] = desc
                results.append(c)

    results.sort(key=lambda r: (r.get("anomaly") or "", r.get("label") or ""))
    return {
        "target": req.url,
        "total_variants": len(variants),
        "anomalies": len(results),
        "baseline_status": baseline_response.status_code if baseline_response else None,
        "results": results,
    }
