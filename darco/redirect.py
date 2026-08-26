"""Open redirect auditor.

Probes parameters whose names look redirect-prone with off-site canary URLs
and classifies how the application redirects: Location header (confirmed),
meta refresh (high), or JavaScript location assignment (medium).

The canary host uses the reserved `.invalid` TLD, so no outbound connection
is ever made to it — we only observe whether the target echoes it back.
"""

import httpx

from .engine import execute
from .models import (
    NameValue,
    RedirectFinding,
    RedirectScanResult,
    Request,
    Response,
    SessionState,
)
from .state_fields import is_state_field

CANARY_HOST = "darco-canary.invalid"
CANARY_PATH = "/darcoredirect"

# Absolute URL payload variants: plain, protocol-relative, percent-encoded.
_PAYLOADS = [
    f"http://{CANARY_HOST}{CANARY_PATH}",
    f"//{CANARY_HOST}{CANARY_PATH}",
    f"http%3A%2F%2F{CANARY_HOST}%2Fdarcoredirect",
]

REDIRECT_PARAM_HINTS = frozenset(
    {
        "url",
        "uri",
        "u",
        "next",
        "n",
        "return",
        "returnurl",
        "returnto",
        "return_path",
        "redirect",
        "redirecturi",
        "redirect_uri",
        "redirecturl",
        "redirect_url",
        "target",
        "dest",
        "destination",
        "goto",
        "go",
        "continue",
        "continueurl",
        "link",
        "forward",
        "rurl",
        "r_uri",
        "callback",
        "out",
        "view",
        "page",
        "path",
        "to",
        "jump",
        "jump_to",
        "window",
        "return_page",
        "dest_url",
        "destination_url",
    }
)


def _send(req: Request, session: SessionState) -> Response | None:
    try:
        res = execute(req, session)
        if isinstance(res, tuple) and len(res) >= 2:
            return res[1]
        elif isinstance(res, Response):
            return res
        return None
    except (httpx.HTTPError, OSError, TimeoutError, ValueError):
        return None


def _clone_and_mutate_param(
    base: Request, param_type: str, param_name: str, new_val: str
) -> Request:
    req = base.model_copy(deep=True)
    if param_type == "query":
        req.params = [
            NameValue(name=p.name, value=new_val if p.name == param_name else p.value)
            for p in req.params
        ]
    elif param_type == "form":
        req.body_form = [
            NameValue(name=p.name, value=new_val if p.name == param_name else p.value)
            for p in req.body_form
        ]
    elif param_type == "json" and isinstance(req.body_json, dict):
        d = dict(req.body_json)
        d[param_name] = new_val
        req.body_json = d
    return req


def _is_redirect_candidate(name: str) -> bool:
    normalized = name.lower().replace("-", "").replace("_", "").replace(".", "")
    if normalized in REDIRECT_PARAM_HINTS:
        return True
    # Also catch compound names like "login_return_url" / "nextPage".
    return any(h in normalized for h in ("return", "redirect", "goto", "dest", "next"))


def _location_of(resp: Response, canary: str) -> str:
    for h in resp.headers:
        if h.name.lower() == "location" and canary in h.value:
            return h.value
    return ""


_META_PATTERNS = ("http-equiv", "refresh")
_JS_PATTERNS = ("location.href", "location.replace", "window.location", "document.location")


def _body_redirect_of(body: str, canary: str) -> tuple[str, str] | None:
    """Return (redirect_type, matched_snippet) for meta-refresh or JS redirects."""
    low = body.lower()
    idx = low.find(canary)
    while idx != -1:
        start = max(0, idx - 200)
        window = low[start : idx + len(canary)]
        snippet = body[start : idx + len(canary)].replace("\n", " ").strip()
        if all(p in window for p in _META_PATTERNS):
            return "meta_refresh", snippet[-120:]
        for js in _JS_PATTERNS:
            if js in window:
                return "js_location", snippet[-120:]
        idx = low.find(canary, idx + 1)
    return None


def scan_redirect(
    request: Request,
    session: SessionState | None = None,
    param_filter: str | None = None,
    include_state_fields: bool = False,
) -> RedirectScanResult:
    """Audit a request's parameters for open-redirect behavior."""
    if session is None:
        session = SessionState()

    candidates: list[tuple[str, str]] = []  # (param_type, param_name)
    sources = (
        [("query", p.name) for p in request.params]
        + [("form", p.name) for p in request.body_form]
        + (
            [("json", k) for k in request.body_json]
            if isinstance(request.body_json, dict)
            else []
        )
    )
    for p_type, name in sources:
        if param_filter and name != param_filter:
            continue
        if not include_state_fields and is_state_field(name):
            continue
        if not _is_redirect_candidate(name):
            continue
        candidates.append((p_type, name))

    result = RedirectScanResult(
        target=request.url,
        tested_params=[name for _, name in candidates],
    )

    for p_type, p_name in candidates:
        found: RedirectFinding | None = None
        for payload in _PAYLOADS:
            probe_req = _clone_and_mutate_param(request, p_type, p_name, payload)
            # Observe raw redirect responses; never follow to the canary.
            probe_req.follow_redirects = False
            resp = _send(probe_req, session)
            if not resp:
                continue

            location = _location_of(resp, CANARY_HOST)
            if location:
                found = RedirectFinding(
                    param=p_name,
                    param_type=p_type,
                    redirect_type="location_header",
                    confidence="confirmed",
                    payload=payload,
                    redirect_to=location,
                    status_code=resp.status_code,
                    evidence=(
                        f"{resp.status_code} response redirects to attacker-controlled "
                        f"URL via Location header: {location}"
                    ),
                    suggestion=(
                        f"Validate '{p_name}' against an allowlist of trusted "
                        "destinations; prefer server-side path-only redirects."
                    ),
                )
                break

            body_hit = _body_redirect_of(resp.body or "", CANARY_HOST)
            if body_hit:
                rtype, snippet = body_hit
                found = RedirectFinding(
                    param=p_name,
                    param_type=p_type,
                    redirect_type=rtype,
                    confidence="high" if rtype == "meta_refresh" else "medium",
                    payload=payload,
                    status_code=resp.status_code,
                    evidence=f"Client-side redirect embeds canary URL: {snippet}",
                    suggestion=(
                        f"Validate '{p_name}' against an allowlist of trusted "
                        "destinations before using it in client-side redirects."
                    ),
                )
                break

        if found:
            result.findings.append(found)

    return result


__all__ = ["scan_redirect", "REDIRECT_PARAM_HINTS"]
