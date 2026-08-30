"""CORS (Cross-Origin Resource Sharing) misconfiguration auditor.

Probes endpoints with untrusted, null, and crafted origins to detect
insecure CORS policies:
* Arbitrary Origin reflection (with and without credentials)
* Null origin trust (exploitable via sandboxed iframes)
* Subdomain prefix/suffix regex bypasses
* Wildcard with credentials
* Permissive preflight OPTIONS handling

Includes exploit PoC HTML generation and reproduction curl commands.
"""

from __future__ import annotations

from urllib.parse import urlsplit

import httpx

from .engine import execute
from .models import (
    CorsFinding,
    CorsScanResult,
    NameValue,
    Request,
    Response,
    SessionState,
)

EVIL_ORIGIN = "https://evil.com"
NULL_ORIGIN = "null"


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


def _get_header(resp: Response, name: str) -> str:
    name_low = name.lower()
    for h in resp.headers:
        if h.name.lower() == name_low:
            return h.value.strip()
    return ""


def _build_poc_html(target_url: str, origin: str) -> str:
    """Generate an exploit HTML snippet demonstrating cross-origin data theft."""
    return (
        "<!DOCTYPE html>\n"
        "<html>\n"
        "<head><title>CORS Exploit PoC</title></head>\n"
        "<body>\n"
        "<h1>CORS Data Theft PoC</h1>\n"
        "<pre id=\"output\">Extracting sensitive data...</pre>\n"
        "<script>\n"
        "  fetch('" + target_url + "', {\n"
        "    method: 'GET',\n"
        "    credentials: 'include'\n"
        "  })\n"
        "  .then(response => response.text())\n"
        "  .then(data => {\n"
        "    document.getElementById('output').textContent = data;\n"
        "    console.log('Exfiltrated data:', data);\n"
        "  })\n"
        "  .catch(err => {\n"
        "    document.getElementById('output').textContent = 'Error: ' + err;\n"
        "  });\n"
        "</script>\n"
        "</body>\n"
        "</html>"
    )


def _build_repro_curl(target_url: str, origin: str, method: str = "GET") -> str:
    def _esc(s: str) -> str:
        return s.replace("'", "'\\''")

    parts = ["curl -i"]
    if method != "GET":
        parts.append(f"-X {method}")
    parts.append(f"-H 'Origin: {_esc(origin)}'")
    parts.append(f"'{_esc(target_url)}'")
    return " ".join(parts)


def scan_cors(
    request: Request,
    session: SessionState | None = None,
    extra_origins: list[str] | None = None,
) -> CorsScanResult:
    """Audit an endpoint for CORS misconfigurations."""
    if session is None:
        session = SessionState()

    target_url = request.url
    parsed = urlsplit(target_url)
    hostname = parsed.hostname or "target.test"

    # Test origins to probe
    test_origins = [
        EVIL_ORIGIN,
        NULL_ORIGIN,
        f"https://{hostname}.evil.com",
        f"https://evil{hostname}",
    ]
    if extra_origins:
        test_origins.extend(extra_origins)

    tested_origins_list: list[str] = []
    findings: list[CorsFinding] = []

    # 1. Probe direct request with custom Origin header
    for origin in test_origins:
        tested_origins_list.append(origin)

        probe_req = request.model_copy(deep=True)
        # Add or update Origin header
        new_headers = [h for h in probe_req.headers if h.name.lower() != "origin"]
        new_headers.append(NameValue(name="Origin", value=origin))
        probe_req.headers = new_headers

        resp = _send(probe_req, session)
        if resp is None:
            continue

        acao = _get_header(resp, "Access-Control-Allow-Origin")
        acac = _get_header(resp, "Access-Control-Allow-Credentials").lower() == "true"
        acam = [
            m.strip()
            for m in _get_header(resp, "Access-Control-Allow-Methods").split(",")
            if m.strip()
        ]
        acah = [
            h.strip()
            for h in _get_header(resp, "Access-Control-Allow-Headers").split(",")
            if h.strip()
        ]
        aceh = [
            h.strip()
            for h in _get_header(resp, "Access-Control-Expose-Headers").split(",")
            if h.strip()
        ]
        max_age_str = _get_header(resp, "Access-Control-Max-Age")
        max_age = int(max_age_str) if max_age_str.isdigit() else None

        if not acao:
            continue

        # Evaluate misconfigurations
        if origin == EVIL_ORIGIN and (acao == origin or acao == "*"):
            if acao == origin and acac:
                findings.append(
                    CorsFinding(
                        origin_tested=origin,
                        allow_origin=acao,
                        allow_credentials=True,
                        allow_methods=acam,
                        allow_headers=acah,
                        expose_headers=aceh,
                        max_age=max_age,
                        misconfig_type="arbitrary_origin_allowed",
                        confidence="confirmed",
                        status_code=resp.status_code,
                        evidence=(
                            f"Server reflected untrusted Origin '{origin}' with "
                            f"Access-Control-Allow-Credentials: true. An attacker website "
                            f"can make authenticated cross-origin requests and read sensitive response data."
                        ),
                        suggestion="Validate Origin against a strict whitelist and disable allow-credentials if unneeded.",
                        curl=_build_repro_curl(target_url, origin, request.method),
                        poc_html=_build_poc_html(target_url, origin),
                    )
                )
            elif acao == origin:
                findings.append(
                    CorsFinding(
                        origin_tested=origin,
                        allow_origin=acao,
                        allow_credentials=False,
                        allow_methods=acam,
                        allow_headers=acah,
                        expose_headers=aceh,
                        max_age=max_age,
                        misconfig_type="arbitrary_origin_allowed",
                        confidence="high",
                        status_code=resp.status_code,
                        evidence=f"Server reflected untrusted Origin '{origin}' in Access-Control-Allow-Origin.",
                        suggestion="Validate Origin against a whitelist of trusted domains.",
                        curl=_build_repro_curl(target_url, origin, request.method),
                        poc_html=_build_poc_html(target_url, origin),
                    )
                )
            elif acao == "*" and acac:
                findings.append(
                    CorsFinding(
                        origin_tested=origin,
                        allow_origin="*",
                        allow_credentials=True,
                        allow_methods=acam,
                        allow_headers=acah,
                        expose_headers=aceh,
                        max_age=max_age,
                        misconfig_type="wildcard_with_credentials",
                        confidence="medium",
                        status_code=resp.status_code,
                        evidence="Access-Control-Allow-Origin is '*' with Access-Control-Allow-Credentials: true (invalid per CORS spec, browsers block this combination).",
                        suggestion="Remove credentials flag or specify explicit trusted origins.",
                        curl=_build_repro_curl(target_url, origin, request.method),
                    )
                )

        elif origin == NULL_ORIGIN and acao == "null":
            findings.append(
                CorsFinding(
                    origin_tested=origin,
                    allow_origin="null",
                    allow_credentials=acac,
                    allow_methods=acam,
                    allow_headers=acah,
                    expose_headers=aceh,
                    max_age=max_age,
                    misconfig_type="null_origin_allowed",
                    confidence="confirmed" if acac else "medium",
                    status_code=resp.status_code,
                    evidence=(
                        "Server allows 'Origin: null' in Access-Control-Allow-Origin"
                        + (" with credentials enabled." if acac else ".")
                        + " Attackers can exploit this via sandboxed <iframe> tags."
                    ),
                    suggestion="Do not trust 'null' origin; whitelist specific fully-qualified domains.",
                    curl=_build_repro_curl(target_url, origin, request.method),
                    poc_html=_build_poc_html(target_url, origin),
                )
            )

        elif ("evil.com" in origin or "evil" in origin) and acao == origin:
            findings.append(
                CorsFinding(
                    origin_tested=origin,
                    allow_origin=acao,
                    allow_credentials=acac,
                    allow_methods=acam,
                    allow_headers=acah,
                    expose_headers=aceh,
                    max_age=max_age,
                    misconfig_type="subdomain_prefix_bypass",
                    confidence="confirmed" if acac else "high",
                    status_code=resp.status_code,
                    evidence=f"Server accepted crafted origin '{origin}' matching weak regex domain check.",
                    suggestion="Use exact domain equality checking or properly anchored regex (^https://([a-z0-9-]+\\.)?example\\.com$).",
                    curl=_build_repro_curl(target_url, origin, request.method),
                    poc_html=_build_poc_html(target_url, origin),
                )
            )

    # 2. Preflight OPTIONS request probe
    preflight_req = Request(
        method="OPTIONS",
        url=target_url,
        headers=[
            NameValue(name="Origin", value=EVIL_ORIGIN),
            NameValue(name="Access-Control-Request-Method", value="PUT"),
            NameValue(
                name="Access-Control-Request-Headers", value="X-Custom-Header, Authorization"
            ),
        ],
        follow_redirects=False,
    )
    preflight_resp = _send(preflight_req, session)
    if preflight_resp is not None and preflight_resp.status_code in (200, 204):
        p_acao = _get_header(preflight_resp, "Access-Control-Allow-Origin")
        p_acac = _get_header(preflight_resp, "Access-Control-Allow-Credentials").lower() == "true"
        p_acam = [
            m.strip()
            for m in _get_header(preflight_resp, "Access-Control-Allow-Methods").split(",")
            if m.strip()
        ]
        if p_acao in (EVIL_ORIGIN, "*") and ("PUT" in p_acam or "DELETE" in p_acam or "*" in p_acam):
            findings.append(
                CorsFinding(
                    origin_tested=EVIL_ORIGIN,
                    allow_origin=p_acao,
                    allow_credentials=p_acac,
                    allow_methods=p_acam,
                    misconfig_type="preflight_all_methods",
                    confidence="high",
                    status_code=preflight_resp.status_code,
                    evidence=f"Preflight OPTIONS accepted {p_acao} allowing dangerous methods: {', '.join(p_acam)}",
                    suggestion="Restrict allowed preflight methods and origin checking.",
                    curl="curl -i -X OPTIONS -H 'Origin: https://evil.com' -H 'Access-Control-Request-Method: PUT' '" + target_url + "'",
                )
            )

    # De-duplicate findings by (misconfig_type, origin_tested)
    seen = set()
    unique_findings: list[CorsFinding] = []
    for f in findings:
        key = (f.misconfig_type, f.origin_tested)
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)

    return CorsScanResult(
        target=target_url,
        tested_origins=tested_origins_list,
        findings=unique_findings,
    )
