from __future__ import annotations

import re
from urllib.parse import urlsplit

from .models import Finding, NameValue, Request, Response

PARAM_PATTERN = re.compile(r"(admin|debug|bypass|role|verified|is_|enable|allow|flag|token|secret|otp|pin|test|dev|internal)", re.IGNORECASE)
PATH_PATTERN = re.compile(r"/(admin|internal|debug|backup|api/v\d?|swagger|docs|env|\.git|config|test|dev|console|actuator|\.env)(/|$|\.|_)", re.IGNORECASE)
BOOLEAN_VALUES = {"true", "false", "1", "0", "yes", "no", "on", "off"}
ERROR_PATTERNS = [
    r"Traceback \(most recent call last\)",
    r" in <module>",
    r'File ".*\.py", line \d+',
    r"SQL syntax",
    r"You have an error in your SQL",
    r"Warning:",
    r"Fatal error",
    r"Unhandled Exception",
    r"Undefined variable",
    r"syntax error",
    r"java\.lang\.",
    r"NullPointerException",
    r"Stack trace",
    r"Exception in thread",
    r"at [\w.$]+\.\w+\([\w.$]+\.java:\d+\)",
    r"Internal Server Error",
]
RATE_PATTERN = re.compile(r"rate\s*limit|too many requests|try again later|slow down|temporarily blocked", re.IGNORECASE)
CAPTCHA_PATTERN = re.compile(r"recaptcha|g-recaptcha|hcaptcha|turnstile|geetest|cloudflare-challenge|google\.com/recaptcha|hcaptcha\.com|challenges\.cloudflare", re.IGNORECASE)
AUTH_COOKIE_PATTERN = re.compile(r"session|token|jwt|auth|sid|remember", re.IGNORECASE)
INTERESTING_HEADERS = {"server", "x-powered-by", "x-aspnet-version", "x-backend", "via", "x-debug", "www-authenticate", "x-forwarded-for", "x-real-ip"}

_finding_counter = 0


def _finding(f_type: str, location: str, evidence: str, suggestion: str, severity: str = "info", request_id: str | None = None) -> Finding:
    global _finding_counter
    _finding_counter += 1
    return Finding(
        id=f"f{_finding_counter}",
        type=f_type,
        severity=severity,
        location=location,
        evidence=evidence[:500],
        suggestion=suggestion,
        request_id=request_id,
    )


def analyze_request(request: Request) -> list[Finding]:
    findings: list[Finding] = []
    loc = f"{request.method} {request.url}"
    all_params = list(request.params) + list(request.body_form)
    for p in all_params:
        if PARAM_PATTERN.search(p.name):
            findings.append(
                _finding(
                    "interesting_param_name",
                    loc,
                    f"param {p.name}={p.value}",
                    "Probe this parameter with boundary values (empty, oversized, alternate types) and check its effect on responses.",
                    "low",
                )
            )
        if p.value.lower() in BOOLEAN_VALUES:
            findings.append(
                _finding(
                    "boolean_param",
                    loc,
                    f"param {p.name}={p.value} (boolean-ish)",
                    "Try flipping this value (--flip-param) to see if it toggles behavior.",
                    "medium",
                )
            )
    path = urlsplit(request.url).path
    if PATH_PATTERN.search(path):
        findings.append(
            _finding(
                "interesting_path",
                loc,
                f"path segment matches sensitive-name heuristic: {path}",
                "Verify whether this path exposes internal functionality; test access controls.",
                "medium",
            )
        )
    return findings


def analyze_response(request: Request, response: Response) -> list[Finding]:
    findings: list[Finding] = []
    loc = f"{request.method} {request.url}"
    body = response.body

    if response.status_code in (401, 403):
        findings.append(
            _finding(
                "auth_required",
                loc,
                f"status {response.status_code}",
                "Endpoint requires authentication; replay with captured session or test anonymous access controls.",
                "info",
            )
        )
    if any("login" in r.lower() or "signin" in r.lower() for r in response.redirects):
        findings.append(
            _finding(
                "auth_required",
                loc,
                f"redirected to login: {response.redirects[-1]}",
                "Endpoint requires authentication.",
                "info",
            )
        )
    if response.status_code == 429 or any(h.name.lower() == "retry-after" for h in response.headers):
        findings.append(
            _finding(
                "rate_limited",
                loc,
                f"status 429 or Retry-After header",
                "Rate limit engaged. Try --strip-session, alternate headers, or delayed retries; verify the limit is keyed on what you expect.",
                "medium",
            )
        )
    elif RATE_PATTERN.search(body) and response.status_code == 429:
        findings.append(
            _finding(
                "rate_limited",
                loc,
                "response body matches rate-limit wording",
                "Rate limit engaged.",
                "medium",
            )
        )
    if response.status_code >= 500:
        findings.append(
            _finding(
                "server_anomaly",
                loc,
                f"status {response.status_code}",
                "Server error may reveal internals; inspect response body for stack traces and test boundary inputs.",
                "medium",
            )
        )
    for pattern in ERROR_PATTERNS:
        m = re.search(pattern, body)
        if m:
            findings.append(
                _finding(
                    "error_leak",
                    loc,
                    f"error pattern {pattern!r} matched: {m.group(0)}",
                    "Error message leaks implementation detail; examine nearby inputs that triggered it.",
                    "high",
                )
            )
            break
    if CAPTCHA_PATTERN.search(body):
        findings.append(
            _finding(
                "captcha",
                loc,
                "CAPTCHA/challenge marker found in response",
                "Automated requests may be blocked here; plan for manual solving or challenge-aware flow.",
                "info",
            )
        )
    seen_cookie_names: set[str] = set()
    for c in response.set_cookies:
        seen_cookie_names.add(c.name)
        if AUTH_COOKIE_PATTERN.search(c.name):
            findings.append(
                _finding(
                    "auth_token_cookie",
                    loc,
                    f"Set-Cookie {c.name}={c.value[:20]}...",
                    "Auth-like cookie issued; verify scope/expiry and whether stripping it changes behavior.",
                    "medium",
                )
            )
    for h in response.headers:
        if h.name.lower() == "set-cookie":
            name = h.value.split(";", 1)[0].split("=", 1)[0].strip()
            if name and name not in seen_cookie_names:
                seen_cookie_names.add(name)
                if AUTH_COOKIE_PATTERN.search(name):
                    findings.append(
                        _finding(
                            "auth_token_cookie",
                            loc,
                            f"Set-Cookie {name}=...",
                            "Auth-like cookie issued; verify scope/expiry and whether stripping it changes behavior.",
                            "medium",
                        )
                    )
    for h in response.headers:
        if h.name.lower() in INTERESTING_HEADERS:
            findings.append(
                _finding(
                    "interesting_header",
                    loc,
                    f"{h.name}: {h.value[:200]}",
                    "Header discloses backend/framework details; factor into fingerprinting.",
                    "low",
                )
            )
    for p in list(request.params) + list(request.body_form):
        if p.value and len(p.value) > 3 and p.value in body:
            findings.append(
                _finding(
                    "reflection",
                    loc,
                    f"param {p.name}={p.value!r} reflected in response body",
                    "Reflection point confirmed; test for injection/XSS with encoding-aware payloads.",
                    "medium",
                )
            )
    return findings
