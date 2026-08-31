"""Active POC verification for matched attack templates.

Detection tells you *something looks off*. Verification ("smart mode") tries to
prove *real access*:

1. Extract credential-like secrets leaked by the matched response
   (passwords, API keys, tokens, database URIs).
2. If the template declares explicit ``poc`` steps, run them and require every
   step to match.
3. If ``auto_login`` is set, reuse the leaked credentials against the target's
   login form and confirm we actually landed in an authenticated state.

The result is a ``(verified, verification_detail, access_list)`` triple that the
engine attaches to each matched finding.
"""

from __future__ import annotations

import re
from difflib import SequenceMatcher

import httpx
from bs4 import BeautifulSoup

from ..discovery.parsers import extract_forms
from .models import (
    TemplatePoC,
    TemplateRequest,
)

_LOGGED_IN_HINTS = (
    "logout",
    "welcome",
    "account",
    "dashboard",
    "my profile",
    "signed in",
    "logged in",
    "admin panel",
)
_ERROR_HINTS = (
    "incorrect",
    "invalid",
    "error",
    "failed",
    "unauthorised",
    "unauthorized",
    "forbidden",
    "try again",
    "not found",
)
_ACCOUNT_REDIRECT_HINTS = ("/account", "/dashboard", "/admin", "/profile", "/home")

# Credential-like value patterns matched against the matched response body.
CREDENTIAL_PATTERNS: tuple[tuple[str, str], ...] = (
    ("password", r"(?i)(?:PASSWORD|PASS|DB_PASS|DB_PASSWORD)\s*[=:]\s*([^\s\"']+)"),
    ("username", r"(?i)(?:USERNAME|USER|DB_USER|DB_USERNAME|LOGIN)\s*[=:]\s*([^\s\"']+)"),
    ("api_key", r"(?i)(?:API_KEY|API_SECRET|ACCESS_KEY|SECRET_KEY|APP_KEY|PRIVATE_KEY)\s*[=:]\s*([^\s\"']+)"),
    ("token", r"(?i)(?:TOKEN|AUTH_TOKEN|SESSION_TOKEN|JWT|CSRF)\s*[=:]\s*([^\s\"']+)"),
    ("database_url", r"(?i)(?:DATABASE_URL|DB_URI|MONGO_URI|REDIS_URL|JDBC)\s*[=:]\s*(\S+)"),
)


def extract_credentials(text: str) -> list[tuple[str, str]]:
    """Pull (kind, value) credential-like pairs from a response body text."""
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for kind, pattern in CREDENTIAL_PATTERNS:
        for m in re.finditer(pattern, text or ""):
            val = m.group(1).strip().strip("'\"")
            if not val or len(val) < 3:
                continue
            key = f"{kind}:{val}"
            if key in seen:
                continue
            seen.add(key)
            out.append((kind, val))
    return out


def _credential_pairs(
    extracted: dict[str, list[str]], text: str
) -> list[tuple[str, str]]:
    """Turn extracted + raw-scanned values into (username, password) login candidos."""
    leaked = extract_credentials(text)
    pairs: list[tuple[str, str]] = []

    usernames: list[str] = []
    passwords: list[str] = []
    for kind, val in leaked:
        target = usernames if kind in ("username", "token") else passwords
        if val not in target:
            target.append(val)

    # Values pre-declared as username/password via extractors named accordingly.
    for name, vals in extracted.items():
        low = name.lower()
        for v in vals:
            if any(k in low for k in ("user", "email", "login")):
                if v not in usernames:
                    usernames.append(v)
            elif any(k in low for k in ("pass", "secret", "key", "token")) and v not in passwords:
                passwords.append(v)

    if not usernames:
        # Common default/root accounts are worth pairing against leaked secrets.
        usernames = ["admin", "root", "administrator", "darco"]

    for u in usernames:
        for p in passwords:
            pairs.append((u, p))
    if not pairs:
        # A lone leaked secret may itself be the password for a default account.
        for u in usernames:
            for _, val in leaked:
                if (u, val) not in pairs:
                    pairs.append((u, val))
    return pairs


async def _run_poc_requests(
    poc_requests: list[TemplateRequest],
    target: str,
    client: httpx.AsyncClient,
    variables: dict[str, str],
) -> tuple[bool, list[str]]:
    """Run explicit POC steps; succeed only if EVERY step matches."""
    from .engine import _evaluate_matcher, _substitute_variables

    access: list[str] = []
    for req in poc_requests:
        step_ok = False
        for raw_path in req.path:
            req_url = _substitute_variables(raw_path, variables)
            req_body = _substitute_variables(req.body, variables) if req.body else None
            req_headers = {
                k: _substitute_variables(v, variables)
                for k, v in req.headers.items()
            }
            resp = await client.request(
                req.method,
                req_url,
                headers=req_headers or None,
                content=req_body.encode("utf-8") if req_body else None,
                follow_redirects=req.redirects,
            )
            if not req.matchers:
                step_ok = resp.status_code == 200
            else:
                evals = [
                    _evaluate_matcher(m, resp)[0] for m in req.matchers
                ]
                step_ok = (
                    all(evals)
                    if req.matchers_condition.lower() == "and"
                    else any(evals)
                )
            if step_ok:
                access.append(f"{req.method} {req_url} → HTTP {resp.status_code}")
                break
        if not step_ok:
            return False, access
    return True, access


async def _try_login(
    client: httpx.AsyncClient,
    target: str,
    username: str,
    password: str,
) -> tuple[bool, str]:
    """Attempt a login with leaked creds; return (success, detail)."""
    from ..login import find_login_forms

    forms = find_login_forms(
        target, timeout=10.0, verify=True, probe_common_paths=True
    )
    if not forms:
        return False, "no login form discovered to try leaked credentials"

    # The discovery uses a blocking client; mirror it here with the async client
    # by locating a form and replaying the submission through `client`.
    form = forms[0]
    uname_field = form.username_field or "username"
    pwd_field = form.password_field or "password"

    hidden: dict[str, str] = {}
    if form.url:
        page = await client.get(form.url)
        if page.status_code < 400:
            soup = BeautifulSoup(page.text, "html.parser")
            for f in extract_forms(soup, form.url):
                if f.action == form.action and f.method.upper() == form.method:
                    hidden = {i.name: i.default or "" for i in f.inputs if i.hidden and i.name}
                    break

    async def attempt(u: str, p: str) -> httpx.Response:
        data = dict(hidden)
        data[uname_field] = u
        data[pwd_field] = p
        if form.method.upper() == "GET":
            return await client.get(form.action, params=data)
        return await client.post(form.action, data=data)

    base = await attempt("darco-baseline-user", "darco-wrong-password-42")
    base_sig = {
        "status": base.status_code,
        "location": (base.headers.get("location") or "").lower(),
        "cookies": {c.name for c in base.cookies.jar},
        "body": (base.text or "").lower(),
    }

    resp = await attempt(username, password)
    loc = (resp.headers.get("location") or "").lower()
    body = (resp.text or "").lower()

    if (
        resp.status_code in (301, 302, 303, 307, 308)
        and any(h in loc for h in _ACCOUNT_REDIRECT_HINTS)
        and not any(h in loc for h in ("login", "signin", "error"))
    ):
        return True, f"redirected to authenticated area '{loc}'"

    if any(h in body for h in _LOGGED_IN_HINTS) and not any(
        h in body for h in _ERROR_HINTS
    ):
        matched = [m for m in _LOGGED_IN_HINTS if m in body]
        return True, f"logged-in content markers: {', '.join(matched[:3])}"

    base_cookies = base_sig["cookies"]
    resp_cookies = {c.name for c in resp.cookies.jar}
    new_cookies = resp_cookies - base_cookies
    if new_cookies:
        return True, f"new session cookie(s): {', '.join(sorted(new_cookies))}"

    if (
        base_sig["status"] == resp.status_code
        and body
        and base_sig["body"]
        and SequenceMatcher(None, base_sig["body"][:4000], body[:4000]).ratio() < 0.55
        and not any(h in body for h in _ERROR_HINTS)
    ):
        return True, "authenticated response differs strongly from failed-login page"

    return False, "credentials rejected by login form"


async def verify_template_match(
    poc: TemplatePoC | None,
    *,
    target: str,
    client: httpx.AsyncClient,
    variables: dict[str, str],
    extracted: dict[str, list[str]],
    text: str,
) -> tuple[bool, str, list[str]]:
    """Run POC / auto-login verification. Returns (verified, detail, access)."""
    access: list[str] = []

    if poc and poc.requests:
        ok, access = await _run_poc_requests(poc.requests, target, client, variables)
        if ok:
            return True, "POC exploit steps succeeded (all requests matched)", access
        return False, "POC exploit steps failed (not all requests matched)", access

    if not poc or poc.auto_login:
        pairs = _credential_pairs(extracted, text)
        if not pairs:
            return (
                False,
                "no credential-like secrets discovered to verify access",
                access,
            )
        for u, p in pairs[:8]:  # cap attempts to avoid flooding the target
            ok, detail = await _try_login(client, target, u, p)
            if ok:
                access.append(f"logged in as '{u}' using leaked credential")
                return True, f"auto-login with leaked '{u}' credential succeeded: {detail}", access
        return False, f"leaked credential(s) rejected by login form ({len(pairs)} tried)", access

    return False, "verification not configured for this template", access
