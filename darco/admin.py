"""Admin panel discovery and management console security auditing.

Probes target sites for administrative panels, backend portals, CMS consoles,
and dashboards, extracting authentication mechanisms and auditing discovered
login forms using smart domain-derived and passively discovered credentials.
"""

from __future__ import annotations

import asyncio
import re
from urllib.parse import urljoin

import httpx
from bs4 import BeautifulSoup

from .discovery.parsers import extract_forms
from .login import (
    _to_login_form,
    audit_login_forms,
    generate_smart_credentials,
    is_login_form,
)
from .models import AdminPanel, AdminPanelReport, Finding, LoginForm

USER_AGENT = "darco/0.1 (admin-panel finder)"

# High-value administrative paths and control panels
ADMIN_PATHS = (
    "/admin",
    "/admin/",
    "/admin/login",
    "/admin/login.php",
    "/admin/login.html",
    "/admin/index.php",
    "/admin/index.html",
    "/admin/dashboard",
    "/admin/home",
    "/admin/cp.php",
    "/admin/controlpanel.php",
    "/admin.php",
    "/admin.html",
    "/administrator",
    "/administrator/",
    "/administrator/index.php",
    "/administrator/login.php",
    "/adminpanel",
    "/admin-panel",
    "/admin_login",
    "/admincontrol",
    "/admin_area",
    "/backend",
    "/backend/",
    "/backend/login",
    "/backend/admin",
    "/controlpanel",
    "/cp",
    "/cpanel",
    "/whm",
    "/webmail",
    "/dashboard",
    "/dashboard/",
    "/dashboard/login",
    "/dashboard/admin",
    "/manager",
    "/manager/html",
    "/manager/status",
    "/portal",
    "/portal/login",
    "/portal/admin",
    "/superadmin",
    "/masteradmin",
    "/sysadmin",
    "/wp-admin",
    "/wp-login.php",
    "/wp-admin/index.php",
    "/user/login",
    "/member/login",
    "/staff",
    "/staff/login",
    "/secure/login",
    "/phpmyadmin",
    "/phpmyadmin/",
    "/pma",
    "/adminer",
    "/adminer.php",
    "/sqlweb",
    "/actuator",
    "/actuator/health",
    "/actuator/env",
    "/console",
    "/h2-console",
    "/api/admin",
    "/auth/admin",
    "/login/admin",
)

_TITLE_REGEX = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def _extract_title(html: str) -> str:
    m = _TITLE_REGEX.search(html)
    if m:
        return re.sub(r"\s+", " ", m.group(1)).strip()
    return ""


async def find_admin_panels(
    url: str,
    *,
    timeout: float = 8.0,
    verify: bool = True,
    paths: tuple[str, ...] | list[str] | None = None,
    workers: int = 10,
    client: httpx.AsyncClient | None = None,
) -> list[AdminPanel]:
    """Probe a target URL for administrative panels and backend consoles."""
    base_url = url.rstrip("/")
    probe_paths = list(paths or ADMIN_PATHS)
    discovered: list[AdminPanel] = []
    seen_urls: set[str] = set()

    managed_client = client is None
    async_client = client or httpx.AsyncClient(
        timeout=timeout,
        verify=verify,
        follow_redirects=False,
        trust_env=False,
    )

    try:
        queue: asyncio.Queue[str] = asyncio.Queue()
        for p in probe_paths:
            queue.put_nowait(p)

        async def worker() -> None:
            while not queue.empty():
                try:
                    p = queue.get_nowait()
                except asyncio.QueueEmpty:
                    break

                target_path_url = urljoin(base_url + "/", p.lstrip("/"))
                if target_path_url in seen_urls:
                    queue.task_done()
                    continue
                seen_urls.add(target_path_url)

                try:
                    resp = await async_client.get(
                        target_path_url,
                        headers={"User-Agent": USER_AGENT},
                    )
                except (httpx.HTTPError, OSError, TimeoutError):
                    queue.task_done()
                    continue

                # Filter out obvious 404 / non-existent endpoints
                if resp.status_code == 404 or resp.status_code >= 500:
                    queue.task_done()
                    continue

                title = ""
                auth_type = "unknown"
                login_form: LoginForm | None = None
                redirect_url = resp.headers.get("location")
                server = resp.headers.get("server", "")

                body = resp.text or ""
                content_type = resp.headers.get("content-type", "").lower()
                is_html_content = (
                    "html" in content_type
                    or "<html" in body.lower()
                    or "<form" in body.lower()
                )

                if is_html_content:
                    title = _extract_title(body)

                # Classify authentication & panel exposure type
                if resp.status_code in (301, 302, 303, 307, 308):
                    auth_type = "redirect"
                    redir = resp.headers.get("location", "")
                    if any(
                        k in redir.lower() for k in ("login", "auth", "signin", "admin")
                    ):
                        auth_type = "portal_redirect"

                elif resp.status_code == 401:
                    auth_type = "basic_auth"

                elif resp.status_code == 403:
                    auth_type = "forbidden"

                elif resp.status_code == 200:
                    if is_html_content:
                        try:
                            soup = BeautifulSoup(body, "html.parser")
                            forms = extract_forms(soup, str(resp.url))
                            for f in forms:
                                if is_login_form(f):
                                    login_form = _to_login_form(f, str(resp.url))
                                    auth_type = "login_form"
                                    break
                        except (ValueError, TypeError, KeyError):
                            pass

                    if auth_type == "unknown":
                        if any(
                            k in title.lower()
                            for k in (
                                "admin",
                                "dashboard",
                                "control panel",
                                "login",
                                "management",
                                "portal",
                            )
                        ):
                            auth_type = (
                                "login_form"
                                if "<input" in body.lower()
                                else "exposed_dashboard"
                            )
                        elif "actuator" in p or "api" in p:
                            auth_type = "api"
                        else:
                            auth_type = "accessible_endpoint"

                evidence = f"HTTP {resp.status_code}"
                if title:
                    evidence += f" (Title: '{title}')"
                if redirect_url:
                    evidence += f" -> Location: {redirect_url}"

                confidence = (
                    "confirmed"
                    if resp.status_code == 200
                    or auth_type in ("login_form", "basic_auth", "exposed_dashboard")
                    else "high"
                )

                discovered.append(
                    AdminPanel(
                        path=p,
                        url=target_path_url,
                        status_code=resp.status_code,
                        title=title,
                        auth_type=auth_type,
                        redirect_url=redirect_url,
                        login_form=login_form,
                        server=server,
                        confidence=confidence,
                        evidence=evidence,
                    )
                )
                queue.task_done()

        tasks = [asyncio.create_task(worker()) for _ in range(max(1, workers))]
        await queue.join()
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

    finally:
        if managed_client:
            await async_client.aclose()

    return sorted(discovered, key=lambda a: (0 if a.status_code == 200 else 1, a.path))


async def audit_admin_panels(
    url: str,
    *,
    emails: tuple[str, ...] | list[str] = (),
    test_creds: bool = True,
    timeout: float = 8.0,
    verify: bool = True,
    workers: int = 10,
    paths: tuple[str, ...] | list[str] | None = None,
) -> AdminPanelReport:
    """Discover admin panels and test detected login forms with smart credentials."""
    panels = await find_admin_panels(
        url,
        timeout=timeout,
        verify=verify,
        paths=paths,
        workers=workers,
    )

    clean_emails = []
    seen_emails = set()
    for em in emails:
        c = em.strip().lower()
        if c and c not in seen_emails:
            seen_emails.add(c)
            clean_emails.append(c)

    report = AdminPanelReport(
        target=url,
        scanned_paths=len(paths or ADMIN_PATHS),
        panels_found=panels,
        emails_used=clean_emails,
    )

    all_findings: list[Finding] = []

    for panel in panels:
        p_clean = panel.path.strip("/")
        if panel.auth_type == "exposed_dashboard":
            all_findings.append(
                Finding(
                    id=f"admin-exposed-{p_clean}",
                    type="admin_panel_exposed",
                    severity="high",
                    location=panel.url,
                    evidence=f"Administrative dashboard exposed without authentication: {panel.evidence}",
                    suggestion="Enforce strict authentication and restrict access to authorized IP ranges.",
                )
            )
        elif panel.auth_type in ("login_form", "basic_auth", "portal_redirect"):
            all_findings.append(
                Finding(
                    id=f"admin-panel-{p_clean}",
                    type="admin_panel_found",
                    severity="medium",
                    location=panel.url,
                    evidence=f"Administrative portal discovered: {panel.evidence}",
                    suggestion="Verify that the administrative interface is protected by multi-factor authentication (MFA) and rate limiting.",
                )
            )

    login_forms = [p.login_form for p in panels if p.login_form]
    if test_creds and login_forms:
        smart_creds = generate_smart_credentials(url, emails=clean_emails)
        report.tested_creds = len(smart_creds)
        login_res = audit_login_forms(
            login_forms,
            target=url,
            default_credentials=smart_creds,
            emails=clean_emails,
            test_default_creds=True,
            timeout=timeout,
            verify=verify,
        )
        report.bypasses = login_res.bypasses

        for b in login_res.bypasses:
            is_cred = b.param == "credentials" and ":" in b.payload
            finding_type = "default_credentials" if is_cred else "login_sqli_bypass"
            all_findings.append(
                Finding(
                    id=f"admin-login-{finding_type}-{b.payload[:16]}",
                    type=finding_type,
                    severity="high"
                    if b.confidence in ("confirmed", "high")
                    else "medium",
                    location=f"{url} ({b.param})",
                    evidence=b.evidence,
                    suggestion=b.suggestion,
                )
            )

    report.findings = all_findings
    return report


def find_admin_panels_sync(
    url: str,
    *,
    timeout: float = 8.0,
    verify: bool = True,
    paths: tuple[str, ...] | list[str] | None = None,
    workers: int = 10,
) -> list[AdminPanel]:
    """Synchronous wrapper around find_admin_panels."""
    return asyncio.run(
        find_admin_panels(
            url,
            timeout=timeout,
            verify=verify,
            paths=paths,
            workers=workers,
        )
    )


def audit_admin_panels_sync(
    url: str,
    *,
    emails: tuple[str, ...] | list[str] = (),
    test_creds: bool = True,
    timeout: float = 8.0,
    verify: bool = True,
    workers: int = 10,
    paths: tuple[str, ...] | list[str] | None = None,
) -> AdminPanelReport:
    """Synchronous wrapper around audit_admin_panels."""
    return asyncio.run(
        audit_admin_panels(
            url,
            emails=emails,
            test_creds=test_creds,
            timeout=timeout,
            verify=verify,
            workers=workers,
            paths=paths,
        )
    )


__all__ = [
    "ADMIN_PATHS",
    "audit_admin_panels",
    "audit_admin_panels_sync",
    "find_admin_panels",
    "find_admin_panels_sync",
]
