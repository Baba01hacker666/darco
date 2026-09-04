import re
from urllib.parse import parse_qsl

import httpx

from .discovery.crawler import discover
from .fuzz_v2 import run_fuzz
from .models import (
    AutoScanReport,
    BodyType,
    Finding,
    NameValue,
    Request,
    SiteMap,
)
from .redirect import scan_redirect
from .sqli import scan_sqli
from .traversal import scan_traversal
from .upload import audit_file_upload
from .workspace import Workspace
from .xss import scan_xss


def _build_requests_from_sitemap(
    sitemap: SiteMap, verify: bool = True
) -> list[Request]:
    """Convert discovered endpoints with parameters and forms into executable Request models."""
    requests: list[Request] = []
    seen = set()

    # 1. Endpoints with query parameters
    for ep in sitemap.endpoints:
        params: list[NameValue] = []
        clean_url = ep.url.split("?", 1)[0]
        if ep.params:
            params = [
                NameValue(name=p.name, value=p.value if p.value is not None else "1")
                for p in ep.params
                if p.name
            ]
        elif "?" in ep.url:
            query = ep.url.split("?", 1)[1]
            params = [
                NameValue(name=k, value=v or "1")
                for k, v in parse_qsl(query, keep_blank_values=True)
            ]
        if params:
            sig = ("GET", clean_url, tuple(sorted(p.name for p in params)))
            if sig not in seen:
                seen.add(sig)
                requests.append(
                    Request(
                        method="GET",
                        url=clean_url,
                        params=params,
                        verify=verify,
                        source="crawler",
                    )
                )

    # 2. Forms (GET and POST)
    for f in sitemap.forms:
        action_url = f.action
        method = (f.method or "GET").upper()
        clean_action = action_url.split("?", 1)[0] if "?" in action_url else action_url

        params = [
            NameValue(
                name=inp.name,
                value=inp.default if inp.default is not None else "1",
            )
            for inp in f.inputs
            if inp.name
        ]

        if not params:
            continue

        sig = (method, clean_action, tuple(sorted(p.name for p in params)))
        if sig in seen:
            continue
        seen.add(sig)

        if method == "POST":
            requests.append(
                Request(
                    method="POST",
                    url=clean_action,
                    headers=[
                        NameValue(
                            name="Content-Type",
                            value="application/x-www-form-urlencoded",
                        )
                    ],
                    body_type=BodyType.FORM,
                    body_form=params,
                    verify=verify,
                    source="form",
                )
            )
        else:
            requests.append(
                Request(
                    method="GET",
                    url=clean_action,
                    params=params,
                    verify=verify,
                    source="form",
                )
            )

    return requests


async def run_auto_scan(
    workspace: Workspace,
    url: str,
    *,
    depth: int = 3,
    max_urls: int = 200,
    workers: int = 5,
    parse_js: bool = True,
    fuzz: bool = True,
    sqli: bool = True,
    xss: bool = True,
    redirect: bool = True,
    traversal: bool = True,
    stored_xss: bool = True,
    cors: bool = True,
    upload: bool = True,
    default_creds: bool = True,
    include_state_fields: bool = False,
    timeout: float = 10.0,
    verify: bool = True,
    plugins: list[str] | None = None,
    skip_plugins: list[str] | None = None,
    proxy: str | None = None,
) -> AutoScanReport:
    """Crawl a target, discover all endpoints/forms, and automatically fuzz & audit them."""
    # Step 1: Crawl & Discover Target
    sitemap = await discover(
        workspace,
        url,
        depth=depth,
        max_urls=max_urls,
        workers=workers,
        parse_js=parse_js,
        timeout=timeout,
        verify=verify,
        proxy=proxy,
    )

    session = workspace.load_session()
    candidate_requests = _build_requests_from_sitemap(sitemap, verify=verify)

    report = AutoScanReport(
        target=url,
        crawled_endpoints=len(sitemap.endpoints),
        crawled_forms=len(sitemap.forms),
        fuzzed_requests=len(candidate_requests),
        technologies=sitemap.technologies,
        wafs=sitemap.wafs,
        emails=sitemap.emails,
        findings=list(sitemap.signals),
    )

    all_new_findings: list[Finding] = []

    # Active plugins - filtered by --plugin / --skip-plugin
    from .plugins import active_plugins, evilspider_plugin
    active = active_plugins(only=plugins, skip=skip_plugins)
    evilspider_plugin.configure(proxy=proxy)

    # Step 2: Auto-Fuzz and Security Audit on each candidate request
    for req in candidate_requests:
        # A. Smart Parameter Fuzzing
        if fuzz and (req.params or req.body_form or req.body_json):
            try:
                fuzz_res = run_fuzz(
                    req,
                    session,
                    include_state_fields=include_state_fields,
                    concurrency=12,
                )
                for anom in fuzz_res.get("results", []):
                    anom["target_url"] = req.url
                    anom["method"] = req.method
                    report.anomalies.append(anom)
                    anom_list = anom.get("anomalies") or (
                        [anom.get("anomaly")] if anom.get("anomaly") else []
                    )
                    primary_anom = anom.get("anomaly") or (
                        anom_list[0] if anom_list else "unknown"
                    )
                    if any(
                        a
                        in (
                            "error_leak",
                            "status_change",
                            "new_auth_cookie",
                            "sql_error",
                        )
                        for a in anom_list
                    ):
                        is_high = any(
                            a in ("error_leak", "sql_error") for a in anom_list
                        )
                        all_new_findings.append(
                            Finding(
                                id=f"fuzz-{req.method}-{anom.get('label')}",
                                type=f"fuzz_{primary_anom}",
                                severity="high" if is_high else "medium",
                                location=f"{req.method} {req.url} ({anom.get('label')})",
                                evidence=anom.get("detail", ""),
                                suggestion="Validate parameter inputs and handle exceptions gracefully.",
                            )
                        )
            except (httpx.HTTPError, OSError, TimeoutError, ValueError):
                pass

        # B. SQL Injection Heuristic Scanner
        if sqli and (req.params or req.body_form or req.body_json or req.body_raw):
            try:
                sqli_res = scan_sqli(
                    req,
                    session=session,
                    include_state_fields=include_state_fields,
                    only_plugins=[p.name for p in active],
                    skip_plugins=[],
                )
                for v in sqli_res.vulnerabilities:
                    report.sqli_vulnerabilities.append(v)
                    all_new_findings.append(
                        Finding(
                            id=f"sqli-{v.param}-{v.injection_type}",
                            type=f"sqli_{v.injection_type}",
                            severity=(
                                "high"
                                if v.confidence in ("confirmed", "high")
                                else "medium"
                            ),
                            location=f"{req.method} {req.url} ({v.param})",
                            evidence=v.evidence,
                            suggestion=v.suggestion,
                        )
                    )
            except (httpx.HTTPError, OSError, TimeoutError, ValueError):
                pass

        # C. XSS & Reflection Auditor
        if xss and (req.params or req.body_form or req.body_json):
            try:
                xss_res = scan_xss(
                    req,
                    session=session,
                    include_state_fields=include_state_fields,
                )
                for r in xss_res.reflections:
                    if r.confidence in ("confirmed", "high", "medium"):
                        report.xss_reflections.append(r)
                        all_new_findings.append(
                            Finding(
                                id=f"xss-{r.param}-{r.context}",
                                type=f"xss_{r.context}",
                                severity=(
                                    "high"
                                    if r.confidence in ("confirmed", "high")
                                    else "medium"
                                ),
                                location=f"{req.method} {req.url} ({r.param})",
                                evidence=r.evidence,
                                suggestion=r.suggestion,
                            )
                        )
            except (httpx.HTTPError, OSError, TimeoutError, ValueError):
                pass

        # D. Open Redirect Auditor
        if redirect and (req.params or req.body_form or req.body_json):
            try:
                red_res = scan_redirect(
                    req,
                    session=session,
                    include_state_fields=include_state_fields,
                )
                for rf in red_res.findings:
                    report.redirect_findings.append(rf)
                    all_new_findings.append(
                        Finding(
                            id=f"redirect-{rf.param}-{rf.redirect_type}",
                            type=f"open_redirect_{rf.redirect_type}",
                            severity=(
                                "high" if rf.confidence == "confirmed" else "medium"
                            ),
                            location=f"{req.method} {req.url}",
                            evidence=rf.evidence,
                            suggestion=rf.suggestion,
                        )
                    )
            except (httpx.HTTPError, OSError, TimeoutError, ValueError):
                pass

        # E. Path Traversal Auditor
        if traversal and (req.params or req.body_form or req.body_json):
            try:
                trav_res = scan_traversal(
                    req,
                    session=session,
                    include_state_fields=include_state_fields,
                )
                for tf in trav_res.findings:
                    report.traversal_findings.append(tf)
                    all_new_findings.append(
                        Finding(
                            id=f"traversal-{tf.param}-{tf.target_file}",
                            type="path_traversal",
                            severity="high",
                            location=f"{req.method} {req.url} ({tf.param})",
                            evidence=tf.evidence,
                            suggestion=tf.suggestion,
                        )
                    )
            except (httpx.HTTPError, OSError, TimeoutError, ValueError):
                pass

        # F. CORS Auditor
        if cors:
            try:
                from .cors import scan_cors

                cors_res = scan_cors(req, session=session)
                for cf in cors_res.findings:
                    report.cors_findings.append(cf)
                    all_new_findings.append(
                        Finding(
                            id=f"cors-{cf.misconfig_type}-{req.url[:16]}",
                            type=f"cors_{cf.misconfig_type}",
                            severity="high" if cf.confidence in ("confirmed", "high") else "medium",
                            location=f"{req.method} {req.url}",
                            evidence=cf.evidence,
                            suggestion=cf.suggestion,
                        )
                    )
            except (httpx.HTTPError, OSError, TimeoutError, ValueError):
                pass

    # Step 2b: Audit discovered login forms for SQL auth bypass and default credentials
    if sqli or default_creds:
        from .login import audit_login_forms, login_forms_from_forms

        login_forms = login_forms_from_forms(sitemap.forms)
        if login_forms:
            try:
                login_res = audit_login_forms(
                    login_forms,
                    target=url,
                    timeout=timeout,
                    verify=verify,
                    emails=sitemap.emails,
                    test_default_creds=default_creds,
                )
                report.login_bypasses = login_res.bypasses
                for b in login_res.bypasses:
                    is_cred = b.param == "credentials" and ":" in b.payload
                    finding_type = (
                        "default_credentials" if is_cred else "login_sqli_bypass"
                    )
                    all_new_findings.append(
                        Finding(
                            id=f"login-{finding_type}-{b.payload[:16]}",
                            type=finding_type,
                            severity=(
                                "high"
                                if b.confidence in ("confirmed", "high")
                                else "medium"
                            ),
                            location=f"{url} ({b.param})",
                            evidence=b.evidence,
                            suggestion=b.suggestion,
                        )
                    )
            except (httpx.HTTPError, OSError, TimeoutError, ValueError):
                pass

    # Step 2c: Admin Panel discovery and smart credential auditing
    try:
        from .admin import find_admin_panels

        admin_panels = await find_admin_panels(
            url,
            timeout=timeout,
            verify=verify,
            workers=workers,
        )
        report.admin_panels = admin_panels
        for ap in admin_panels:
            if ap.auth_type == "exposed_dashboard":
                all_new_findings.append(
                    Finding(
                        id=f"admin-exposed-{ap.path.strip('/')}",
                        type="admin_panel_exposed",
                        severity="high",
                        location=ap.url,
                        evidence=f"Administrative dashboard exposed without authentication: {ap.evidence}",
                        suggestion="Enforce strict authentication and restrict access to authorized IP ranges.",
                    )
                )
            elif ap.auth_type in ("login_form", "basic_auth", "portal_redirect"):
                all_new_findings.append(
                    Finding(
                        id=f"admin-panel-{ap.path.strip('/')}",
                        type="admin_panel_found",
                        severity="medium",
                        location=ap.url,
                        evidence=f"Administrative portal discovered: {ap.evidence}",
                        suggestion="Verify that the administrative interface is protected by multi-factor authentication (MFA) and rate limiting.",
                    )
                )

        admin_login_forms = [p.login_form for p in admin_panels if p.login_form]
        if (sqli or default_creds) and admin_login_forms:
            existing_actions = (
                {f.action for f in login_forms}
                if "login_forms" in locals() and login_forms
                else set()
            )
            new_admin_forms = [
                f for f in admin_login_forms if f.action not in existing_actions
            ]
            if new_admin_forms:
                try:
                    admin_res = audit_login_forms(
                        new_admin_forms,
                        target=url,
                        timeout=timeout,
                        verify=verify,
                        emails=sitemap.emails,
                        test_default_creds=default_creds,
                    )
                    report.login_bypasses.extend(admin_res.bypasses)
                    for b in admin_res.bypasses:
                        is_cred = b.param == "credentials" and ":" in b.payload
                        finding_type = (
                            "default_credentials" if is_cred else "login_sqli_bypass"
                        )
                        all_new_findings.append(
                            Finding(
                                id=f"admin-login-{finding_type}-{b.payload[:16]}",
                                type=finding_type,
                                severity=(
                                    "high"
                                    if b.confidence in ("confirmed", "high")
                                    else "medium"
                                ),
                                location=f"{url} ({b.param})",
                                evidence=b.evidence,
                                suggestion=b.suggestion,
                            )
                        )
                except (httpx.HTTPError, OSError, TimeoutError, ValueError):
                    pass
    except (httpx.HTTPError, OSError, TimeoutError, ValueError):
        pass

    # Step 2d: Stored XSS audit — submit canaries through discovered forms
    # and verify unencoded rendering on later page views.
    if stored_xss and sitemap.forms:
        from .stored_xss import audit_stored_xss

        try:
            sxss_res = audit_stored_xss(
                sitemap.forms,
                target=url,
                timeout=timeout,
                verify=verify,
            )
            for f in sxss_res.findings:
                report.stored_xss_findings.append(f)
                all_new_findings.append(
                    Finding(
                        id=f"stored-xss-{f.param}-{f.context}",
                        type=f"stored_xss_{f.context}",
                        severity="high",
                        location=f"{f.method} {f.form_action} ({f.param}) -> {f.render_url}",
                        evidence=f.evidence,
                        suggestion=f.suggestion,
                    )
                )
        except (httpx.HTTPError, OSError, TimeoutError, ValueError):
            pass

    # Step 3: Check for file upload forms and upload endpoints
    if upload:
        audited_upload_urls: set[str] = set()
        for f in sitemap.forms:
            file_inputs = [inp for inp in f.inputs if inp.type == "file"]
            if file_inputs:
                action_url = f.action
                clean_action = (
                    action_url.split("?", 1)[0] if "?" in action_url else action_url
                )
                audited_upload_urls.add(clean_action)
                for finp in file_inputs:
                    try:
                        up_req = Request(
                            method=(f.method or "POST").upper(),
                            url=clean_action,
                            verify=verify,
                            source="form",
                        )
                        up_res = audit_file_upload(
                            up_req, session=session, file_field=finp.name
                        )
                        for uf in up_res.findings:
                            report.upload_findings.append(uf)
                            all_new_findings.append(
                                Finding(
                                    id=f"upload-{uf.param}-{uf.vulnerability_type}",
                                    type=f"upload_{uf.vulnerability_type}",
                                    severity=(
                                        "high"
                                        if uf.confidence in ("confirmed", "high")
                                        else "medium"
                                    ),
                                    location=f"{up_req.method} {up_req.url} ({uf.param})",
                                    evidence=uf.evidence,
                                    suggestion=uf.suggestion,
                                )
                            )
                    except (httpx.HTTPError, OSError, TimeoutError, ValueError):
                        pass

        # Also audit any discovered endpoints matching upload patterns
        for ep in sitemap.endpoints:
            clean_ep = ep.url.split("?", 1)[0]
            if clean_ep not in audited_upload_urls and re.search(
                r"/(?:upload|avatar|attachment|photo|media)(?:/|\.|\?|$)",
                clean_ep,
                re.IGNORECASE,
            ):
                audited_upload_urls.add(clean_ep)
                try:
                    up_req = Request(
                        method="POST",
                        url=clean_ep,
                        verify=verify,
                        source="crawler",
                    )
                    up_res = audit_file_upload(up_req, session=session)
                    for uf in up_res.findings:
                        report.upload_findings.append(uf)
                        all_new_findings.append(
                            Finding(
                                id=f"upload-{uf.param}-{uf.vulnerability_type}",
                                type=f"upload_{uf.vulnerability_type}",
                                severity=(
                                    "high"
                                    if uf.confidence in ("confirmed", "high")
                                    else "medium"
                                ),
                                location=f"{up_req.method} {up_req.url} ({uf.param})",
                                evidence=uf.evidence,
                                suggestion=uf.suggestion,
                            )
                        )
                except (httpx.HTTPError, OSError, TimeoutError, ValueError):
                    pass

    if all_new_findings:
        report.findings.extend(all_new_findings)
        workspace.add_findings(all_new_findings)

    # Step 4: Passive template scanning on key discovered URLs
    # Passive templates don't send requests - they analyze responses we already have
    from .templates import load_builtin_templates
    from .templates.engine import _evaluate_matcher
    passive_templates = [t for t in load_builtin_templates() if t.passive]
    if passive_templates:
        key_urls = set()
        key_urls.add(url)
        for ep in sitemap.endpoints[:20]:
            if ep.status == 200:
                key_urls.add(ep.url)
        # Also include JS files discovered during crawl
        for js_file in sitemap.js_files[:10]:
            key_urls.add(js_file.url)

        passive_findings = []
        for target_url in key_urls:
            try:
                with httpx.Client(timeout=timeout, verify=verify, trust_env=False) as client:
                    resp = client.get(target_url, headers={"User-Agent": "darco/0.1 (pentest assistant)"})
                    for tmpl in passive_templates:
                        for req in tmpl.requests:
                            all_matched = True
                            for m in req.matchers:
                                m_ok, _ = _evaluate_matcher(m, resp, 0.0)
                                if not m_ok:
                                    all_matched = False
                                    break
                            if all_matched:
                                passive_findings.append(
                                    Finding(
                                        id=f"passive-{tmpl.id}-{hash(target_url) & 0xFFFF:04x}",
                                        type=f"passive_{tmpl.id.replace('-', '_')}",
                                        severity=tmpl.info.severity,
                                        location=target_url,
                                        evidence=f"Passive match: {tmpl.info.name} on {target_url}",
                                        suggestion=tmpl.info.remediation,
                                    )
                                )
                                break
            except (httpx.HTTPError, OSError, TimeoutError):
                continue

        if passive_findings:
            report.findings.extend(passive_findings)
            workspace.add_findings(passive_findings)

    return report


__all__ = ["run_auto_scan"]
