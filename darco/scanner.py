from urllib.parse import parse_qsl

import httpx

from .discovery.crawler import discover
from .fuzz import run_fuzz
from .models import (
    AutoScanReport,
    BodyType,
    Finding,
    NameValue,
    Request,
    SiteMap,
)
from .sqli import scan_sqli
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
        if "?" in ep.url:
            clean_url = ep.url.split("?", 1)[0]
            query = ep.url.split("?", 1)[1]
            params = [
                NameValue(name=k, value=v)
                for k, v in parse_qsl(query, keep_blank_values=True)
            ]
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
        clean_action = (
            action_url.split("?", 1)[0] if "?" in action_url else action_url
        )

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
    timeout: float = 10.0,
    verify: bool = True,
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
        findings=list(sitemap.signals),
    )

    all_new_findings: list[Finding] = []

    # Step 2: Auto-Fuzz and Security Audit on each candidate request
    for req in candidate_requests:
        # A. Smart Parameter Fuzzing
        if fuzz and (req.params or req.body_form or req.body_json):
            try:
                fuzz_res = run_fuzz(req, session)
                for anom in fuzz_res.get("results", []):
                    anom["target_url"] = req.url
                    anom["method"] = req.method
                    report.anomalies.append(anom)
                    if anom.get("anomaly") in (
                        "error_leak",
                        "status_change",
                        "new_auth_cookie",
                    ):
                        all_new_findings.append(
                            Finding(
                                id=f"fuzz-{req.method}-{anom.get('label')}",
                                type=f"fuzz_{anom.get('anomaly')}",
                                severity="medium"
                                if anom.get("anomaly") != "error_leak"
                                else "high",
                                location=f"{req.method} {req.url} ({anom.get('label')})",
                                evidence=anom.get("detail", ""),
                                suggestion="Validate parameter inputs and handle exceptions gracefully.",
                            )
                        )
            except (httpx.HTTPError, OSError, TimeoutError, ValueError):
                pass

        # B. SQL Injection Heuristic Scanner
        if sqli and (req.params or req.body_form or req.body_json):
            try:
                sqli_res = scan_sqli(req, session=session)
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
                xss_res = scan_xss(req, session=session)
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

    if all_new_findings:
        report.findings.extend(all_new_findings)
        workspace.add_findings(all_new_findings)

    return report


__all__ = ["run_auto_scan"]
