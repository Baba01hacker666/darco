import asyncio
from pathlib import Path
from urllib.parse import urljoin, urlsplit

import httpx
from bs4 import BeautifulSoup

from .discovery.js_extractor import extract_detailed_js_endpoints
from .models import (
    ApiEndpoint,
    Finding,
    JsAnalysisReport,
    JsSecret,
)

CDN_DOMAINS = {
    "cdnjs.cloudflare.com",
    "cdn.jsdelivr.net",
    "cdn.jsdelivr.com",
    "unpkg.com",
    "ajax.googleapis.com",
    "code.jquery.com",
    "stackpath.bootstrapcdn.com",
    "maxcdn.bootstrapcdn.com",
    "cdn.tailwindcss.com",
    "use.fontawesome.com",
    "kit.fontawesome.com",
    "cdn.ampproject.org",
    "googletagmanager.com",
    "google-analytics.com",
    "analytics.google.com",
    "connect.facebook.net",
    "static.hotjar.com",
    "script.hotjar.com",
    "clarity.ms",
    "cdn.segment.com",
    "widget.intercom.io",
    "challenges.cloudflare.com",
    "recaptcha.net",
    "hcaptcha.com",
}


def is_cdn_or_vendor_script(script_url: str) -> bool:
    """Check if a script URL belongs to a 3rd-party CDN, tracker, or external library vendor."""
    u = urlsplit(script_url)
    hostname = (u.hostname or "").lower()

    for cdn in CDN_DOMAINS:
        if hostname == cdn or hostname.endswith("." + cdn):
            return True

    path_lower = u.path.lower()
    return any(
        tracker in hostname or tracker in path_lower
        for tracker in (
            "google-analytics",
            "googletagmanager",
            "facebook.net",
            "hotjar",
            "clarity.ms",
            "hcaptcha",
            "recaptcha",
        )
    )


def analyze_local_js(file_path: str) -> JsAnalysisReport:
    """Analyze a local JS file or bundle."""
    path = Path(file_path)
    if not path.exists():
        raise ValueError(f"file not found: {file_path}")

    text = path.read_text(encoding="utf-8", errors="replace")
    endpoints, secrets, chunks = extract_detailed_js_endpoints(
        text, source_name=path.name
    )

    gql = [ep.path for ep in endpoints if ep.is_graphql]
    findings = _generate_findings("local_file", endpoints, secrets)

    return JsAnalysisReport(
        target=str(path),
        js_files_analyzed=1,
        endpoints=endpoints,
        graphql_endpoints=gql,
        secrets=secrets,
        chunks_discovered=chunks,
        findings=findings,
    )


async def analyze_target_js(
    url: str,
    *,
    max_chunks: int = 50,
    ignore_cdn: bool = True,
    timeout: float = 10.0,
    verify: bool = True,
    headers: dict[str, str] | None = None,
) -> JsAnalysisReport:
    """Analyze all client-side JavaScript bundles, SPAs, and webpack chunks on a target URL."""
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    req_headers = {"User-Agent": "darco/0.1 (security assistant)"}
    if headers:
        req_headers.update(headers)

    all_endpoints_map: dict[tuple[str, str], ApiEndpoint] = {}
    all_secrets: list[JsSecret] = []
    seen_secrets = set()
    analyzed_scripts = 0
    all_chunks_discovered: list[str] = []
    fetched_script_urls: set[str] = set()

    async with httpx.AsyncClient(
        verify=verify, timeout=timeout, trust_env=False, headers=req_headers
    ) as client:
        # Step 1: Fetch HTML and extract inline and external scripts
        try:
            resp = await client.get(url, follow_redirects=True)
            base_url = str(resp.url)
            html_text = resp.text
        except (httpx.HTTPError, OSError, TimeoutError, ValueError):
            return JsAnalysisReport(target=url)

        soup = BeautifulSoup(html_text, "html.parser")
        script_tags = soup.find_all("script")

        script_urls_to_fetch: list[str] = []

        for tag in script_tags:
            src = tag.get("src")
            if src:
                resolved = urljoin(base_url, src)
                if ignore_cdn and is_cdn_or_vendor_script(resolved):
                    continue
                if resolved not in fetched_script_urls:
                    script_urls_to_fetch.append(resolved)
            else:
                inline_js = tag.string or tag.text or ""
                if inline_js.strip():
                    analyzed_scripts += 1
                    eps, secs, chunks = extract_detailed_js_endpoints(
                        inline_js, base_url=base_url, source_name="inline_script"
                    )
                    for ep in eps:
                        key = (ep.method, ep.path)
                        all_endpoints_map[key] = ep
                    for s in secs:
                        if s.value not in seen_secrets:
                            seen_secrets.add(s.value)
                            all_secrets.append(s)
                    for c in chunks:
                        if c not in all_chunks_discovered:
                            all_chunks_discovered.append(c)

        # Step 2: Fetch and analyze external script files
        async def _fetch_and_analyze(script_url: str):
            nonlocal analyzed_scripts
            if script_url in fetched_script_urls:
                return
            fetched_script_urls.add(script_url)
            try:
                r = await client.get(script_url, follow_redirects=True)
                if r.status_code == 200:
                    analyzed_scripts += 1
                    eps, secs, chunks = extract_detailed_js_endpoints(
                        r.text,
                        base_url=base_url,
                        source_name=script_url.split("/")[-1] or script_url,
                    )
                    for ep in eps:
                        key = (ep.method, ep.path)
                        all_endpoints_map[key] = ep
                    for s in secs:
                        if s.value not in seen_secrets:
                            seen_secrets.add(s.value)
                            all_secrets.append(s)
                    for c in chunks:
                        if c not in all_chunks_discovered:
                            all_chunks_discovered.append(c)
            except (httpx.HTTPError, OSError, TimeoutError, ValueError):
                pass

        if script_urls_to_fetch:
            await asyncio.gather(
                *[_fetch_and_analyze(su) for su in script_urls_to_fetch]
            )

        # Step 3: Fetch discovered chunks (e.g. webpack chunks / Next.js chunks)
        chunk_urls_to_fetch = []
        for c in all_chunks_discovered:
            c_url = urljoin(base_url, c)
            if ignore_cdn and is_cdn_or_vendor_script(c_url):
                continue
            if (
                c_url not in fetched_script_urls
                and len(chunk_urls_to_fetch) < max_chunks
            ):
                chunk_urls_to_fetch.append(c_url)

        if chunk_urls_to_fetch:
            await asyncio.gather(
                *[_fetch_and_analyze(cu) for cu in chunk_urls_to_fetch]
            )

    endpoints_list = sorted(
        all_endpoints_map.values(), key=lambda e: (e.method, e.path)
    )
    gql_list = [ep.path for ep in endpoints_list if ep.is_graphql]
    findings = _generate_findings(url, endpoints_list, all_secrets)

    return JsAnalysisReport(
        target=url,
        js_files_analyzed=analyzed_scripts,
        endpoints=endpoints_list,
        graphql_endpoints=gql_list,
        secrets=all_secrets,
        chunks_discovered=all_chunks_discovered,
        findings=findings,
    )


def _generate_findings(
    target: str, endpoints: list[ApiEndpoint], secrets: list[JsSecret]
) -> list[Finding]:
    """Generate structured security findings from discovered JS secrets and high-interest API routes."""
    findings: list[Finding] = []

    # 1. Hardcoded secrets
    for s in secrets:
        sev = (
            "high"
            if s.type
            in ("jwt_token", "aws_access_key", "google_api_key", "bearer_token")
            else "medium"
        )
        findings.append(
            Finding(
                id=f"js-secret-{s.type}",
                type=f"js_{s.type}",
                severity=sev,
                location=f"{s.source_js}",
                evidence=f"Discovered {s.type}: {s.value[:40]}... in {s.source_js}",
                suggestion="Remove hardcoded API keys and credentials from client-facing JavaScript bundles.",
            )
        )

    # 2. Sensitive API routes
    for ep in endpoints:
        p_lower = ep.path.lower()
        if any(
            term in p_lower
            for term in ("/admin", "/internal", "/debug", "/swagger", "/actuator")
        ):
            findings.append(
                Finding(
                    id=f"js-route-{ep.method}-{ep.path[:30]}",
                    type="exposed_internal_route",
                    severity="medium",
                    location=f"{ep.method} {ep.path}",
                    evidence=f"Internal / Admin API route exposed in client JS ({ep.source_js}): {ep.context_snippet}",
                    suggestion="Ensure internal and administrative routes enforce strict backend access control and authentication.",
                )
            )

    return findings


__all__ = ["analyze_local_js", "analyze_target_js"]
