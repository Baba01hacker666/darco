from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from urllib.parse import urlsplit

import httpx

from ..detection import detect_technologies, detect_waf
from ..models import Cookie, Finding, NameValue, PassiveReport, Request, Response
from .crtsh import enumerate_subdomains_crtsh
from .dns import enumerate_dns
from .headers import audit_security_headers
from .security_txt import inspect_security_txt


def _extract_domain(target: str) -> tuple[str, str]:
    """Return (clean_domain, base_url)."""
    raw = target.strip()
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw
    split = urlsplit(raw)
    domain = split.hostname or raw
    base_url = f"{split.scheme}://{split.netloc}"
    return domain, base_url


async def run_passive_enum(
    target: str,
    *,
    subdomains: bool = True,
    dns: bool = True,
    security_txt: bool = True,
    headers: bool = True,
    timeout: float = 8.0,
    verify: bool = True,
) -> PassiveReport:
    """Perform passive intelligence gathering and security enumeration on a target."""
    domain, base_url = _extract_domain(target)
    now_iso = datetime.now(UTC).isoformat()

    report = PassiveReport(
        target=base_url,
        domain=domain,
        timestamp=now_iso,
    )

    all_findings: list[Finding] = []

    async with httpx.AsyncClient(
        timeout=timeout, verify=verify, trust_env=False, follow_redirects=True
    ) as client:
        # Run async reconnaissance tasks concurrently
        tasks = []
        if dns:
            tasks.append(("dns", enumerate_dns(domain, client)))
        if subdomains:
            tasks.append(
                ("crtsh", enumerate_subdomains_crtsh(domain, client, timeout=timeout))
            )
        if security_txt:
            tasks.append(("sec_txt", inspect_security_txt(base_url, client)))

        # Also fetch base page for headers, tech, and WAF fingerprinting
        async def fetch_base():
            try:
                resp = await client.get(
                    base_url, headers={"User-Agent": "darco/0.1 (passive recon)"}
                )
                return resp
            except (httpx.HTTPError, OSError, TimeoutError):
                return None

        tasks.append(("base_fetch", fetch_base()))

        # Execute concurrent tasks
        results = await asyncio.gather(*(t[1] for t in tasks), return_exceptions=True)

        for (task_name, _), res in zip(tasks, results):
            if isinstance(res, Exception):
                continue

            if task_name == "dns" and isinstance(res, tuple):
                dns_records, dns_findings = res
                report.dns_records = dns_records
                all_findings.extend(dns_findings)
                report.ip_addresses = [
                    r.value
                    for r in dns_records
                    if r.record_type in ("A", "AAAA")
                    and r.name.lower() == domain.lower()
                ]

            elif task_name == "crtsh" and isinstance(res, list):
                report.subdomains = res

            elif task_name == "sec_txt" and isinstance(res, tuple):
                sec_obj, sec_findings = res
                report.security_txt = sec_obj
                all_findings.extend(sec_findings)

            elif task_name == "base_fetch" and isinstance(res, httpx.Response):
                # Build Darco response model
                darco_resp = Response(
                    status_code=res.status_code,
                    reason=res.reason_phrase or "",
                    headers=[
                        NameValue(name=k, value=v) for k, v in res.headers.items()
                    ],
                    body=res.text,
                    body_len=len(res.content),
                    url=str(res.url),
                    elapsed_ms=round(res.elapsed.total_seconds() * 1000),
                    redirects=[str(r.url) for r in res.history],
                    set_cookies=[
                        Cookie(name=c.name, value=c.value, domain=c.domain, path=c.path)
                        for c in res.cookies.jar
                    ],
                )
                req_model = Request(method="GET", url=base_url)

                # Tech and WAF detection
                report.technologies = detect_technologies(darco_resp, req_model)
                report.wafs = detect_waf(darco_resp, req_model)

                # Headers audit
                if headers:
                    pres_hdrs, miss_hdrs, hdr_findings = audit_security_headers(
                        darco_resp, base_url
                    )
                    report.security_headers = pres_hdrs
                    report.missing_security_headers = miss_hdrs
                    all_findings.extend(hdr_findings)

    # Attach findings
    report.findings = all_findings
    return report
