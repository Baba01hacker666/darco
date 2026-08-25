from __future__ import annotations

import asyncio
import re
from datetime import UTC, datetime
from urllib.parse import parse_qsl, urljoin, urlsplit

import httpx
from bs4 import BeautifulSoup

from ..analyze import analyze_response
from ..models import (
    Cookie,
    Endpoint,
    Finding,
    Form,
    JsFile,
    NameValue,
    Request,
    Response,
    SiteMap,
)
from ..workspace import Workspace
from .js_extractor import extract_js_endpoints
from .parsers import (
    extract_forms,
    extract_links,
    extract_meta_refresh,
    extract_scripts,
    is_html,
)

_finding_counter = 0


def _finding(
    f_type: str, location: str, evidence: str, suggestion: str, severity: str = "info"
) -> Finding:
    global _finding_counter
    _finding_counter += 1
    return Finding(
        id=f"c{_finding_counter}",
        type=f_type,
        severity=severity,
        location=location,
        evidence=evidence[:500],
        suggestion=suggestion,
    )


def normalize_url(url: str, base: str | None = None) -> str | None:
    if base:
        url = urljoin(base, url)
    if not url:
        return None
    try:
        u = urlsplit(url)
    except ValueError:
        return None
    if u.scheme not in ("http", "https"):
        return None
    host = (u.hostname or "").lower()
    if not host:
        return None
    port = u.port
    default_port = (u.scheme == "http" and port == 80) or (
        u.scheme == "https" and port == 443
    )
    netloc = host if (port is None or default_port) else f"{host}:{port}"
    return f"{u.scheme}://{netloc}{u.path or '/'}" + (f"?{u.query}" if u.query else "")


def same_origin(a: str, b: str) -> bool:
    return urlsplit(a).netloc.lower() == urlsplit(b).netloc.lower()


async def discover(
    workspace: Workspace,
    start_url: str,
    *,
    depth: int = 3,
    max_urls: int = 500,
    workers: int = 5,
    seeds: tuple[str, ...] = (),
    parse_js: bool = True,
    timeout: float = 10.0,
    verify: bool = True,
) -> SiteMap:
    """Crawl a target and build a SiteMap. Updates workspace session and findings."""
    session = workspace.load_session()
    sitemap = SiteMap(target=start_url, crawled_at=datetime.now(UTC).isoformat())
    start = normalize_url(start_url)
    if not start:
        raise ValueError(f"invalid start URL: {start_url!r}")

    visited: set[str] = set()
    queue: asyncio.Queue[tuple[str, int]] = asyncio.Queue()
    endpoint_by_url: dict[str, Endpoint] = {}
    forms: list[Form] = []
    js_files: dict[str, JsFile] = {}
    signals: list[Finding] = []
    errors = 0
    max_urls_reached = False

    robots, seed_urls = await _load_seeds(start, timeout, verify)
    sitemap.robots = robots
    for r in robots:
        resolved = normalize_url(urljoin(start, r), start)
        if resolved and resolved not in endpoint_by_url:
            endpoint_by_url[resolved] = Endpoint(
                url=resolved,
                methods=["GET"],
                source="robots",
                notes=["path listed in robots.txt (Disallow); not crawled"],
            )

    for seed in list(seeds) + seed_urls:
        normalized = normalize_url(seed, start)
        if normalized and normalized not in visited:
            await queue.put((normalized, 0))
    if queue.empty():
        await queue.put((start, 0))

    async with httpx.AsyncClient(
        timeout=timeout,
        verify=verify,
        trust_env=False,
        follow_redirects=True,
        cookies=_to_httpx_cookies(session),
    ) as client:
        pending = 0

        async def worker() -> None:
            nonlocal pending, errors, max_urls_reached
            while True:
                try:
                    url, d = await asyncio.wait_for(queue.get(), timeout=0.3)
                except TimeoutError:
                    if pending == 0 and queue.empty():
                        return
                    continue
                pending += 1
                try:
                    if url in visited:
                        continue
                    if len(visited) >= max_urls:
                        max_urls_reached = True
                        continue
                    visited.add(url)
                    try:
                        await _process(
                            client,
                            start,
                            url,
                            d,
                            endpoint_by_url,
                            forms,
                            js_files,
                            signals,
                            parse_js,
                            timeout,
                            verify,
                            queue,
                            visited,
                            depth,
                            max_urls,
                        )
                    except (TimeoutError, httpx.HTTPError, OSError):
                        errors += 1
                finally:
                    pending -= 1
                    queue.task_done()

        tasks = [asyncio.create_task(worker()) for _ in range(max(1, workers))]
        await queue.join()
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

    workspace.save_session(session)
    workspace.add_findings(signals)
    sitemap.endpoints = sorted(endpoint_by_url.values(), key=lambda e: e.url)
    sitemap.forms = forms
    sitemap.js_files = sorted(js_files.values(), key=lambda j: j.url)
    sitemap.signals = signals
    sitemap.stats = {
        "visited": len(visited),
        "errors": errors,
        "endpoints": len(sitemap.endpoints),
        "forms": len(forms),
        "js_files": len(js_files),
        "signals": len(signals),
        "max_urls_reached": int(max_urls_reached),
    }
    workspace.save_sitemap(sitemap)
    return sitemap


async def _load_seeds(
    start: str, timeout: float, verify: bool
) -> tuple[list[str], list[str]]:
    robots: list[str] = []
    seed_urls: list[str] = []
    try:
        async with httpx.AsyncClient(
            timeout=timeout, verify=verify, trust_env=False
        ) as client:
            for path, is_robots in (("/robots.txt", True), ("/sitemap.xml", False)):
                try:
                    resp = await client.get(urljoin(start, path))
                except httpx.HTTPError:
                    continue
                if resp.status_code != 200:
                    continue
                text = resp.text
                if is_robots:
                    for line in text.splitlines():
                        line = line.strip()
                        if line.lower().startswith("disallow:"):
                            value = line.split(":", 1)[1].strip()
                            if value and value != "/":
                                robots.append(value)
                else:
                    for m in re.finditer(
                        r"<loc>\s*(.+?)\s*</loc>", text, re.IGNORECASE
                    ):
                        seed_urls.append(m.group(1).strip())
    except httpx.HTTPError:
        pass
    return robots, seed_urls


async def _process(
    client: httpx.AsyncClient,
    start: str,
    url: str,
    d: int,
    endpoint_by_url: dict[str, Endpoint],
    forms: list[Form],
    js_files: dict[str, JsFile],
    signals: list[Finding],
    parse_js: bool,
    timeout: float,
    verify: bool,
    queue: asyncio.Queue,
    visited: set[str],
    depth: int,
    max_urls: int,
) -> None:
    resp = await client.get(
        url, headers={"User-Agent": "darco/0.1 (pentest assistant)"}
    )
    base = str(resp.url)
    content_type = resp.headers.get("content-type", "")

    key = _endpoint_key(url)
    endpoint = endpoint_by_url.setdefault(
        key, Endpoint(url=key, methods=["GET"], source="seed" if d == 0 else "link")
    )
    endpoint.status = resp.status_code
    endpoint.content_type = content_type.split(";")[0] or None
    redirects = [str(r.url) for r in resp.history]
    if resp.status_code in (401, 403) or any(
        "login" in r.lower() or "signin" in r.lower() for r in redirects
    ):
        endpoint.auth_required = True
    if resp.status_code == 429:
        signals.append(
            _finding(
                "rate_limited",
                url,
                "status 429 during crawl",
                "Site rate-limits crawling; slow down or use delays.",
                "medium",
            )
        )

    body = resp.text
    if is_html(content_type, body):
        soup = BeautifulSoup(body, "html.parser")
        children: list[str] = []
        for link in extract_links(soup, base) + extract_meta_refresh(soup, base):
            normalized = normalize_url(link, base)
            if not normalized or not same_origin(start, normalized):
                continue
            _record_endpoint(normalized, endpoint_by_url, source="link")
            children.append(normalized)
        for form in extract_forms(soup, base):
            forms.append(form)
            action = normalize_url(form.action, base)
            if action and same_origin(start, action):
                action = _endpoint_key(action)
                ep = endpoint_by_url.setdefault(
                    action, Endpoint(url=action, methods=[], source="form")
                )
                if form.method not in ep.methods:
                    ep.methods.append(form.method)
                for inp in form.inputs:
                    if inp.name and not any(p.name == inp.name for p in ep.params):
                        ep.params.append(NameValue(name=inp.name))
        if parse_js:
            for script_url in extract_scripts(soup, base):
                normalized = normalize_url(script_url, base)
                if not normalized or not same_origin(start, normalized):
                    continue
                if normalized not in js_files:
                    try:
                        js_resp = await client.get(normalized)
                    except httpx.HTTPError:
                        continue
                    js_endpoints = extract_js_endpoints(js_resp.text, normalized)
                    js_files[normalized] = JsFile(
                        url=normalized, endpoints=js_endpoints
                    )
                    for js_ep in js_endpoints:
                        resolved = normalize_url(js_ep, normalized)
                        if resolved and same_origin(start, resolved):
                            _record_endpoint(resolved, endpoint_by_url, source="js")
        if d < depth:
            for child in children:
                if len(visited) >= max_urls:
                    break
                if child not in visited:
                    await queue.put((child, d + 1))

    for f in analyze_response(
        Request(method="GET", url=url, source="crawl"), _response_from_httpx(resp)
    ):
        signals.append(_finding(f.type, url, f.evidence, f.suggestion, f.severity))
    path = urlsplit(url).path
    if re.search(
        r"/(admin|internal|debug|backup|api/v\d?|swagger|docs|env|\.git|config|test|dev|console|actuator)(/|$|\.|_)",
        path,
        re.IGNORECASE,
    ):
        signals.append(
            _finding(
                "interesting_path",
                url,
                f"path matches sensitive heuristic: {path}",
                "Verify access controls and whether this exposes internal functionality.",
                "medium",
            )
        )


def _endpoint_key(url: str) -> str:
    return url.split("?", 1)[0]


def _record_endpoint(
    normalized: str, endpoint_by_url: dict[str, Endpoint], *, source: str
) -> None:
    key = _endpoint_key(normalized)
    ep = endpoint_by_url.setdefault(
        key, Endpoint(url=key, methods=["GET"], source=source)
    )
    if "GET" not in ep.methods:
        ep.methods.append("GET")
    for k, v in parse_qsl(urlsplit(normalized).query, keep_blank_values=True):
        if not any(p.name == k for p in ep.params):
            ep.params.append(NameValue(name=k, value=v))


def _response_from_httpx(resp: httpx.Response) -> Response:
    set_cookies = [
        Cookie(name=c.name, value=c.value, domain=c.domain, path=c.path)
        for c in resp.cookies.jar
    ]
    return Response(
        status_code=resp.status_code,
        reason=resp.reason_phrase or "",
        headers=[NameValue(name=k, value=v) for k, v in resp.headers.items()],
        body=resp.text,
        body_len=len(resp.content),
        url=str(resp.url),
        elapsed_ms=round(resp.elapsed.total_seconds() * 1000),
        redirects=[str(r.url) for r in resp.history],
        set_cookies=set_cookies,
    )


def _to_httpx_cookies(session) -> httpx.Cookies:
    jar = httpx.Cookies()
    for c in session.cookies:
        jar.set(c.name, c.value, domain=c.domain, path=c.path or "/")
    return jar
