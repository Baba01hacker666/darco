from __future__ import annotations

from datetime import UTC, datetime
from urllib.parse import urlencode

import httpx

from .models import (
    BodyType,
    Cookie,
    HistoryRecord,
    NameValue,
    Request,
    Response,
    SessionState,
)
from .workspace import Workspace, merge_cookies

AUTH_HEADER_NAMES = {
    "authorization",
    "cookie",
    "proxy-authorization",
    "x-api-key",
    "x-auth-token",
    "x-csrf-token",
    "x-xsrf-token",
    "xsrf-token",
    "csrf-token",
    "x-requested-with",
}

CSRF_HEADER_NAMES = {"x-csrf-token", "x-xsrf-token", "xsrf-token", "csrf-token"}


def host_of(url: str) -> str:
    return (httpx.URL(url).host or "").lower()


def rebuild_url(url: str, params: list[NameValue]) -> str:
    """Re-append query params to a URL, replacing any existing query string."""
    if not params:
        return url.split("?", 1)[0]
    query = urlencode([(p.name, p.value) for p in params])
    return f"{url.split('?', 1)[0]}?{query}"


def effective_cookies(request: Request, session: SessionState) -> list[Cookie]:
    if request.session_stripped:
        return []
    explicit = {c.name for c in request.cookies}
    merged = list(request.cookies)
    for c in session.cookies:
        if c.name not in explicit:
            merged.append(c)
    return merged


def effective_headers(
    request: Request, session: SessionState, base_headers: list[NameValue] | None = None
) -> list[NameValue]:
    headers = list(request.headers)
    if request.session_stripped:
        headers = [h for h in headers if h.name.lower() not in AUTH_HEADER_NAMES]
    else:
        host = host_of(request.url)
        for csrf in session.csrf_headers.get(host, []):
            if csrf.name.lower() not in {h.name.lower() for h in headers}:
                headers.append(csrf)
    if base_headers:
        existing = {h.name.lower() for h in headers}
        for bh in base_headers:
            if bh.name.lower() not in existing:
                headers.append(bh)
    return headers


def execute(
    request: Request,
    session: SessionState,
    *,
    base_headers: list[NameValue] | None = None,
) -> tuple[httpx.Response, Response, SessionState]:
    """Low-level send. Returns (raw httpx response, darco Response model, updated session).

    The raw httpx response is exposed for the proxy so bytes can be forwarded exactly.
    """
    url = rebuild_url(request.url, request.params)
    cookies = httpx.Cookies()
    for c in effective_cookies(request, session):
        cookies.set(
            c.name,
            c.value,
            domain=c.domain or host_of(url),
            path=c.path or "/",
        )
    headers = [
        (h.name, h.value) for h in effective_headers(request, session, base_headers)
    ]

    content = None
    json_body = None
    data = None
    if request.body_type == BodyType.JSON:
        json_body = request.body_json if request.body_json is not None else {}
    elif request.body_type == BodyType.FORM:
        form_data: dict[str, list[str]] = {}
        for h in request.body_form:
            form_data.setdefault(h.name, []).append(h.value)
        data = {k: v if len(v) > 1 else v[0] for k, v in form_data.items()}
    elif request.body_type == BodyType.RAW:
        content = request.body_raw.encode(request.body_encoding)

    with httpx.Client(
        verify=request.verify, timeout=request.timeout, trust_env=False, cookies=cookies
    ) as client:
        resp = client.request(
            request.method,
            url,
            headers=headers,
            content=content,
            json=json_body,
            data=data,
            follow_redirects=request.follow_redirects,
        )

    body_bytes = resp.content
    try:
        body_text = body_bytes.decode("utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        body_text = body_bytes.decode("latin-1", errors="replace")

    redirects = [str(r.url) for r in resp.history]
    if request.follow_redirects and redirects:
        redirects.append(str(resp.url))

    set_cookies: list[Cookie] = []
    for c in resp.cookies.jar:
        set_cookies.append(
            Cookie(name=c.name, value=c.value, domain=c.domain, path=c.path)
        )

    response = Response(
        status_code=resp.status_code,
        reason=resp.reason_phrase or "",
        headers=[NameValue(name=k, value=v) for k, v in resp.headers.items()],
        body=body_text,
        body_len=len(body_bytes),
        url=str(resp.url),
        elapsed_ms=round(resp.elapsed.total_seconds() * 1000),
        redirects=redirects,
        set_cookies=set_cookies,
    )

    update_session(session, request, response)
    return resp, response, session


def send_request(
    request: Request,
    session: SessionState,
    *,
    base_headers: list[NameValue] | None = None,
) -> tuple[Response, SessionState]:
    """Send a Request, returning the Response and the updated SessionState."""
    try:
        _, response, session = execute(request, session, base_headers=base_headers)
        return response, session
    except httpx.HTTPError as exc:
        raise _EngineError(f"request failed: {exc}") from exc


def send_and_record(
    workspace: Workspace,
    request: Request,
    session: SessionState,
    *,
    base_headers: list[NameValue] | None = None,
) -> tuple[HistoryRecord, SessionState]:
    """Send a request, record it in workspace history, persist session. Returns (record, session)."""
    record_id = workspace.next_id()
    try:
        response, session = send_request(request, session, base_headers=base_headers)
        error = None
    except _EngineError as exc:
        response = None
        error = str(exc)
    record = HistoryRecord(
        id=record_id,
        ts=datetime.now(UTC).isoformat(),
        request=request,
        response=response,
        error=error,
    )
    workspace.add_history(record)
    workspace.save_session(session)
    return record, session


def update_session(session: SessionState, request: Request, response: Response) -> None:
    """Public: apply Set-Cookie and CSRF header capture to the session."""
    if request.session_stripped:
        return
    host = host_of(response.url) or host_of(request.url)
    session.cookies = merge_cookies(session.cookies, response.set_cookies, host)
    for h in response.headers:
        if h.name.lower() in CSRF_HEADER_NAMES and h.value:
            entries = session.csrf_headers.setdefault(host, [])
            entries = [e for e in entries if e.name.lower() != h.name.lower()]
            entries.append(NameValue(name=h.name, value=h.value))
            session.csrf_headers[host] = entries


class _EngineError(Exception):
    pass


__all__ = [
    "effective_cookies",
    "effective_headers",
    "execute",
    "host_of",
    "rebuild_url",
    "send_and_record",
    "send_request",
]
