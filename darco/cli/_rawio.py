"""Raw HTTP request/response serialization helpers."""

from __future__ import annotations

import json
from urllib.parse import urlencode, urlsplit

from ..models import BodyType, NameValue, Request


# ------------------------------------------------------------------ raw serialization helpers
def _request_body_bytes(req: Request) -> bytes:
    if req.body_type == BodyType.JSON:
        return (json.dumps(req.body_json) if req.body_json is not None else "").encode(
            "utf-8"
        )
    if req.body_type == BodyType.FORM:
        return urlencode([(p.name, p.value) for p in req.body_form]).encode("utf-8")
    if req.body_type == BodyType.RAW:
        return req.body_raw.encode(req.body_encoding)
    return b""


def _raw_request(req: Request) -> str:
    u = urlsplit(req.url)
    target = u.path or "/"
    if u.query:
        target += "?" + u.query
    lines = [f"{req.method} {target} HTTP/1.1"]
    headers = list(req.headers)
    if not any(h.name.lower() == "host" for h in headers):
        headers.insert(0, NameValue(name="Host", value=u.netloc))
    lines.extend(f"{h.name}: {h.value}" for h in headers)
    body = _request_body_bytes(req)
    if body:
        lines.append("")
        lines.append(body.decode(req.body_encoding, errors="replace"))
    return "\r\n".join(lines)


def _raw_response(resp) -> str:
    lines = [f"HTTP/1.1 {resp.status_code} {resp.reason}"]
    lines.extend(f"{h.name}: {h.value}" for h in resp.headers)
    if resp.body:
        lines.append("")
        lines.append(resp.body)
    return "\r\n".join(lines)
