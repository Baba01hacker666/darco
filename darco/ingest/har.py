from __future__ import annotations

import json
from pathlib import Path

from ..errors import DarcoError
from ..models import BodyType, Cookie, NameValue, Request


def parse_har(text_or_path: str | Path, *, source: str = "har") -> list[Request]:
    """Parse a HAR file into a list of Requests (one per entry)."""
    p = Path(text_or_path)
    if p.exists():
        try:
            data = json.loads(p.read_text())
        except Exception as exc:  # noqa: BLE001
            raise DarcoError(f"invalid HAR file: {exc}") from exc
    else:
        try:
            data = json.loads(text_or_path)
        except Exception as exc:  # noqa: BLE001
            raise DarcoError(f"invalid HAR payload: {exc}") from exc

    entries = data.get("log", {}).get("entries", [])
    if not entries and isinstance(data, list):
        entries = data
    requests: list[Request] = []
    for entry in entries:
        req = entry.get("request")
        if not req:
            continue
        requests.append(_request_from_har(req, source=source))
    if not requests:
        raise DarcoError("no request entries found in HAR")
    return requests


def _request_from_har(req: dict, *, source: str) -> Request:
    method = req.get("method", "GET").upper()
    url = req.get("url", "").split("?", 1)[0]
    headers = [
        NameValue(name=h.get("name", ""), value=h.get("value", ""))
        for h in req.get("headers", [])
        if h.get("name", "").lower() not in {"content-length", "host"}
    ]
    cookies = [
        Cookie(name=c.get("name", ""), value=c.get("value", ""))
        for c in req.get("cookies", [])
    ]
    params = [
        NameValue(name=q.get("name", ""), value=q.get("value", ""))
        for q in req.get("queryString", [])
    ]

    body_type = BodyType.NONE
    body_json = None
    body_form: list[NameValue] = []
    body_raw = ""
    post = req.get("postData")
    if post and post.get("text"):
        mime = (post.get("mimeType") or "").lower()
        text = post.get("text", "")
        if "json" in mime:
            try:
                body_json = json.loads(text)
                body_type = BodyType.JSON
            except json.JSONDecodeError:
                body_raw = text
                body_type = BodyType.RAW
        elif "x-www-form-urlencoded" in mime:
            body_form = [NameValue(name=p.get("name", ""), value=p.get("value", "")) for p in post.get("params", [])]
            body_type = BodyType.FORM
        else:
            body_raw = text
            body_type = BodyType.RAW

    return Request(
        method=method,
        url=url,
        headers=headers,
        cookies=cookies,
        params=params,
        body_type=body_type,
        body_json=body_json,
        body_form=body_form,
        body_raw=body_raw,
        source=source,
    )
