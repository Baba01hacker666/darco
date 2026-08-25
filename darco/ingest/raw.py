from __future__ import annotations

import json as _json
import re
from urllib.parse import parse_qsl, urlsplit

from ..errors import DarcoError
from ..models import BodyType, Cookie, NameValue, Request


def parse_raw_http(text: str, *, scheme: str | None = None, source: str = "raw") -> Request:
    """Parse a raw HTTP request (Burp 'copy as http request' style) into a Request."""
    text = text.replace("\r\n", "\n")
    if "\n\n" in text:
        head, _, body = text.partition("\n\n")
    else:
        head, body = text, ""
    lines = [ln for ln in head.split("\n") if ln.strip() != ""]
    if not lines:
        raise DarcoError("empty raw request")

    m = re.match(r"^(\S+)\s+(\S+)(?:\s+HTTP/\S+)?$", lines[0])
    if not m:
        raise DarcoError(f"invalid request line: {lines[0]!r}")
    method, target = m.group(1).upper(), m.group(2)

    headers: list[NameValue] = []
    for line in lines[1:]:
        name, sep, value = line.partition(":")
        if not sep:
            raise DarcoError(f"invalid header line: {line!r}")
        headers.append(NameValue(name=name.strip(), value=value.strip()))

    host = next((h.value for h in headers if h.name.lower() == "host"), None)
    if target.startswith(("http://", "https://")):
        url = target
    else:
        if host is None:
            raise DarcoError("raw request has no Host header and no absolute URL")
        scheme = scheme or ("https" if ":443" in host or host.endswith(":443") else "http")
        url = f"{scheme}://{host}{target}"

    cookies: list[Cookie] = []
    cookie_headers = [h.value for h in headers if h.name.lower() == "cookie"]
    if cookie_headers:
        headers = [h for h in headers if h.name.lower() != "cookie"]
        for cookie_header in cookie_headers:
            for part in cookie_header.split(";"):
                part = part.strip()
                if part:
                    cname, _, cvalue = part.partition("=")
                    cookies.append(Cookie(name=cname.strip(), value=cvalue.strip()))

    params: list[NameValue] = []
    split = urlsplit(url)
    if split.query:
        params.extend(NameValue(name=k, value=v) for k, v in parse_qsl(split.query, keep_blank_values=True))
        url = url.split("?", 1)[0]

    body_type = BodyType.NONE
    body_json = None
    body_form: list[NameValue] = []
    body_raw = ""
    if body:
        ctype = next((h.value for h in headers if h.name.lower() == "content-type"), "").lower()
        if "json" in ctype:
            body_type = BodyType.JSON
            try:
                body_json = _json.loads(body)
            except _json.JSONDecodeError:
                body_type = BodyType.RAW
                body_raw = body
        elif "x-www-form-urlencoded" in ctype:
            body_type = BodyType.FORM
            body_form = [NameValue(name=k, value=v) for k, v in parse_qsl(body, keep_blank_values=True)]
        else:
            body_type = BodyType.RAW
            body_raw = body

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
