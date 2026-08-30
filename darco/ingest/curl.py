from __future__ import annotations

import base64
import json as _json
from urllib.parse import parse_qsl, urlencode, urlsplit

from ..errors import DarcoError
from ..models import BodyType, Cookie, NameValue, Request


def _tokenize(cmd: str) -> list[str]:
    tokens: list[str] = []
    cur: list[str] = []
    quote: str | None = None
    i = 0
    while i < len(cmd):
        ch = cmd[i]
        if quote:
            if ch == quote:
                quote = None
            elif ch == "\\" and quote == '"':
                i += 1
                if i < len(cmd):
                    cur.append(cmd[i])
            else:
                cur.append(ch)
        else:
            if ch in ("'", '"'):
                quote = ch
            elif ch.isspace():
                if cur:
                    tokens.append("".join(cur))
                    cur = []
            elif ch == "\\":
                i += 1
                if i < len(cmd):
                    cur.append(cmd[i])
            else:
                cur.append(ch)
        i += 1
    if cur:
        tokens.append("".join(cur))
    return tokens


def _split_flag(tok: str) -> tuple[str, str | None]:
    if tok.startswith("--") and "=" in tok:
        name, _, value = tok.partition("=")
        return name, value
    return tok, None


def _parse_header(h: str) -> NameValue:
    h = h.strip()
    if h.endswith(";"):
        return NameValue(name=h[:-1].strip(), value="")
    name, sep, value = h.partition(":")
    if not sep:
        raise DarcoError(f"invalid -H header (missing ':'): {h!r}")
    return NameValue(name=name.strip(), value=value.strip())


def _parse_cookies(raw: str) -> list[Cookie]:
    cookies: list[Cookie] = []
    for part in raw.split(";"):
        part = part.strip()
        if not part:
            continue
        name, _, value = part.partition("=")
        name = name.strip()
        if name.lower() in {
            "expires",
            "path",
            "domain",
            "max-age",
            "secure",
            "httponly",
            "samesite",
            "version",
        }:
            continue
        cookies.append(Cookie(name=name, value=value.strip()))
    return cookies


def _urlencode_value(value: str) -> str:
    return urlencode({"v": value})[2:]


def _encode_data_urlencode(arg: str) -> str:
    if arg.startswith("="):
        return _urlencode_value(arg[1:])
    name, sep, value = arg.partition("=")
    if sep:
        return f"{name}={_urlencode_value(value)}"
    return f"{name}={_urlencode_value(name)}"


def _ensure_content_type(headers: list[NameValue], value: str) -> None:
    if not any(h.name.lower() == "content-type" for h in headers):
        headers.append(NameValue(name="Content-Type", value=value))


LONG_VALUE_FLAGS = {
    "--url",
    "--request",
    "--header",
    "--data",
    "--data-raw",
    "--data-binary",
    "--data-urlencode",
    "--data-json",
    "--form",
    "--cookie",
    "--user",
    "--user-agent",
    "--referer",
    "--max-time",
    "--connect-timeout",
}
SHORT_VALUE_FLAGS = {
    "-X",
    "-H",
    "-d",
    "-F",
    "-b",
    "-u",
    "-A",
    "-e",
}
SKIP_VALUE_FLAGS = {"-o", "-c", "-D", "--output", "--cookie-jar", "--dump-header"}
BOOL_FLAGS = {
    "-L",
    "--location",
    "-k",
    "--insecure",
    "-G",
    "--get",
    "-I",
    "--head",
    "-s",
    "--silent",
    "-S",
    "--show-error",
    "-v",
    "--verbose",
    "--compressed",
    "--http1.1",
    "--http2",
    "--http1.0",
    "-i",
    "--include",
    "--path-as-is",
}


def parse_curl(command: str | list[str], *, source: str = "curl") -> Request:
    """Parse a curl command into a darco Request.

    Accepts the full command string (shell quoting is honored by ``_tokenize``)
    or a pre-tokenized list (e.g. click nargs), which preserves argument
    boundaries like ``-H 'Content-Type: application/xml'`` exactly.
    """
    tokens = _tokenize(command) if isinstance(command, str) else list(command)
    if not tokens:
        raise DarcoError("empty curl command")

    method = "GET"
    explicit_method = False
    headers: list[NameValue] = []
    cookies: list[Cookie] = []
    data_items: list[str] = []
    form_items: list[tuple[str, str]] = []
    url: str | None = None
    follow_redirects = False
    verify = True
    timeout = 10.0
    data_kind: str | None = None
    get_mode = False
    head_mode = False
    raw_binary = False

    def apply_value_flag(flag: str, arg: str) -> None:
        nonlocal method, explicit_method, timeout, raw_binary
        if flag in ("-X", "--request"):
            method = arg.upper()
            explicit_method = True
        elif flag in ("-H", "--header"):
            headers.append(_parse_header(arg))
        elif flag in ("-d", "--data", "--data-raw", "--data-binary"):
            data_items.append(arg)
            if flag == "--data-binary":
                raw_binary = True
            nonlocal_data_kind()
        elif flag == "--data-urlencode":
            data_items.append(_encode_data_urlencode(arg))
            nonlocal_data_kind()
        elif flag == "--data-json":
            data_items.append(arg)
            nonlocal_data_kind("json")
        elif flag in ("-F", "--form"):
            name, _, value = arg.partition("=")
            if not name:
                raise DarcoError(f"invalid -F form field: {arg!r}")
            form_items.append((name.strip(), value))
        elif flag in ("-b", "--cookie"):
            cookies.extend(_parse_cookies(arg))
        elif flag in ("-u", "--user"):
            encoded = base64.b64encode(arg.encode("utf-8")).decode("ascii")
            headers.append(NameValue(name="Authorization", value=f"Basic {encoded}"))
        elif flag in ("-A", "--user-agent"):
            headers.append(NameValue(name="User-Agent", value=arg))
        elif flag in ("-e", "--referer"):
            headers.append(NameValue(name="Referer", value=arg))
        elif flag in ("--max-time", "--connect-timeout"):
            try:
                timeout = float(arg)
            except ValueError:
                pass

    def nonlocal_data_kind(kind: str | None = None) -> None:
        nonlocal data_kind
        if kind is not None:
            data_kind = kind
        elif data_kind is None:
            data_kind = "form"

    i, n = 0, len(tokens)
    while i < n:
        tok = tokens[i]
        if tok == "curl":
            i += 1
            continue
        long_name, inline = _split_flag(tok)

        if long_name in LONG_VALUE_FLAGS:
            if inline is None:
                if i + 1 >= n:
                    raise DarcoError(f"missing value for {long_name}")
                arg = tokens[i + 1]
                i += 2
            else:
                arg = inline
                i += 1
            apply_value_flag(long_name, arg)
        elif tok in SHORT_VALUE_FLAGS:
            if i + 1 >= n:
                raise DarcoError(f"missing value for {tok}")
            arg = tokens[i + 1]
            i += 2
            apply_value_flag(tok, arg)
        elif tok in SKIP_VALUE_FLAGS:
            if inline is None:
                i += 2
            else:
                i += 1
        elif tok in BOOL_FLAGS:
            if tok in ("-L", "--location"):
                follow_redirects = True
            elif tok in ("-k", "--insecure"):
                verify = False
            elif tok in ("-G", "--get"):
                get_mode = True
            elif tok in ("-I", "--head"):
                head_mode = True
            i += 1
        elif tok.startswith("-"):
            raise DarcoError(f"unsupported curl option: {tok}")
        else:
            if url is None:
                url = tok
            i += 1

    if url is None:
        raise DarcoError("no URL found in curl command")
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    if head_mode:
        method = "HEAD"
    elif not explicit_method and not get_mode and (data_items or form_items):
        method = "POST"

    params: list[NameValue] = []
    split = urlsplit(url)
    if split.query:
        params.extend(
            NameValue(name=k, value=v)
            for k, v in parse_qsl(split.query, keep_blank_values=True)
        )
        url = url.split("?", 1)[0]

    body_type = BodyType.NONE
    body_json = None
    body_form: list[NameValue] = []
    body_raw = ""

    if form_items:
        body_type = BodyType.FORM
        body_form = [NameValue(name=n, value=v) for n, v in form_items]
        _ensure_content_type(headers, "multipart/form-data")
    elif data_items:
        if get_mode:
            for item in data_items:
                if "=" in item:
                    k, _, v = item.partition("=")
                    params.append(NameValue(name=k, value=v))
        elif data_kind == "json":
            body_type = BodyType.JSON
            try:
                body_json = _json.loads("&".join(data_items))
            except _json.JSONDecodeError as exc:
                raise DarcoError(f"invalid --data-json payload: {exc}") from exc
            _ensure_content_type(headers, "application/json")
        else:
            joined = "&".join(data_items)
            if raw_binary:
                # curl semantics: --data-binary sends bytes verbatim, no form
                # interpretation (XML like '<?xml version="1.0"...' contains
                # '=' but is a raw body, not a form).
                body_type = BodyType.RAW
                body_raw = joined
                if joined.lstrip().startswith(("<", "<?xml")):
                    _ensure_content_type(headers, "application/xml")
                elif joined.lstrip().startswith(("{", "[")):
                    try:
                        body_json = _json.loads(joined)
                        body_type = BodyType.JSON
                        _ensure_content_type(headers, "application/json")
                    except (_json.JSONDecodeError, ValueError):
                        pass
            else:
                if joined.lstrip().startswith(("{", "[")):
                    try:
                        body_json = _json.loads(joined)
                        body_type = BodyType.JSON
                        _ensure_content_type(headers, "application/json")
                    except (_json.JSONDecodeError, ValueError):
                        body_type = BodyType.RAW
                        body_raw = joined
                elif joined.lstrip().startswith(("<", "<?xml")):
                    body_type = BodyType.RAW
                    body_raw = joined
                    _ensure_content_type(headers, "application/xml")
                else:
                    pairs = parse_qsl(joined, keep_blank_values=True)
                    if joined and all("=" in p for p in joined.split("&")):
                        body_type = BodyType.FORM
                        body_form = [NameValue(name=k, value=v) for k, v in pairs]
                        _ensure_content_type(
                            headers, "application/x-www-form-urlencoded"
                        )
                    else:
                        body_type = BodyType.RAW
                        body_raw = joined
            if not any(h.name.lower() == "content-type" for h in headers):
                _ensure_content_type(headers, "application/x-www-form-urlencoded")

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
        follow_redirects=follow_redirects,
        timeout=timeout,
        verify=verify,
        source=source,
    )
