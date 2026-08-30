"""Shared on-the-fly request building: base-request resolution, engine execution, one-shot construction, and send mutation wiring."""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

from ..configfile import DarcoConfig
from ..errors import DarcoError
from ..models import BodyType, NameValue, Request
from ._context import _find_workspace, _one_shot_session


# ------------------------------------------------------------------ fuzz (smart default engine)
def _resolve_base_request(
    ctx, from_id, curl_cmd, raw_file, url, method, data, cli_header, cli_form=()
):
    """Build a base Request from the same sources send uses. Returns (req, is_oneshot_session)."""
    cfg: DarcoConfig = (ctx.obj or {}).get("config") or DarcoConfig.empty()
    if url and not from_id and not curl_cmd and not raw_file:
        req = _build_oneshot(url, method, data, cli_header, cli_form)
        # apply config base headers
        existing = {h.name.lower() for h in req.headers}
        for bh in cfg.headers:
            if bh.name.lower() not in existing:
                req.headers.append(bh)
        req.follow_redirects = True
        req.timeout = cfg.timeout
        req.verify = not cfg.insecure
        return req, _one_shot_session(), True
    ws = _find_workspace(ctx, auto_create_target=url)
    wcfg = ws.load_config()
    if from_id:
        base = ws.get_record(from_id).request.model_copy(deep=True)
        base.parent_id = from_id
    elif curl_cmd:
        from ..ingest import parse_curl

        base = parse_curl(curl_cmd)
    elif raw_file:
        from ..ingest import parse_raw_http

        base = parse_raw_http(Path(raw_file).read_text())
    else:
        raise DarcoError(
            "provide a base request: -u <url>, 'darco fuzz <url>', or --from <id>"
        )
    if url:
        base.url = url
    if method:
        base.method = method.upper()
    base.follow_redirects = (
        base.follow_redirects
        if base.follow_redirects is not None
        else wcfg.follow_redirects
    )
    base.timeout = base.timeout or wcfg.timeout
    base.verify = not wcfg.insecure
    return base, ws.load_session(), False


def _engine_execute(req, session):
    from ..engine import execute

    return execute(req, session)


def _build_oneshot(
    url: str,
    method: str | None = None,
    data: str | None = None,
    cli_header: tuple = (),
    cli_form: tuple = (),
) -> Request:
    headers = []
    for h in cli_header:
        name, sep, value = h.partition(":")
        if not sep:
            raise DarcoError(f"invalid --header (expected 'Name: value'): {h!r}")
        headers.append(NameValue(name=name.strip(), value=value.strip()))
    body_type = BodyType.NONE
    body_raw = ""
    body_form: list[NameValue] = []
    body_json = None

    if cli_form:
        body_type = BodyType.FORM
        for f in cli_form:
            name, _, val = f.partition("=")
            body_form.append(NameValue(name=name.strip(), value=val))
        if not any(h.name.lower() == "content-type" for h in headers):
            headers.append(
                NameValue(
                    name="Content-Type", value="application/x-www-form-urlencoded"
                )
            )
        if not method:
            method = "POST"
    elif data:
        if data.startswith("@") and len(data) > 1:
            try:
                body_raw = Path(data[1:]).read_text()
            except OSError as exc:
                raise DarcoError(f"cannot read --data file: {exc}") from exc
        else:
            body_raw = data
        if body_raw.strip().startswith(("{", "[")):
            try:
                body_json = json.loads(body_raw)
                body_type = BodyType.JSON
                if not any(h.name.lower() == "content-type" for h in headers):
                    headers.append(
                        NameValue(name="Content-Type", value="application/json")
                    )
            except (ValueError, TypeError, json.JSONDecodeError):
                body_type = BodyType.RAW
        elif "=" in body_raw and not any(c in body_raw for c in ("\n", "\r", "{")):
            body_type = BodyType.FORM
            for pair in body_raw.split("&"):
                if "=" in pair:
                    k, _, v = pair.partition("=")
                    body_form.append(NameValue(name=k, value=v))
            if not any(h.name.lower() == "content-type" for h in headers):
                headers.append(
                    NameValue(
                        name="Content-Type", value="application/x-www-form-urlencoded"
                    )
                )
        else:
            body_type = BodyType.RAW
        if not method:
            method = "POST"

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    split = urlsplit(url)
    params = [
        NameValue(name=k, value=v)
        for k, v in parse_qsl(split.query, keep_blank_values=True)
    ]
    clean_url = url.split("?", 1)[0] if split.query else url
    return Request(
        method=(method or "GET").upper(),
        url=clean_url,
        headers=headers,
        params=params,
        body_type=body_type,
        body_raw=body_raw,
        body_form=body_form,
        body_json=body_json,
        source="oneshot",
    )


def _apply_send_mutations(req: Request, opts: dict) -> tuple[Request, list[str]]:
    from ..mutate import apply_mutations, parse_mutation_ops

    ops = parse_mutation_ops(opts)
    return apply_mutations(req, ops)
