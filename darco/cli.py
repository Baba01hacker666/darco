from __future__ import annotations

import asyncio
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit, urlencode

import click

from . import __version__
from .errors import DarcoError
from .models import BodyType, HistoryRecord, NameValue, Request, SessionState, to_json
from .workspace import Workspace


def _echo_json(data) -> None:
    click.echo(json.dumps(data, indent=2, ensure_ascii=False))


def _find_workspace(ctx) -> Workspace:
    ws_path = ctx.obj.get("workspace_path")
    if ws_path:
        return Workspace.open(Path(ws_path))
    candidates = [p for p in Path.cwd().iterdir() if p.is_dir() and p.name.endswith(".darco")]
    if len(candidates) == 1:
        return Workspace.open(candidates[0])
    if not candidates:
        raise DarcoError("no workspace found; run 'darco init <target>' or pass --workspace")
    raise DarcoError(f"multiple workspaces found ({', '.join(p.name for p in candidates)}); pass --workspace")


# ------------------------------------------------------------------ raw serialization helpers
def _request_body_bytes(req: Request) -> bytes:
    if req.body_type == BodyType.JSON:
        return (json.dumps(req.body_json) if req.body_json is not None else "").encode("utf-8")
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


# ------------------------------------------------------------------ root
@click.group()
@click.option("--workspace", "-w", type=click.Path(), default=None, help="Workspace dir (auto-detected if omitted)")
@click.pass_context
def cli(ctx, workspace):
    ctx.ensure_object(dict)
    ctx.obj["workspace_path"] = workspace


@cli.command("version")
def version_cmd():
    click.echo(f"darco {__version__}")


# ------------------------------------------------------------------ init
@cli.command("init")
@click.argument("target")
@click.option("--dir", "dirpath", type=click.Path(), default=None, help="Workspace directory (default: <host>.darco)")
@click.option("-H", "--header", multiple=True, help="Base header to apply to every request (NAME: value)")
@click.option("--cookie", default=None, help="Base cookie header value (name=value; ...)")
@click.option("--no-follow-redirects", is_flag=True, help="Do not follow redirects by default")
@click.option("--timeout", type=float, default=10.0, help="Request timeout in seconds")
@click.option("--insecure", is_flag=True, help="Disable TLS verification by default")
def init_cmd(target, dirpath, header, cookie, no_follow_redirects, timeout, insecure):
    base_headers: list[NameValue] = []
    for h in header:
        name, sep, value = h.partition(":")
        if not sep:
            raise DarcoError(f"invalid --header (expected 'Name: value'): {h!r}")
        base_headers.append(NameValue(name=name.strip(), value=value.strip()))
    if cookie:
        base_headers.append(NameValue(name="Cookie", value=cookie))
    ws = Workspace.create(
        target,
        Path(dirpath) if dirpath else None,
        base_headers=base_headers,
        follow_redirects=not no_follow_redirects,
        timeout=timeout,
        insecure=insecure,
    )
    _echo_json({"status": "created", "workspace": str(ws.path), "target": target})


# ------------------------------------------------------------------ ingest
@cli.group("ingest")
def ingest_group():
    """Parse external request formats into the workspace history."""


def _store_parsed(ws: Workspace, request: Request, dry_run: bool) -> dict:
    if dry_run:
        return {"request": to_json(request)}
    record = HistoryRecord(
        id=ws.next_id(),
        ts=datetime.now(timezone.utc).isoformat(),
        request=request,
    )
    ws.add_history(record)
    return {"id": record.id, "request": to_json(request)}


@ingest_group.command("curl", context_settings={"ignore_unknown_options": True})
@click.argument("command", nargs=-1, required=True)
@click.option("--dry-run", is_flag=True, help="Parse and print without storing")
@click.pass_context
def ingest_curl(ctx, command, dry_run):
    from .ingest import parse_curl

    ws = _find_workspace(ctx)
    request = parse_curl(" ".join(command))
    _echo_json(_store_parsed(ws, request, dry_run))


@ingest_group.command("raw")
@click.argument("file", type=click.Path(), default="-")
@click.option("--scheme", default=None, help="Scheme when the request target is relative (http/https)")
@click.option("--dry-run", is_flag=True)
@click.pass_context
def ingest_raw(ctx, file, scheme, dry_run):
    from .ingest import parse_raw_http

    ws = _find_workspace(ctx)
    text = sys.stdin.read() if file == "-" else Path(file).read_text()
    request = parse_raw_http(text, scheme=scheme)
    _echo_json(_store_parsed(ws, request, dry_run))


@ingest_group.command("har")
@click.argument("file", type=click.Path(exists=True))
@click.option("--dry-run", is_flag=True)
@click.pass_context
def ingest_har(ctx, file, dry_run):
    from .ingest import parse_har

    ws = _find_workspace(ctx)
    requests = parse_har(file)
    if dry_run:
        _echo_json({"requests": [to_json(r) for r in requests]})
        return
    results = []
    for request in requests:
        results.append(_store_parsed(ws, request, dry_run))
    _echo_json({"stored": len(results), "records": results})


# ------------------------------------------------------------------ send
@cli.command("send")
@click.option("--from", "from_id", default=None, help="Base request: history record id")
@click.option("--curl", "curl_cmd", default=None, help="Base request: curl command string")
@click.option("--raw-file", type=click.Path(exists=True), default=None, help="Base request: raw HTTP request file")
@click.option("--url", default=None, help="Override URL")
@click.option("--method", default=None, help="Override method")
@click.option("--set-header", multiple=True)
@click.option("--unset-header", multiple=True)
@click.option("--set-param", multiple=True)
@click.option("--unset-param", multiple=True)
@click.option("--flip-param", multiple=True)
@click.option("--strip-session", is_flag=True, help="Remove session cookies and auth headers for this request")
@click.option("--set-body", default=None, help="Set raw body (prefix @ to read from file)")
@click.option("--modify-file", type=click.Path(exists=True), default=None, help="JSON list of mutation ops")
@click.option("--follow-redirects/--no-follow-redirects", default=None)
@click.option("--insecure", is_flag=True, default=None)
@click.option("--timeout", type=float, default=None)
@click.option("--diff", "diff_id", default=None, help="Compare response with a stored record id")
@click.option("--raw", is_flag=True, help="Print raw HTTP response")
@click.pass_context
def send_cmd(ctx, from_id, curl_cmd, raw_file, url, method, set_header, unset_header,
             set_param, unset_param, flip_param, strip_session, set_body, modify_file,
             follow_redirects, insecure, timeout, diff_id, raw):
    from .engine import send_and_record
    from .mutate import apply_mutations, parse_mutation_ops

    ws = _find_workspace(ctx)
    cfg = ws.load_config()

    if from_id:
        base = ws.get_record(from_id).request
        base = base.model_copy(deep=True)
        base.parent_id = from_id
    elif curl_cmd:
        from .ingest import parse_curl

        base = parse_curl(curl_cmd)
    elif raw_file:
        from .ingest import parse_raw_http

        base = parse_raw_http(Path(raw_file).read_text())
    else:
        raise DarcoError("provide a base request: --from <id>, --curl, or --raw-file")

    if url:
        base.url = url
    if method:
        base.method = method.upper()
    if follow_redirects is not None:
        base.follow_redirects = follow_redirects
    elif base.follow_redirects is None:
        base.follow_redirects = cfg.follow_redirects
    base.timeout = timeout if timeout is not None else cfg.timeout
    base.verify = not (cfg.insecure or (insecure is True))

    ops = parse_mutation_ops({
        "set_header": set_header,
        "unset_header": unset_header,
        "set_param": set_param,
        "unset_param": unset_param,
        "flip_param": flip_param,
        "strip_session": strip_session,
        "set_body": set_body,
        "modify_file": modify_file,
    })
    request, descriptions = apply_mutations(base, ops)

    session = ws.load_session()
    record, session = send_and_record(ws, request, session, base_headers=cfg.base_headers)

    if record.error:
        _echo_json({"id": record.id, "error": record.error})
        sys.exit(1)

    output: dict = {"id": record.id, "request": to_json(record.request), "response": to_json(record.response)}
    if diff_id:
        other = ws.get_record(diff_id)
        if not other.response:
            raise DarcoError(f"record {diff_id!r} has no response to diff against")
        from .diff import diff_responses

        output["diff"] = diff_responses(other.response, record.response)
    if raw:
        click.echo(_raw_response(record.response))
    else:
        _echo_json(output)


# ------------------------------------------------------------------ diff
@cli.command("diff")
@click.argument("id_a")
@click.argument("id_b")
@click.pass_context
def diff_cmd(ctx, id_a, id_b):
    from .diff import diff_responses

    ws = _find_workspace(ctx)
    ra = ws.get_record(id_a)
    rb = ws.get_record(id_b)
    if not ra.response or not rb.response:
        raise DarcoError("both records must have responses")
    _echo_json(diff_responses(ra.response, rb.response))


# ------------------------------------------------------------------ analyze
@cli.command("analyze")
@click.argument("record_id")
@click.option("--format", "fmt", type=click.Choice(["json", "table"]), default="json")
@click.pass_context
def analyze_cmd(ctx, record_id, fmt):
    from .analyze import analyze_request, analyze_response

    ws = _find_workspace(ctx)
    record = ws.get_record(record_id)
    findings = analyze_request(record.request)
    if record.response:
        findings += analyze_response(record.request, record.response)
    if fmt == "table":
        if not findings:
            click.echo("no findings")
        for f in findings:
            click.echo(f"[{f.severity}] {f.type} @ {f.location}: {f.evidence}")
    else:
        _echo_json({"id": record_id, "findings": [to_json(f) for f in findings]})


# ------------------------------------------------------------------ proxy
@cli.command("proxy")
@click.option("--port", type=int, default=8080)
@click.option("--listen", default="127.0.0.1")
@click.option("--record-only", is_flag=True, default=True, help="Record flows only (v1 mode)")
@click.pass_context
def proxy_cmd(ctx, port, listen, record_only):
    from .proxy import ProxyServer

    ws = _find_workspace(ctx)
    session = ws.load_session()
    server = ProxyServer(ws, session, host=listen, port=port, base_headers=ws.load_config().base_headers)
    bound = server.start()
    click.echo(json.dumps({"status": "listening", "host": listen, "port": bound, "mode": "record-only"}))
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()


# ------------------------------------------------------------------ discover
@cli.command("discover")
@click.argument("url")
@click.option("--depth", type=int, default=3)
@click.option("--max-urls", type=int, default=500)
@click.option("--workers", type=int, default=5)
@click.option("--seed", "seed_files", multiple=True, type=click.Path(exists=True))
@click.option("--no-js", is_flag=True)
@click.option("--insecure", is_flag=True)
@click.option("--timeout", type=float, default=10.0)
@click.pass_context
def discover_cmd(ctx, url, depth, max_urls, workers, seed_files, no_js, insecure, timeout):
    from .discovery.crawler import discover

    ws = _find_workspace(ctx)
    cfg = ws.load_config()
    seeds: list[str] = []
    for f in seed_files:
        seeds.extend(line.strip() for line in Path(f).read_text().splitlines() if line.strip())
    sitemap = asyncio.run(
        discover(
            ws,
            url,
            depth=depth,
            max_urls=max_urls,
            workers=workers,
            seeds=tuple(seeds),
            parse_js=not no_js,
            timeout=timeout,
            verify=not (cfg.insecure or insecure),
        )
    )
    _echo_json(to_json(sitemap))


# ------------------------------------------------------------------ status / session / export
@cli.command("status")
@click.pass_context
def status_cmd(ctx):
    ws = _find_workspace(ctx)
    _echo_json(ws.status())


@cli.group("session", invoke_without_command=True)
@click.pass_context
def session_group(ctx):
    if ctx.invoked_subcommand is None:
        ws = _find_workspace(ctx)
        _echo_json(to_json(ws.load_session()))


@session_group.command("list")
@click.pass_context
def session_list(ctx):
    ws = _find_workspace(ctx)
    _echo_json(to_json(ws.load_session()))


@session_group.command("clear")
@click.pass_context
def session_clear(ctx):
    ws = _find_workspace(ctx)
    ws.save_session(SessionState())
    _echo_json({"status": "cleared"})


@cli.command("export")
@click.argument("record_id")
@click.option("--raw", is_flag=True, help="Emit raw HTTP request text")
@click.option("--response", "want_response", is_flag=True, help="Emit raw HTTP response text")
@click.pass_context
def export_cmd(ctx, record_id, raw, want_response):
    ws = _find_workspace(ctx)
    record = ws.get_record(record_id)
    if raw:
        click.echo(_raw_request(record.request))
        return
    if want_response:
        if not record.response:
            raise DarcoError(f"record {record_id!r} has no response")
        click.echo(_raw_response(record.response))
        return
    _echo_json(to_json(record))


def main() -> None:
    try:
        cli(standalone_mode=False)
    except DarcoError as exc:
        click.echo(f"error: {exc}", err=True)
        sys.exit(1)
    except click.ClickException as exc:
        click.echo(f"error: {exc.format_message()}", err=True)
        sys.exit(exc.exit_code)


if __name__ == "__main__":
    main()
