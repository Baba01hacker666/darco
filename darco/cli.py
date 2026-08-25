from __future__ import annotations

import asyncio
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit, urlencode

import click

from . import __version__
from .errors import DarcoError
from .models import BodyType, HistoryRecord, NameValue, Request, SessionState, to_json
from .workspace import Workspace
from .configfile import load as load_config, DarcoConfig

# Default output format for human-facing commands. Agents/tests pass
# `--format json` (or `-J`) to get the machine contract.
DEFAULT_FMT = "md"

# Commands that emit structured output and respect --format.
_FORMAT_CMDS = {
    "init", "ingest", "send", "diff", "analyze", "status", "session",
    "export", "repeat", "findings", "discover",
}


def _echo_json(data) -> None:
    click.echo(json.dumps(data, indent=2, ensure_ascii=False))


def _emit(ctx, data: dict, md_builder) -> None:
    """Print `data` as markdown (default), JSON, or table, per --format."""
    fmt = (ctx.obj or {}).get("format", DEFAULT_FMT)
    if fmt == "json":
        _echo_json(data)
    elif fmt == "md":
        click.echo(md_builder(data))
    else:  # table
        click.echo(_table_from_json(data))


def _table_from_json(data: dict) -> str:
    rows = []
    for k, v in data.items():
        if isinstance(v, (dict, list)):
            v = json.dumps(v, ensure_ascii=False)
        rows.append(f"{k}\t{v}")
    return "\n".join(rows)


# ------------------------------------------------------------------ workspace resolution
def _find_workspace(ctx, require: bool = True) -> Workspace | None:
    ws_path = (ctx.obj or {}).get("workspace_path")
    if ws_path:
        return Workspace.open(Path(ws_path))
    candidates = [p for p in Path.cwd().iterdir() if p.is_dir() and p.name.endswith(".darco")]
    if len(candidates) == 1:
        return Workspace.open(candidates[0])
    if require:
        if not candidates:
            raise DarcoError("no workspace found; run 'darco init <target>' or pass --workspace (or use -u for one-shot mode)")
        raise DarcoError(f"multiple workspaces found ({', '.join(p.name for p in candidates)}); pass --workspace")
    return None


def _one_shot_session() -> SessionState:
    """A throwaway session for one-shot (-u) commands: nothing persisted."""
    return SessionState(updated_at=datetime.now(timezone.utc).isoformat())


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
@click.option("--config", "config_path", default=None, help="Config file (darco.toml / darco.json); auto-discovered if omitted")
@click.option("--format", "format", type=click.Choice(["json", "md", "table"]), default=DEFAULT_FMT,
              help="Output format (default: md)")
@click.option("-J", "--json", "as_json", is_flag=True, help="Shorthand for --format json (agent contract)")
@click.pass_context
def cli(ctx, workspace, config_path, format, as_json):
    ctx.ensure_object(dict)
    ctx.obj["workspace_path"] = workspace
    ctx.obj["format"] = "json" if as_json else format
    cfg = load_config(config_path)
    # config file wins on defaults but CLI flags still override per-command
    if as_json is False and format == DEFAULT_FMT and cfg.format != DEFAULT_FMT:
        ctx.obj["format"] = cfg.format
    ctx.obj["config"] = cfg


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
@click.pass_context
def init_cmd(ctx, target, dirpath, header, cookie, no_follow_redirects, timeout, insecure):
    from .render import md_init

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
    _emit(ctx, {"status": "created", "workspace": str(ws.path), "target": target}, md_init)


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
    from .render import md_store

    ws = _find_workspace(ctx)
    request = parse_curl(" ".join(command))
    _emit(ctx, _store_parsed(ws, request, dry_run), md_store)


@ingest_group.command("raw")
@click.argument("file", type=click.Path(), default="-")
@click.option("--scheme", default=None, help="Scheme when the request target is relative (http/https)")
@click.option("--dry-run", is_flag=True)
@click.pass_context
def ingest_raw(ctx, file, scheme, dry_run):
    from .ingest import parse_raw_http
    from .render import md_store

    ws = _find_workspace(ctx)
    text = sys.stdin.read() if file == "-" else Path(file).read_text()
    request = parse_raw_http(text, scheme=scheme)
    _emit(ctx, _store_parsed(ws, request, dry_run), md_store)


@ingest_group.command("har")
@click.argument("file", type=click.Path(exists=True))
@click.option("--dry-run", is_flag=True)
@click.pass_context
def ingest_har(ctx, file, dry_run):
    from .ingest import parse_har
    from .render import md_store

    ws = _find_workspace(ctx)
    requests = parse_har(file)
    if dry_run:
        _emit(ctx, {"requests": [to_json(r) for r in requests]}, md_store)
        return
    results = [_store_parsed(ws, r, dry_run) for r in requests]
    _emit(ctx, {"stored": len(results), "records": results}, md_store)


# ------------------------------------------------------------------ send (+ on-the-fly -u mode)
@cli.command("send")
@click.option("--from", "from_id", default=None, help="Base request: history record id")
@click.option("--curl", "curl_cmd", default=None, help="Base request: curl command string")
@click.option("--raw-file", type=click.Path(exists=True), default=None, help="Base request: raw HTTP request file")
@click.option("-u", "--url", default=None, help="ONE-SHOT: send directly to this URL (no workspace needed)")
@click.option("-X", "--method", default=None, help="ONE-SHOT method (with -u)")
@click.option("--data", default=None, help="ONE-SHOT body (with -u); prefix @file to read")
@click.option("--header", "cli_header", multiple=True, help="ONE-SHOT header NAME:VALUE (with -u)")
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
@click.option("--fuzz", "do_fuzz", is_flag=True, help="After sending, auto-fuzz the request (smart variants)")
@click.option("--raw", is_flag=True, help="Print raw HTTP response")
@click.pass_context
def send_cmd(ctx, from_id, curl_cmd, raw_file, url, method, data, cli_header,
             set_header, unset_header, set_param, unset_param, flip_param,
             strip_session, set_body, modify_file, follow_redirects, insecure,
             timeout, diff_id, do_fuzz, raw):
    from .engine import send_and_record, send_request
    from .mutate import apply_mutations, parse_mutation_ops
    from .render import md_send

    # ---- ONE-SHOT mode: -u without a workspace ----
    if url and not from_id and not curl_cmd and not raw_file:
        req = _build_oneshot(url, method, data, cli_header)
        req, desc = _apply_send_mutations(req, {
            "set_header": set_header, "unset_header": unset_header,
            "set_param": set_param, "unset_param": unset_param,
            "flip_param": flip_param, "strip_session": strip_session,
            "set_body": set_body, "modify_file": modify_file,
        })
        req.follow_redirects = follow_redirects if follow_redirects is not None else True
        req.timeout = timeout or 10.0
        req.verify = not insecure
        response, _ = send_request(req, _one_shot_session())
        if raw:
            click.echo(_raw_response(response))
            return
        if do_fuzz:
            from .fuzz import run_fuzz
            from .render import md_fuzz

            cfg = (ctx.obj or {}).get("config") or DarcoConfig.empty()
            fres = run_fuzz(req, _one_shot_session(), baseline_response=response,
                            concurrency=cfg.fuzz.concurrency)
            out = {"id": None, "oneshot": True, "request": to_json(req),
                   "response": to_json(response), "mutations": desc, "fuzz": fres}
            _emit(ctx, out, md_send)
            return
        _emit(ctx, {
            "id": None, "oneshot": True, "request": to_json(req),
            "response": to_json(response), "mutations": desc,
        }, md_send)
        return

    # ---- workspace mode ----
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
        raise DarcoError("provide a base request: --from <id>, --curl, --raw-file, or -u <url>")

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
        "set_header": set_header, "unset_header": unset_header,
        "set_param": set_param, "unset_param": unset_param,
        "flip_param": flip_param, "strip_session": strip_session,
        "set_body": set_body, "modify_file": modify_file,
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
    if do_fuzz:
        from .fuzz import run_fuzz
        from .render import md_fuzz

        cfg_darco: DarcoConfig = (ctx.obj or {}).get("config") or DarcoConfig.empty()
        fres = run_fuzz(request, session, baseline_response=record.response,
                        concurrency=cfg_darco.fuzz.concurrency)
        output["fuzz"] = fres
    if raw:
        click.echo(_raw_response(record.response))
    else:
        _emit(ctx, output, md_send)


# ------------------------------------------------------------------ fuzz (smart default engine)
def _resolve_base_request(ctx, from_id, curl_cmd, raw_file, url, method, data, cli_header):
    """Build a base Request from the same sources send uses. Returns (req, is_oneshot_session)."""
    cfg: DarcoConfig = (ctx.obj or {}).get("config") or DarcoConfig.empty()
    if url and not from_id and not curl_cmd and not raw_file:
        req = _build_oneshot(url, method, data, cli_header)
        # apply config base headers
        existing = {h.name.lower() for h in req.headers}
        for bh in cfg.headers:
            if bh.name.lower() not in existing:
                req.headers.append(bh)
        req.follow_redirects = True
        req.timeout = cfg.timeout
        req.verify = not cfg.insecure
        return req, _one_shot_session(), True
    ws = _find_workspace(ctx)
    wcfg = ws.load_config()
    if from_id:
        base = ws.get_record(from_id).request.model_copy(deep=True)
        base.parent_id = from_id
    elif curl_cmd:
        from .ingest import parse_curl
        base = parse_curl(curl_cmd)
    elif raw_file:
        from .ingest import parse_raw_http
        base = parse_raw_http(Path(raw_file).read_text())
    else:
        raise DarcoError("provide a base request: --from <id>, --curl, --raw-file, or -u <url>")
    if url:
        base.url = url
    if method:
        base.method = method.upper()
    base.follow_redirects = base.follow_redirects if base.follow_redirects is not None else wcfg.follow_redirects
    base.timeout = base.timeout or wcfg.timeout
    base.verify = not wcfg.insecure
    return base, ws.load_session(), False


@cli.command("fuzz")
@click.option("--from", "from_id", default=None, help="Base request: history record id")
@click.option("--curl", "curl_cmd", default=None, help="Base request: curl command string")
@click.option("--raw-file", type=click.Path(exists=True), default=None)
@click.option("-u", "--url", default=None, help="ONE-SHOT: target URL (no workspace needed)")
@click.option("-X", "--method", default=None)
@click.option("--data", default=None, help="Body (prefix @file to read)")
@click.option("--header", "cli_header", multiple=True)
@click.option("--concurrency", type=int, default=None, help="Parallel variant dispatches")
@click.pass_context
def fuzz_cmd(ctx, from_id, curl_cmd, raw_file, url, method, data, cli_header, concurrency):
    """Smart-default fuzz: auto-mutate params (flip, type-confuse numerics, boundaries, SQL/XSS) and report anomalies."""
    from .fuzz import run_fuzz
    from .render import md_fuzz

    cfg: DarcoConfig = (ctx.obj or {}).get("config") or DarcoConfig.empty()
    if not cfg.fuzz.enabled:
        raise DarcoError("fuzzing disabled in config ([fuzz] enabled = false); set enabled = true to run")

    req, session, _ = _resolve_base_request(ctx, from_id, curl_cmd, raw_file, url, method, data, cli_header)
    conc = concurrency or cfg.fuzz.concurrency
    # baseline = the clean request
    try:
        _, baseline, _ = _engine_execute(req, session)
    except Exception as exc:  # noqa: BLE001
        baseline = None
        click.echo(f"warn: baseline request failed: {exc}", err=True)
    result = run_fuzz(req, session, baseline_response=baseline, concurrency=conc)
    _emit(ctx, result, md_fuzz)


def _engine_execute(req, session):
    from .engine import execute
    return execute(req, session)


def _build_oneshot(url: str, method, data, cli_header) -> Request:
    headers = []
    for h in cli_header:
        name, sep, value = h.partition(":")
        if not sep:
            raise DarcoError(f"invalid --header (expected 'Name: value'): {h!r}")
        headers.append(NameValue(name=name.strip(), value=value.strip()))
    body_type = BodyType.NONE
    body_raw = ""
    if data:
        if data.startswith("@") and len(data) > 1:
            try:
                body_raw = Path(data[1:]).read_text()
            except OSError as exc:
                raise DarcoError(f"cannot read --data file: {exc}") from exc
        else:
            body_raw = data
        body_type = BodyType.RAW
    split = urlsplit(url)
    params = [NameValue(name=k, value=v) for k, v in parse_qsl(split.query, keep_blank_values=True)]
    clean_url = url.split("?", 1)[0] if split.query else url
    return Request(
        method=(method or "GET").upper(),
        url=clean_url,
        headers=headers,
        params=params,
        body_type=body_type,
        body_raw=body_raw,
        source="oneshot",
    )


def _apply_send_mutations(req: Request, opts: dict) -> tuple[Request, list[str]]:
    from .mutate import apply_mutations, parse_mutation_ops
    ops = parse_mutation_ops(opts)
    return apply_mutations(req, ops)


# ------------------------------------------------------------------ diff
@cli.command("diff")
@click.argument("id_a")
@click.argument("id_b")
@click.pass_context
def diff_cmd(ctx, id_a, id_b):
    from .diff import diff_responses
    from .render import md_diff

    ws = _find_workspace(ctx)
    ra = ws.get_record(id_a)
    rb = ws.get_record(id_b)
    if not ra.response or not rb.response:
        raise DarcoError("both records must have responses")
    _emit(ctx, diff_responses(ra.response, rb.response), md_diff)


# ------------------------------------------------------------------ analyze
@cli.command("analyze")
@click.argument("record_id")
@click.option("--save", "save", is_flag=True, help="Persist findings to the workspace (findings.json)")
@click.pass_context
def analyze_cmd(ctx, record_id, save):
    from .analyze import analyze_request, analyze_response
    from .render import md_analyze

    ws = _find_workspace(ctx)
    record = ws.get_record(record_id)
    findings = analyze_request(record.request)
    if record.response:
        findings += analyze_response(record.request, record.response)
    if save:
        added = ws.add_findings(findings)
        _emit(ctx, {"id": record_id, "saved": added}, md_analyze)
        return
    _emit(ctx, {"id": record_id, "findings": [to_json(f) for f in findings]}, md_analyze)


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
    from .render import md_discover

    ws = _find_workspace(ctx)
    cfg = ws.load_config()
    seeds: list[str] = []
    for f in seed_files:
        seeds.extend(line.strip() for line in Path(f).read_text().splitlines() if line.strip())
    sitemap = asyncio.run(
        discover(
            ws, url, depth=depth, max_urls=max_urls, workers=workers,
            seeds=tuple(seeds), parse_js=not no_js, timeout=timeout,
            verify=not (cfg.insecure or insecure),
        )
    )
    _emit(ctx, to_json(sitemap), md_discover)


# ------------------------------------------------------------------ status / session / export
@cli.command("status")
@click.pass_context
def status_cmd(ctx):
    from .render import md_status

    ws = _find_workspace(ctx)
    _emit(ctx, ws.status(), md_status)


@cli.group("session", invoke_without_command=True)
@click.pass_context
def session_group(ctx):
    if ctx.invoked_subcommand is None:
        ws = _find_workspace(ctx)
        from .render import md_session
        _emit(ctx, to_json(ws.load_session()), md_session)


@session_group.command("list")
@click.pass_context
def session_list(ctx):
    from .render import md_session

    ws = _find_workspace(ctx)
    _emit(ctx, to_json(ws.load_session()), md_session)


@session_group.command("clear")
@click.pass_context
def session_clear(ctx):
    ws = _find_workspace(ctx)
    ws.save_session(SessionState())
    _emit(ctx, {"status": "cleared"}, lambda d: "# Session\n\n- **status**: cleared")


# ------------------------------------------------------------------ export
@cli.command("export")
@click.argument("record_id")
@click.option("--raw", is_flag=True, help="Emit raw HTTP request text")
@click.option("--response", "want_response", is_flag=True, help="Emit raw HTTP response text")
@click.pass_context
def export_cmd(ctx, record_id, raw, want_response):
    from .render import md_record

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
    _emit(ctx, to_json(record), md_record)


# ------------------------------------------------------------------ repeat
@cli.command("repeat")
@click.argument("record_id")
@click.option("--count", type=int, default=1, help="Number of times to replay the stored request")
@click.option("--interval", type=float, default=0.0, help="Seconds to sleep between replays")
@click.option("--strip-session", is_flag=True, help="Remove session cookies/auth headers on every replay")
@click.option("--set-header", "set_header", multiple=True)
@click.option("--set-param", "set_param", multiple=True)
@click.option("--unset-param", "unset_param", multiple=True)
@click.option("--follow-redirects/--no-follow-redirects", default=None)
@click.pass_context
def repeat_cmd(ctx, record_id, count, interval, strip_session, set_header, set_param, unset_param, follow_redirects):
    """Replay a stored request COUNT times (rate-limit / OTP-verification loop)."""
    import time

    from .engine import send_and_record
    from .mutate import apply_mutations, parse_mutation_ops
    from .render import md_repeat

    if count < 1:
        raise DarcoError("--count must be >= 1")

    ws = _find_workspace(ctx)
    cfg = ws.load_config()
    base_record = ws.get_record(record_id)
    base = base_record.request.model_copy(deep=True)
    base.parent_id = record_id

    ops = parse_mutation_ops({
        "set_header": set_header, "set_param": set_param, "unset_param": unset_param,
        "strip_session": strip_session,
    })

    results = []
    session = ws.load_session()
    for i in range(count):
        request, _ = apply_mutations(base, ops)
        if follow_redirects is not None:
            request.follow_redirects = follow_redirects
        elif request.follow_redirects is None:
            request.follow_redirects = cfg.follow_redirects
        request.timeout = cfg.timeout
        request.verify = not cfg.insecure
        record, session = send_and_record(ws, request, session, base_headers=cfg.base_headers)
        results.append({"index": i, "id": record.id,
                        "status": record.response.status_code if record.response else None,
                        "error": record.error})
        if interval and i < count - 1:
            time.sleep(interval)

    statuses = [r["status"] for r in results if r["status"] is not None]
    _emit(ctx, {
        "from": record_id, "count": count, "ids": [r["id"] for r in results],
        "statuses": statuses, "distinct_statuses": sorted(set(statuses)),
        "errors": sum(1 for r in results if r["error"]),
    }, md_repeat)


# ------------------------------------------------------------------ findings
@cli.group("findings")
def findings_group():
    """Inspect findings accumulated in the workspace (via `analyze --save`)."""


@findings_group.command("list")
@click.pass_context
def findings_list(ctx):
    from .render import md_findings_list

    ws = _find_workspace(ctx)
    found = ws.load_findings()
    _emit(ctx, {"count": len(found), "findings": [to_json(f) for f in found]}, md_findings_list)


@findings_group.command("clear")
@click.pass_context
def findings_clear(ctx):
    ws = _find_workspace(ctx)
    ws.save_findings([])
    _emit(ctx, {"status": "cleared"}, lambda d: "# Findings\n\n- **status**: cleared")


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
