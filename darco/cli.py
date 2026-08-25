from __future__ import annotations

import asyncio
import json
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit

import click

from . import __version__
from .configfile import DarcoConfig
from .configfile import load as load_config
from .errors import DarcoError
from .models import BodyType, HistoryRecord, NameValue, Request, SessionState, to_json
from .workspace import Workspace, default_workspace_name

# Default output format for human-facing commands. Agents/tests pass
# `--format json` (or `-J`) to get the machine contract.
DEFAULT_FMT = "md"

# Commands that emit structured output and respect --format.
_FORMAT_CMDS = {
    "init",
    "ingest",
    "send",
    "diff",
    "analyze",
    "status",
    "session",
    "export",
    "repeat",
    "findings",
    "discover",
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
def _find_workspace(
    ctx, require: bool = True, auto_create_target: str | None = None
) -> Workspace | None:
    ws_path = (ctx.obj or {}).get("workspace_path")
    if ws_path:
        return Workspace.open(Path(ws_path))
    candidates = [
        p for p in Path.cwd().iterdir() if p.is_dir() and p.name.endswith(".darco")
    ]
    if len(candidates) == 1:
        return Workspace.open(candidates[0])
    if len(candidates) > 1:
        if auto_create_target:
            def_name = default_workspace_name(auto_create_target)
            match = [p for p in candidates if p.name == def_name]
            if match:
                return Workspace.open(match[0])
        raise DarcoError(
            f"multiple workspaces found ({', '.join(p.name for p in candidates)}); pass --workspace"
        )

    # Search parent directories (up to 3 levels)
    try:
        curr = Path.cwd().parent
        for _ in range(3):
            if curr == curr.parent:
                break
            p_candidates = [
                p for p in curr.iterdir() if p.is_dir() and p.name.endswith(".darco")
            ]
            if len(p_candidates) == 1:
                return Workspace.open(p_candidates[0])
            curr = curr.parent
    except OSError:
        pass

    cfg = (ctx.obj or {}).get("config")
    target = auto_create_target or (cfg.target if cfg else None)
    if target:
        ws_name = default_workspace_name(target)
        ws_dir = Path.cwd() / ws_name
        if ws_dir.exists() and (ws_dir / "workspace.json").exists():
            return Workspace.open(ws_dir)
        return Workspace.create(target, ws_dir)

    if require:
        raise DarcoError(
            "no workspace found; use 'darco -u <url>' for one-shot mode or 'darco init <target>' to create a workspace"
        )
    return None


def _one_shot_session() -> SessionState:
    """A throwaway session for one-shot (-u) commands: nothing persisted."""
    return SessionState(updated_at=datetime.now(UTC).isoformat())


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


class DarcoCLI(click.Group):
    """Custom Click Group that allows running URLs and history IDs directly (e.g. `darco https://target.com`)."""

    def resolve_command(self, ctx, args):
        cmd_name = args[0] if args else None
        if (
            cmd_name
            and cmd_name not in self.commands
            and not cmd_name.startswith("-")
            and (
                cmd_name.isdigit()
                or cmd_name.startswith(("http://", "https://", "localhost"))
                or "." in cmd_name
                or "/" in cmd_name
            )
        ):
            return "send", self.get_command(ctx, "send"), args
        return super().resolve_command(ctx, args)


# ------------------------------------------------------------------ root
@click.group(cls=DarcoCLI, invoke_without_command=True)
@click.option(
    "-u", "--url", "url", default=None, help="Target URL to send/inspect directly"
)
@click.option("-X", "--method", default=None, help="HTTP method (GET, POST, etc.)")
@click.option("-d", "--data", default=None, help="Request body (prefix @file to read)")
@click.option("-H", "--header", "cli_header", multiple=True, help="Header NAME:VALUE")
@click.option("-F", "--form", "cli_form", multiple=True, help="Form field NAME=VALUE")
@click.option(
    "--workspace",
    "-w",
    type=click.Path(),
    default=None,
    help="Workspace dir (auto-detected if omitted)",
)
@click.option(
    "--config",
    "config_path",
    default=None,
    help="Config file (darco.toml / darco.json); auto-discovered if omitted",
)
@click.option(
    "--format",
    "format",
    type=click.Choice(["json", "md", "table"]),
    default=DEFAULT_FMT,
    help="Output format (default: md)",
)
@click.option(
    "-J",
    "--json",
    "as_json",
    is_flag=True,
    help="Shorthand for --format json (agent contract)",
)
@click.option("--fuzz", "do_fuzz", is_flag=True, help="Auto-fuzz the target request")
@click.option("--raw", is_flag=True, help="Print raw HTTP response")
@click.pass_context
def cli(
    ctx,
    url,
    method,
    data,
    cli_header,
    cli_form,
    workspace,
    config_path,
    format,
    as_json,
    do_fuzz,
    raw,
):
    ctx.ensure_object(dict)
    ctx.obj["workspace_path"] = workspace
    ctx.obj["format"] = "json" if as_json else format
    cfg = load_config(config_path)
    # config file wins on defaults but CLI flags still override per-command
    if as_json is False and format == DEFAULT_FMT and cfg.format != DEFAULT_FMT:
        ctx.obj["format"] = cfg.format
    ctx.obj["config"] = cfg

    if ctx.invoked_subcommand is None:
        if url:
            ctx.invoke(
                send_cmd,
                target=url,
                method=method,
                data=data,
                cli_header=cli_header,
                cli_form=cli_form,
                do_fuzz=do_fuzz,
                raw=raw,
            )
        else:
            click.echo(ctx.get_help())


@cli.command("version")
def version_cmd():
    click.echo(f"darco {__version__}")


# ------------------------------------------------------------------ init
@cli.command("init")
@click.argument("target_arg", required=False, default=None)
@click.option(
    "-u", "--url", "target_opt", default=None, help="Target URL (default: argument)"
)
@click.option(
    "--dir",
    "dirpath",
    type=click.Path(),
    default=None,
    help="Workspace directory (default: <host>.darco)",
)
@click.option(
    "-H",
    "--header",
    multiple=True,
    help="Base header to apply to every request (NAME: value)",
)
@click.option(
    "--cookie", default=None, help="Base cookie header value (name=value; ...)"
)
@click.option(
    "--no-follow-redirects", is_flag=True, help="Do not follow redirects by default"
)
@click.option("--timeout", type=float, default=10.0, help="Request timeout in seconds")
@click.option("--insecure", is_flag=True, help="Disable TLS verification by default")
@click.pass_context
def init_cmd(
    ctx,
    target_arg,
    target_opt,
    dirpath,
    header,
    cookie,
    no_follow_redirects,
    timeout,
    insecure,
):
    from .render import md_init

    target = target_opt or target_arg
    if not target:
        raise DarcoError(
            "provide a target URL: 'darco init <target>' or 'darco init -u <target>'"
        )
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
    _emit(
        ctx, {"status": "created", "workspace": str(ws.path), "target": target}, md_init
    )


# ------------------------------------------------------------------ ingest
@cli.group("ingest")
def ingest_group():
    """Parse external request formats into the workspace history."""


def _store_parsed(ws: Workspace, request: Request, dry_run: bool) -> dict:
    if dry_run:
        return {"request": to_json(request)}
    record = HistoryRecord(
        id=ws.next_id(),
        ts=datetime.now(UTC).isoformat(),
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
@click.option(
    "--scheme",
    default=None,
    help="Scheme when the request target is relative (http/https)",
)
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
@click.argument("target", required=False, default=None)
@click.option(
    "-u",
    "--url",
    default=None,
    help="ONE-SHOT: send directly to this URL (no workspace needed)",
)
@click.option("--from", "from_id", default=None, help="Base request: history record id")
@click.option(
    "--curl", "curl_cmd", default=None, help="Base request: curl command string"
)
@click.option(
    "--raw-file",
    type=click.Path(exists=True),
    default=None,
    help="Base request: raw HTTP request file",
)
@click.option("-X", "--method", default=None, help="HTTP method (GET, POST, etc.)")
@click.option("-d", "--data", default=None, help="Body (prefix @file to read)")
@click.option("-H", "--header", "cli_header", multiple=True, help="Header NAME:VALUE")
@click.option("-F", "--form", "cli_form", multiple=True, help="Form field NAME=VALUE")
@click.option("--set-header", multiple=True)
@click.option("--unset-header", multiple=True)
@click.option("--set-param", multiple=True)
@click.option("--unset-param", multiple=True)
@click.option("--flip-param", multiple=True)
@click.option(
    "--strip-session",
    is_flag=True,
    help="Remove session cookies and auth headers for this request",
)
@click.option(
    "--set-body", default=None, help="Set raw body (prefix @ to read from file)"
)
@click.option(
    "--modify-file",
    type=click.Path(exists=True),
    default=None,
    help="JSON list of mutation ops",
)
@click.option("--follow-redirects/--no-follow-redirects", default=None)
@click.option("--insecure", is_flag=True, default=None)
@click.option("--timeout", type=float, default=None)
@click.option(
    "--diff", "diff_id", default=None, help="Compare response with a stored record id"
)
@click.option(
    "--fuzz",
    "do_fuzz",
    is_flag=True,
    help="After sending, auto-fuzz the request (smart variants)",
)
@click.option("--raw", is_flag=True, help="Print raw HTTP response")
@click.pass_context
def send_cmd(
    ctx,
    target,
    url,
    from_id,
    curl_cmd,
    raw_file,
    method,
    data,
    cli_header,
    cli_form,
    set_header,
    unset_header,
    set_param,
    unset_param,
    flip_param,
    strip_session,
    set_body,
    modify_file,
    follow_redirects,
    insecure,
    timeout,
    diff_id,
    do_fuzz,
    raw,
):
    from .engine import send_and_record, send_request
    from .mutate import apply_mutations, parse_mutation_ops
    from .render import md_send

    if target:
        if target.startswith(("http://", "https://")) or (
            "://" not in target and "/" in target and not Path(target).is_file()
        ):
            url = url or target
        elif target.startswith("curl "):
            curl_cmd = curl_cmd or target
        elif Path(target).is_file():
            raw_file = raw_file or target
        else:
            from_id = from_id or target

    # ---- ONE-SHOT mode: -u without a workspace ----
    if url and not from_id and not curl_cmd and not raw_file:
        req = _build_oneshot(url, method, data, cli_header, cli_form)
        req, desc = _apply_send_mutations(
            req,
            {
                "set_header": set_header,
                "unset_header": unset_header,
                "set_param": set_param,
                "unset_param": unset_param,
                "flip_param": flip_param,
                "strip_session": strip_session,
                "set_body": set_body,
                "modify_file": modify_file,
            },
        )
        req.follow_redirects = (
            follow_redirects if follow_redirects is not None else True
        )
        req.timeout = timeout or 10.0
        req.verify = not insecure
        response, _ = send_request(req, _one_shot_session())
        if raw:
            click.echo(_raw_response(response))
            return
        if do_fuzz:
            from .fuzz import run_fuzz

            cfg = (ctx.obj or {}).get("config") or DarcoConfig.empty()
            fres = run_fuzz(
                req,
                _one_shot_session(),
                baseline_response=response,
                concurrency=cfg.fuzz.concurrency,
            )
            from .detection import detect_technologies, detect_waf

            wafs = [to_json(w) for w in detect_waf(response, req)]
            techs = [to_json(t) for t in detect_technologies(response, req)]
            out = {
                "id": None,
                "oneshot": True,
                "request": to_json(req),
                "response": to_json(response),
                "mutations": desc,
                "wafs": wafs,
                "technologies": techs,
                "fuzz": fres,
            }
            _emit(ctx, out, md_send)
            return

        from .detection import detect_technologies, detect_waf

        wafs = [to_json(w) for w in detect_waf(response, req)]
        techs = [to_json(t) for t in detect_technologies(response, req)]
        _emit(
            ctx,
            {
                "id": None,
                "oneshot": True,
                "request": to_json(req),
                "response": to_json(response),
                "mutations": desc,
                "wafs": wafs,
                "technologies": techs,
            },
            md_send,
        )
        return

    # ---- workspace mode ----
    ws = _find_workspace(ctx, auto_create_target=url)
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
        raise DarcoError(
            "provide a base request: -u <url>, 'darco send <url>', or --from <id>"
        )

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

    ops = parse_mutation_ops(
        {
            "set_header": set_header,
            "unset_header": unset_header,
            "set_param": set_param,
            "unset_param": unset_param,
            "flip_param": flip_param,
            "strip_session": strip_session,
            "set_body": set_body,
            "modify_file": modify_file,
        }
    )
    request, _descriptions = apply_mutations(base, ops)

    session = ws.load_session()
    record, session = send_and_record(
        ws, request, session, base_headers=cfg.base_headers
    )

    if record.error:
        _echo_json({"id": record.id, "error": record.error})
        sys.exit(1)

    from .detection import detect_technologies, detect_waf

    wafs = (
        [to_json(w) for w in detect_waf(record.response, record.request)]
        if record.response
        else []
    )
    techs = (
        [to_json(t) for t in detect_technologies(record.response, record.request)]
        if record.response
        else []
    )

    output: dict = {
        "id": record.id,
        "request": to_json(record.request),
        "response": to_json(record.response),
        "wafs": wafs,
        "technologies": techs,
    }
    if diff_id:
        other = ws.get_record(diff_id)
        if not other.response:
            raise DarcoError(f"record {diff_id!r} has no response to diff against")
        from .diff import diff_responses

        output["diff"] = diff_responses(other.response, record.response)
    if do_fuzz:
        from .fuzz import run_fuzz

        cfg_darco: DarcoConfig = (ctx.obj or {}).get("config") or DarcoConfig.empty()
        fres = run_fuzz(
            request,
            session,
            baseline_response=record.response,
            concurrency=cfg_darco.fuzz.concurrency,
        )
        output["fuzz"] = fres
    if raw:
        click.echo(_raw_response(record.response))
    else:
        _emit(ctx, output, md_send)


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
        from .ingest import parse_curl

        base = parse_curl(curl_cmd)
    elif raw_file:
        from .ingest import parse_raw_http

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


@cli.command("fuzz")
@click.argument("target", required=False, default=None)
@click.option(
    "-u", "--url", default=None, help="ONE-SHOT: target URL (no workspace needed)"
)
@click.option("--from", "from_id", default=None, help="Base request: history record id")
@click.option(
    "--curl", "curl_cmd", default=None, help="Base request: curl command string"
)
@click.option("--raw-file", type=click.Path(exists=True), default=None)
@click.option("-X", "--method", default=None)
@click.option("-d", "--data", default=None, help="Body (prefix @file to read)")
@click.option("-H", "--header", "cli_header", multiple=True)
@click.option("-F", "--form", "cli_form", multiple=True)
@click.option(
    "--concurrency", type=int, default=None, help="Parallel variant dispatches"
)
@click.pass_context
def fuzz_cmd(
    ctx,
    target,
    url,
    from_id,
    curl_cmd,
    raw_file,
    method,
    data,
    cli_header,
    cli_form,
    concurrency,
):
    """Smart-default fuzz: auto-mutate params (flip, type-confuse numerics, boundaries, SQL/XSS) and report anomalies."""
    from .fuzz import run_fuzz
    from .render import md_fuzz

    if target:
        if target.startswith(("http://", "https://")) or (
            "://" not in target and "/" in target and not Path(target).is_file()
        ):
            url = url or target
        elif target.startswith("curl "):
            curl_cmd = curl_cmd or target
        elif Path(target).is_file():
            raw_file = raw_file or target
        else:
            from_id = from_id or target

    cfg: DarcoConfig = (ctx.obj or {}).get("config") or DarcoConfig.empty()
    if not cfg.fuzz.enabled:
        raise DarcoError(
            "fuzzing disabled in config ([fuzz] enabled = false); set enabled = true to run"
        )

    req, session, _ = _resolve_base_request(
        ctx, from_id, curl_cmd, raw_file, url, method, data, cli_header, cli_form
    )
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
@click.option(
    "--save",
    "save",
    is_flag=True,
    help="Persist findings to the workspace (findings.json)",
)
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
    _emit(
        ctx, {"id": record_id, "findings": [to_json(f) for f in findings]}, md_analyze
    )


# ------------------------------------------------------------------ detect (tech & WAF)
@cli.command("detect")
@click.argument("target", required=False, default=None)
@click.option("-u", "--url", default=None, help="Target URL to fingerprint")
@click.option("--from", "from_id", default=None, help="Stored record id to inspect")
@click.option("--waf-only", is_flag=True, help="Only detect WAF / CDN shields")
@click.option("--tech-only", is_flag=True, help="Only detect web technologies")
@click.option(
    "--insecure", is_flag=True, default=False, help="Disable TLS verification"
)
@click.pass_context
def detect_cmd(ctx, target, url, from_id, waf_only, tech_only, insecure):
    """Detect WAF shields and web technologies from headers, cookies, and body."""
    from .detection import detect_technologies, detect_waf
    from .engine import send_request
    from .render import md_detect

    if target:
        if target.isdigit() or (target.startswith("0") and len(target) == 4):
            from_id = from_id or target
        else:
            url = url or target

    req = None
    resp = None

    if from_id:
        ws = _find_workspace(ctx)
        record = ws.get_record(from_id)
        req = record.request
        resp = record.response
        if not resp:
            raise DarcoError(f"record {from_id!r} has no response to inspect")
    else:
        if not url:
            cfg = (ctx.obj or {}).get("config")
            if cfg and cfg.target:
                url = cfg.target
            else:
                ws = _find_workspace(ctx, require=False)
                if ws:
                    try:
                        url = ws.load_config().target
                    except DarcoError:
                        pass
        if not url:
            raise DarcoError(
                "provide a target URL (-u <url>) or record ID (--from <id>)"
            )
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        req = Request(method="GET", url=url, verify=not insecure)
        resp, _ = send_request(req, _one_shot_session())

    wafs = [to_json(w) for w in detect_waf(resp, req)] if not tech_only else []
    techs = [to_json(t) for t in detect_technologies(resp, req)] if not waf_only else []

    out = {
        "target": req.url,
        "status_code": resp.status_code,
        "wafs": wafs,
        "technologies": techs,
    }
    _emit(ctx, out, md_detect)


@cli.command("waf")
@click.argument("target", required=False, default=None)
@click.option("-u", "--url", default=None, help="Target URL to inspect for WAF")
@click.option("--from", "from_id", default=None, help="Stored record id to inspect")
@click.option(
    "--insecure", is_flag=True, default=False, help="Disable TLS verification"
)
@click.pass_context
def waf_cmd(ctx, target, url, from_id, insecure):
    """Detect WAF / CDN shields protecting the target."""
    ctx.invoke(
        detect_cmd,
        target=target,
        url=url,
        from_id=from_id,
        waf_only=True,
        tech_only=False,
        insecure=insecure,
    )


@cli.command("tech")
@click.argument("target", required=False, default=None)
@click.option(
    "-u", "--url", default=None, help="Target URL to fingerprint technologies"
)
@click.option("--from", "from_id", default=None, help="Stored record id to inspect")
@click.option(
    "--insecure", is_flag=True, default=False, help="Disable TLS verification"
)
@click.pass_context
def tech_cmd(ctx, target, url, from_id, insecure):
    """Detect web servers, frameworks, CMS, and frontend libraries."""
    ctx.invoke(
        detect_cmd,
        target=target,
        url=url,
        from_id=from_id,
        waf_only=False,
        tech_only=True,
        insecure=insecure,
    )


# ------------------------------------------------------------------ passive reconnaissance & enum
@cli.command("passive")
@click.argument("target", required=False, default=None)
@click.option("-u", "--url", default=None, help="Target domain or URL")
@click.option(
    "--no-subdomains",
    is_flag=True,
    help="Skip Certificate Transparency subdomain enumeration",
)
@click.option("--no-dns", is_flag=True, help="Skip DNS and email posture queries")
@click.option("--no-sec-txt", is_flag=True, help="Skip security.txt inspection")
@click.option("--no-headers", is_flag=True, help="Skip security headers audit")
@click.option("--save", is_flag=True, help="Save findings to workspace findings.json")
@click.option(
    "--timeout",
    type=float,
    default=8.0,
    help="HTTP/DNS request timeout in seconds",
)
@click.option(
    "--insecure", is_flag=True, default=False, help="Disable TLS verification"
)
@click.pass_context
def passive_cmd(
    ctx,
    target,
    url,
    no_subdomains,
    no_dns,
    no_sec_txt,
    no_headers,
    save,
    timeout,
    insecure,
):
    """Passive reconnaissance: DNS records, SPF/DMARC posture, subdomains, security.txt, and security headers."""
    import asyncio

    from .passive import run_passive_enum
    from .render import md_passive

    target_val = target or url
    if not target_val:
        cfg = (ctx.obj or {}).get("config")
        if cfg and cfg.target:
            target_val = cfg.target
        else:
            ws = _find_workspace(ctx, require=False)
            if ws:
                try:
                    target_val = ws.load_config().target
                except DarcoError:
                    pass

    if not target_val:
        raise DarcoError(
            "provide a target domain or URL: 'darco passive <target>' or -u <url>"
        )

    report = asyncio.run(
        run_passive_enum(
            target_val,
            subdomains=not no_subdomains,
            dns=not no_dns,
            security_txt=not no_sec_txt,
            headers=not no_headers,
            timeout=timeout,
            verify=not insecure,
        )
    )

    if save:
        ws = _find_workspace(ctx, auto_create_target=target_val)
        if ws:
            ws.add_findings(report.findings)

    _emit(ctx, to_json(report), md_passive)


@cli.command("enum")
@click.argument("target", required=False, default=None)
@click.option("-u", "--url", default=None, help="Target domain or URL")
@click.option(
    "--no-subdomains",
    is_flag=True,
    help="Skip Certificate Transparency subdomain enumeration",
)
@click.option("--no-dns", is_flag=True, help="Skip DNS and email posture queries")
@click.option("--no-sec-txt", is_flag=True, help="Skip security.txt inspection")
@click.option("--no-headers", is_flag=True, help="Skip security headers audit")
@click.option("--save", is_flag=True, help="Save findings to workspace findings.json")
@click.option("--timeout", type=float, default=8.0)
@click.option("--insecure", is_flag=True, default=False)
@click.pass_context
def enum_cmd(
    ctx,
    target,
    url,
    no_subdomains,
    no_dns,
    no_sec_txt,
    no_headers,
    save,
    timeout,
    insecure,
):
    """Alias for passive reconnaissance & enumeration."""
    ctx.invoke(
        passive_cmd,
        target=target,
        url=url,
        no_subdomains=no_subdomains,
        no_dns=no_dns,
        no_sec_txt=no_sec_txt,
        no_headers=no_headers,
        save=save,
        timeout=timeout,
        insecure=insecure,
    )


@cli.command("info")
@click.argument("target", required=False, default=None)
@click.option("-u", "--url", default=None, help="Target domain or URL")
@click.option("--no-subdomains", is_flag=True)
@click.option("--no-dns", is_flag=True)
@click.option("--no-sec-txt", is_flag=True)
@click.option("--no-headers", is_flag=True)
@click.option("--save", is_flag=True)
@click.option("--timeout", type=float, default=8.0)
@click.option("--insecure", is_flag=True, default=False)
@click.pass_context
def info_cmd(
    ctx,
    target,
    url,
    no_subdomains,
    no_dns,
    no_sec_txt,
    no_headers,
    save,
    timeout,
    insecure,
):
    """Alias for passive target information gathering."""
    ctx.invoke(
        passive_cmd,
        target=target,
        url=url,
        no_subdomains=no_subdomains,
        no_dns=no_dns,
        no_sec_txt=no_sec_txt,
        no_headers=no_headers,
        save=save,
        timeout=timeout,
        insecure=insecure,
    )


# ------------------------------------------------------------------ sql injection testing
@cli.command("sql")
@click.argument("target", required=False, default=None)
@click.option(
    "-u",
    "--url",
    default=None,
    help="Target URL (e.g. http://example.com/item?id=1)",
)
@click.option("--from", "from_id", default=None, help="Stored record ID to test")
@click.option("-p", "--param", default=None, help="Specific parameter name to test")
@click.option("--save", is_flag=True, help="Save findings to workspace findings.json")
@click.option(
    "--insecure", is_flag=True, default=False, help="Disable TLS verification"
)
@click.pass_context
def sql_cmd(ctx, target, url, from_id, param, save, insecure):
    """SQL injection testing: syntax break, quote balancing, arithmetic evaluation, and boolean differential."""
    from .models import Finding, Request
    from .render import md_sqli
    from .sqli import scan_sqli

    if target:
        if target.isdigit() or (target.startswith("0") and len(target) == 4):
            from_id = from_id or target
        else:
            url = url or target

    base_req = None
    session = None
    ws = None

    if from_id:
        ws = _find_workspace(ctx)
        record = ws.get_record(from_id)
        base_req = record.request
        session = ws.load_session()
    else:
        if not url:
            cfg = (ctx.obj or {}).get("config")
            if cfg and cfg.target:
                url = cfg.target
            else:
                ws = _find_workspace(ctx, require=False)
                if ws:
                    try:
                        url = ws.load_config().target
                    except DarcoError:
                        pass
        if not url:
            raise DarcoError(
                "provide a target URL with parameters: 'darco sql <url>' or -u <url> or --from <id>"
            )
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        split = urlsplit(url)
        params = [
            NameValue(name=k, value=v)
            for k, v in parse_qsl(split.query, keep_blank_values=True)
        ]
        clean_url = url.split("?", 1)[0] if split.query else url
        base_req = Request(
            method="GET",
            url=clean_url,
            params=params,
            verify=not insecure,
            source="oneshot",
        )
        session = _one_shot_session()

    result = scan_sqli(base_req, session=session, param_filter=param)

    if save:
        ws = ws or _find_workspace(ctx, auto_create_target=base_req.url)
        if ws:
            findings = []
            for v in result.vulnerabilities:
                findings.append(
                    Finding(
                        id=f"sqli-{v.param}-{v.injection_type}",
                        type=f"sqli_{v.injection_type}",
                        severity=(
                            "high"
                            if v.confidence in ("confirmed", "high")
                            else "medium"
                        ),
                        location=f"{base_req.method} {base_req.url} ({v.param})",
                        evidence=v.evidence,
                        suggestion=v.suggestion,
                    )
                )
            ws.add_findings(findings)

    _emit(ctx, to_json(result), md_sqli)


@cli.command("sqli")
@click.argument("target", required=False, default=None)
@click.option("-u", "--url", default=None, help="Target URL to test for SQL injection")
@click.option("--from", "from_id", default=None, help="Stored record ID to test")
@click.option("-p", "--param", default=None, help="Specific parameter name to test")
@click.option("--save", is_flag=True, help="Save findings to workspace findings.json")
@click.option("--insecure", is_flag=True, default=False)
@click.pass_context
def sqli_cmd(ctx, target, url, from_id, param, save, insecure):
    """Alias for SQL injection testing."""
    ctx.invoke(
        sql_cmd,
        target=target,
        url=url,
        from_id=from_id,
        param=param,
        save=save,
        insecure=insecure,
    )


# ------------------------------------------------------------------ xss & reflection testing
@cli.command("xss")
@click.argument("target", required=False, default=None)
@click.option(
    "-u",
    "--url",
    default=None,
    help="Target URL (e.g. http://example.com/search?q=test)",
)
@click.option("--from", "from_id", default=None, help="Stored record ID to test")
@click.option("-p", "--param", default=None, help="Specific parameter name to test")
@click.option(
    "-H",
    "--header",
    "headers",
    multiple=True,
    help="Add custom headers (e.g. -H 'Authorization: Bearer ...')",
)
@click.option(
    "-C",
    "--cookie",
    "cookies",
    multiple=True,
    help="Add custom cookies (e.g. -C 'session=xyz')",
)
@click.option("--save", is_flag=True, help="Save findings to workspace findings.json")
@click.option(
    "--insecure", is_flag=True, default=False, help="Disable TLS verification"
)
@click.pass_context
def xss_cmd(ctx, target, url, from_id, param, headers, cookies, save, insecure):
    """XSS & reflection audit: probes inputs, classifies reflection contexts, and audits HTML encoding."""
    from .models import Cookie, Finding, NameValue, Request
    from .render import md_xss
    from .xss import scan_xss

    if target:
        if target.isdigit() or (target.startswith("0") and len(target) == 4):
            from_id = from_id or target
        else:
            url = url or target

    base_req = None
    session = None
    ws = None

    if from_id:
        ws = _find_workspace(ctx)
        record = ws.get_record(from_id)
        base_req = record.request.model_copy(deep=True)
        session = ws.load_session()
    else:
        if not url:
            cfg = (ctx.obj or {}).get("config")
            if cfg and cfg.target:
                url = cfg.target
            else:
                ws = _find_workspace(ctx, require=False)
                if ws:
                    try:
                        url = ws.load_config().target
                    except DarcoError:
                        pass
        if not url:
            raise DarcoError(
                "provide a target URL with parameters: 'darco xss <url>' or -u <url> or --from <id>"
            )
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        split = urlsplit(url)
        params = [
            NameValue(name=k, value=v)
            for k, v in parse_qsl(split.query, keep_blank_values=True)
        ]
        clean_url = url.split("?", 1)[0] if split.query else url
        base_req = Request(
            method="GET",
            url=clean_url,
            params=params,
            verify=not insecure,
            source="oneshot",
        )
        ws = _find_workspace(ctx, require=False)
        session = ws.load_session() if ws else _one_shot_session()

    # Append any user-provided headers or cookies
    if headers:
        for h in headers:
            if ":" in h:
                k, v = h.split(":", 1)
                base_req.headers.append(NameValue(name=k.strip(), value=v.strip()))
    if cookies:
        for c in cookies:
            if "=" in c:
                k, v = c.split("=", 1)
                session.cookies.append(Cookie(name=k.strip(), value=v.strip()))

    result = scan_xss(base_req, session=session, param_filter=param)

    if save:
        ws = ws or _find_workspace(ctx, auto_create_target=base_req.url)
        if ws:
            findings = []
            for r in result.reflections:
                if r.confidence in ("confirmed", "high", "medium"):
                    findings.append(
                        Finding(
                            id=f"xss-{r.param}-{r.context}",
                            type=f"xss_{r.context}",
                            severity=(
                                "high"
                                if r.confidence in ("confirmed", "high")
                                else "medium"
                            ),
                            location=f"{base_req.method} {base_req.url} ({r.param})",
                            evidence=r.evidence,
                            suggestion=r.suggestion,
                        )
                    )
            ws.add_findings(findings)

    _emit(ctx, to_json(result), md_xss)


@cli.command("reflect")
@click.argument("target", required=False, default=None)
@click.option("-u", "--url", default=None, help="Target URL to test for reflection")
@click.option("--from", "from_id", default=None, help="Stored record ID to test")
@click.option("-p", "--param", default=None, help="Specific parameter name to test")
@click.option("-H", "--header", "headers", multiple=True)
@click.option("-C", "--cookie", "cookies", multiple=True)
@click.option("--save", is_flag=True)
@click.option("--insecure", is_flag=True, default=False)
@click.pass_context
def reflect_cmd(ctx, target, url, from_id, param, headers, cookies, save, insecure):
    """Alias for XSS & reflection audit."""
    ctx.invoke(
        xss_cmd,
        target=target,
        url=url,
        from_id=from_id,
        param=param,
        headers=headers,
        cookies=cookies,
        save=save,
        insecure=insecure,
    )


# ------------------------------------------------------------------ file upload audit
@cli.command("upload")
@click.argument("target", required=False, default=None)
@click.option(
    "-u",
    "--url",
    default=None,
    help="Target upload URL (e.g. http://example.com/api/upload)",
)
@click.option("--from", "from_id", default=None, help="Stored record ID to audit")
@click.option(
    "-p",
    "--param",
    "file_field",
    default=None,
    help="File input field name (e.g. file, avatar, upload)",
)
@click.option(
    "-H",
    "--header",
    "headers",
    multiple=True,
    help="Add custom headers (e.g. -H 'Authorization: Bearer ...')",
)
@click.option(
    "-C",
    "--cookie",
    "cookies",
    multiple=True,
    help="Add custom cookies (e.g. -C 'session=xyz')",
)
@click.option("--save", is_flag=True, help="Save findings to workspace findings.json")
@click.option(
    "--insecure", is_flag=True, default=False, help="Disable TLS verification"
)
@click.pass_context
def upload_cmd(ctx, target, url, from_id, file_field, headers, cookies, save, insecure):
    """File upload security audit: tests SVG (XSS vector), HTML, MIME bypass, and storage security."""
    from .models import Cookie, Finding, NameValue, Request
    from .render import md_upload
    from .upload import audit_file_upload

    if target:
        if target.isdigit() or (target.startswith("0") and len(target) == 4):
            from_id = from_id or target
        else:
            url = url or target

    base_req = None
    session = None
    ws = None

    if from_id:
        ws = _find_workspace(ctx)
        record = ws.get_record(from_id)
        base_req = record.request.model_copy(deep=True)
        session = ws.load_session()
    else:
        if not url:
            cfg = (ctx.obj or {}).get("config")
            if cfg and cfg.target:
                url = cfg.target
            else:
                ws = _find_workspace(ctx, require=False)
                if ws:
                    try:
                        url = ws.load_config().target
                    except DarcoError:
                        pass
        if not url:
            raise DarcoError(
                "provide a target upload URL: 'darco upload <url>' or -u <url> or --from <id>"
            )
        if not url.startswith(("http://", "https://")):
            url = "http://" + url

        base_req = Request(
            method="POST",
            url=url,
            verify=not insecure,
            source="oneshot",
        )
        ws = _find_workspace(ctx, require=False)
        session = ws.load_session() if ws else _one_shot_session()

    # Append any user-provided headers or cookies
    if headers:
        for h in headers:
            if ":" in h:
                k, v = h.split(":", 1)
                base_req.headers.append(NameValue(name=k.strip(), value=v.strip()))
    if cookies:
        for c in cookies:
            if "=" in c:
                k, v = c.split("=", 1)
                session.cookies.append(Cookie(name=k.strip(), value=v.strip()))

    result = audit_file_upload(base_req, session=session, file_field=file_field)

    if save:
        ws = ws or _find_workspace(ctx, auto_create_target=base_req.url)
        if ws:
            findings = []
            for f in result.findings:
                findings.append(
                    Finding(
                        id=f"upload-{f.param}-{f.vulnerability_type}",
                        type=f"upload_{f.vulnerability_type}",
                        severity=(
                            "high"
                            if f.confidence in ("confirmed", "high")
                            else "medium"
                        ),
                        location=f"{base_req.method} {base_req.url} ({f.param})",
                        evidence=f.evidence,
                        suggestion=f.suggestion,
                    )
                )
            ws.add_findings(findings)

    _emit(ctx, to_json(result), md_upload)


# ------------------------------------------------------------------ js & api extraction
@cli.command("js")
@click.argument("target", required=False, default=None)
@click.option(
    "-u", "--url", default=None, help="Target URL to extract JS APIs & chunks from"
)
@click.option(
    "-f", "--file", "file_path", default=None, help="Local JS file to analyze"
)
@click.option(
    "--max-chunks",
    type=int,
    default=50,
    help="Maximum number of dynamic webpack chunks to fetch",
)
@click.option(
    "--include-cdn",
    is_flag=True,
    default=False,
    help="Include 3rd-party CDN and tracker scripts",
)
@click.option("--save", is_flag=True, help="Save findings to workspace findings.json")
@click.option(
    "--insecure", is_flag=True, default=False, help="Disable TLS verification"
)
@click.option(
    "--timeout",
    type=float,
    default=10.0,
    help="Request timeout in seconds",
)
@click.pass_context
def js_cmd(ctx, target, url, file_path, max_chunks, include_cdn, save, insecure, timeout):
    """Extract API routes, GraphQL queries, parameters, secrets, and webpack chunks from JavaScript."""
    from .js_analyzer import analyze_local_js, analyze_target_js
    from .render import md_js

    target_val = target or url or file_path

    if file_path or (target_val and Path(target_val).is_file()):
        file_to_read = file_path or target_val
        report = analyze_local_js(file_to_read)
        if save:
            ws = _find_workspace(ctx, require=False)
            if ws:
                ws.add_findings(report.findings)
        _emit(ctx, to_json(report), md_js)
        return

    if not target_val:
        cfg = (ctx.obj or {}).get("config")
        if cfg and cfg.target:
            target_val = cfg.target
        else:
            ws = _find_workspace(ctx, require=False)
            if ws:
                try:
                    target_val = ws.load_config().target
                except DarcoError:
                    pass

    if not target_val:
        raise DarcoError(
            "provide a target URL or JS file: 'darco js <url|file.js>' or -u <url> or -f <file.js>'"
        )

    report = asyncio.run(
        analyze_target_js(
            target_val,
            max_chunks=max_chunks,
            ignore_cdn=not include_cdn,
            timeout=timeout,
            verify=not insecure,
        )
    )

    if save:
        ws = _find_workspace(ctx, auto_create_target=target_val)
        if ws:
            ws.add_findings(report.findings)

    _emit(ctx, to_json(report), md_js)


@cli.command("apis")
@click.argument("target", required=False, default=None)
@click.option(
    "-u", "--url", default=None, help="Target URL to extract JS APIs & chunks from"
)
@click.option(
    "-f", "--file", "file_path", default=None, help="Local JS file to analyze"
)
@click.option(
    "--max-chunks",
    type=int,
    default=50,
    help="Maximum number of dynamic webpack chunks to fetch",
)
@click.option(
    "--include-cdn",
    is_flag=True,
    default=False,
    help="Include 3rd-party CDN and tracker scripts",
)
@click.option("--save", is_flag=True, help="Save findings to workspace findings.json")
@click.option(
    "--insecure", is_flag=True, default=False, help="Disable TLS verification"
)
@click.option(
    "--timeout",
    type=float,
    default=10.0,
    help="Request timeout in seconds",
)
@click.pass_context
def apis_cmd(ctx, target, url, file_path, max_chunks, include_cdn, save, insecure, timeout):
    """Alias for JavaScript API and endpoint extraction."""
    ctx.invoke(
        js_cmd,
        target=target,
        url=url,
        file_path=file_path,
        max_chunks=max_chunks,
        include_cdn=include_cdn,
        save=save,
        insecure=insecure,
        timeout=timeout,
    )


# ------------------------------------------------------------------ proxy
@cli.command("proxy")
@click.option("--port", type=int, default=8080)
@click.option("--listen", default="127.0.0.1")
@click.option(
    "--record-only", is_flag=True, default=True, help="Record flows only (v1 mode)"
)
@click.pass_context
def proxy_cmd(ctx, port, listen, record_only):
    from .proxy import ProxyServer

    ws = _find_workspace(ctx)
    session = ws.load_session()
    server = ProxyServer(
        ws, session, host=listen, port=port, base_headers=ws.load_config().base_headers
    )
    bound = server.start()
    click.echo(
        json.dumps(
            {
                "status": "listening",
                "host": listen,
                "port": bound,
                "mode": "record-only",
            }
        )
    )
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()


# ------------------------------------------------------------------ discover / crawl / auto-scan
@cli.command("discover")
@click.argument("url_arg", required=False, default=None)
@click.option(
    "-u", "--url", "url_opt", default=None, help="Target URL to discover/crawl"
)
@click.option("--depth", type=int, default=3)
@click.option("--max-urls", type=int, default=500)
@click.option("--workers", type=int, default=5)
@click.option("--seed", "seed_files", multiple=True, type=click.Path(exists=True))
@click.option("--no-js", is_flag=True)
@click.option("--fuzz", is_flag=True, help="Auto-fuzz discovered endpoints and forms")
@click.option(
    "--sqli",
    is_flag=True,
    help="Auto-test discovered endpoints/forms for SQL injection",
)
@click.option(
    "--xss",
    is_flag=True,
    help="Auto-test discovered endpoints/forms for XSS reflection",
)
@click.option(
    "--upload",
    is_flag=True,
    help="Auto-audit discovered file upload forms/endpoints (SVG/HTML XSS)",
)
@click.option("--insecure", is_flag=True)
@click.option("--timeout", type=float, default=10.0)
@click.pass_context
def discover_cmd(
    ctx,
    url_arg,
    url_opt,
    depth,
    max_urls,
    workers,
    seed_files,
    no_js,
    fuzz,
    sqli,
    xss,
    upload,
    insecure,
    timeout,
):
    """Discover site architecture, endpoints, forms, JS files, and security signals."""
    from .discovery.crawler import discover
    from .render import md_discover, md_scan
    from .scanner import run_auto_scan

    url = url_opt or url_arg
    if not url:
        raise DarcoError(
            "provide a target URL: 'darco discover <url>' or 'darco discover -u <url>'"
        )
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    ws = _find_workspace(ctx, require=False, auto_create_target=url)
    if ws is None:
        ws = Workspace.create(url)

    cfg = ws.load_config()

    if fuzz or sqli or xss or upload:
        report = asyncio.run(
            run_auto_scan(
                ws,
                url,
                depth=depth,
                max_urls=max_urls,
                workers=workers,
                parse_js=not no_js,
                fuzz=fuzz,
                sqli=sqli,
                xss=xss,
                upload=upload,
                timeout=timeout,
                verify=not (cfg.insecure or insecure),
            )
        )
        _emit(ctx, to_json(report), md_scan)
        return

    seeds: list[str] = []
    for f in seed_files:
        seeds.extend(
            line.strip() for line in Path(f).read_text().splitlines() if line.strip()
        )
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
    _emit(ctx, to_json(sitemap), md_discover)


@cli.command("crawl")
@click.argument("url_arg", required=False, default=None)
@click.option("-u", "--url", "url_opt", default=None, help="Target URL to crawl")
@click.option("--depth", type=int, default=3)
@click.option("--max-urls", type=int, default=500)
@click.option("--workers", type=int, default=5)
@click.option("--seed", "seed_files", multiple=True, type=click.Path(exists=True))
@click.option("--no-js", is_flag=True)
@click.option("--fuzz", is_flag=True, help="Auto-fuzz discovered endpoints and forms")
@click.option(
    "--sqli",
    is_flag=True,
    help="Auto-test discovered endpoints/forms for SQL injection",
)
@click.option(
    "--xss",
    is_flag=True,
    help="Auto-test discovered endpoints/forms for XSS reflection",
)
@click.option(
    "--upload",
    is_flag=True,
    help="Auto-audit discovered file upload forms/endpoints",
)
@click.option("--insecure", is_flag=True)
@click.option("--timeout", type=float, default=10.0)
@click.pass_context
def crawl_cmd(
    ctx,
    url_arg,
    url_opt,
    depth,
    max_urls,
    workers,
    seed_files,
    no_js,
    fuzz,
    sqli,
    xss,
    upload,
    insecure,
    timeout,
):
    """Crawl a target website and extract endpoints, forms, and JavaScript references."""
    ctx.invoke(
        discover_cmd,
        url_arg=url_arg,
        url_opt=url_opt,
        depth=depth,
        max_urls=max_urls,
        workers=workers,
        seed_files=seed_files,
        no_js=no_js,
        fuzz=fuzz,
        sqli=sqli,
        xss=xss,
        upload=upload,
        insecure=insecure,
        timeout=timeout,
    )


@cli.command("scan")
@click.argument("url_arg", required=False, default=None)
@click.option("-u", "--url", "url_opt", default=None, help="Target URL to auto-scan")
@click.option("--depth", type=int, default=3)
@click.option("--max-urls", type=int, default=200)
@click.option("--workers", type=int, default=5)
@click.option("--no-fuzz", is_flag=True, help="Disable parameter mutation fuzzing")
@click.option("--no-sqli", is_flag=True, help="Disable SQL injection testing")
@click.option("--no-xss", is_flag=True, help="Disable XSS reflection testing")
@click.option("--no-upload", is_flag=True, help="Disable file upload security auditing")
@click.option("--no-js", is_flag=True)
@click.option("--insecure", is_flag=True)
@click.option("--timeout", type=float, default=10.0)
@click.pass_context
def scan_cmd(
    ctx,
    url_arg,
    url_opt,
    depth,
    max_urls,
    workers,
    no_fuzz,
    no_sqli,
    no_xss,
    no_upload,
    no_js,
    insecure,
    timeout,
):
    """All-in-one automated pipeline: crawl target, detect WAF/tech, and auto-fuzz/audit for SQLi, XSS, and file uploads."""
    ctx.invoke(
        discover_cmd,
        url_arg=url_arg,
        url_opt=url_opt,
        depth=depth,
        max_urls=max_urls,
        workers=workers,
        seed_files=(),
        no_js=no_js,
        fuzz=not no_fuzz,
        sqli=not no_sqli,
        xss=not no_xss,
        upload=not no_upload,
        insecure=insecure,
        timeout=timeout,
    )


@cli.command("auto")
@click.argument("url_arg", required=False, default=None)
@click.option("-u", "--url", "url_opt", default=None, help="Target URL to auto-scan")
@click.option("--depth", type=int, default=3)
@click.option("--max-urls", type=int, default=200)
@click.option("--workers", type=int, default=5)
@click.option("--no-fuzz", is_flag=True)
@click.option("--no-sqli", is_flag=True)
@click.option("--no-xss", is_flag=True)
@click.option("--no-upload", is_flag=True)
@click.option("--no-js", is_flag=True)
@click.option("--insecure", is_flag=True)
@click.option("--timeout", type=float, default=10.0)
@click.pass_context
def auto_cmd(
    ctx,
    url_arg,
    url_opt,
    depth,
    max_urls,
    workers,
    no_fuzz,
    no_sqli,
    no_xss,
    no_upload,
    no_js,
    insecure,
    timeout,
):
    """Alias for automated crawl and security scan."""
    ctx.invoke(
        scan_cmd,
        url_arg=url_arg,
        url_opt=url_opt,
        depth=depth,
        max_urls=max_urls,
        workers=workers,
        no_fuzz=no_fuzz,
        no_sqli=no_sqli,
        no_xss=no_xss,
        no_upload=no_upload,
        no_js=no_js,
        insecure=insecure,
        timeout=timeout,
    )


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
@click.option(
    "--response", "want_response", is_flag=True, help="Emit raw HTTP response text"
)
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
@click.option(
    "--count", type=int, default=1, help="Number of times to replay the stored request"
)
@click.option(
    "--interval", type=float, default=0.0, help="Seconds to sleep between replays"
)
@click.option(
    "--strip-session",
    is_flag=True,
    help="Remove session cookies/auth headers on every replay",
)
@click.option("--set-header", "set_header", multiple=True)
@click.option("--set-param", "set_param", multiple=True)
@click.option("--unset-param", "unset_param", multiple=True)
@click.option("--follow-redirects/--no-follow-redirects", default=None)
@click.pass_context
def repeat_cmd(
    ctx,
    record_id,
    count,
    interval,
    strip_session,
    set_header,
    set_param,
    unset_param,
    follow_redirects,
):
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

    ops = parse_mutation_ops(
        {
            "set_header": set_header,
            "set_param": set_param,
            "unset_param": unset_param,
            "strip_session": strip_session,
        }
    )

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
        record, session = send_and_record(
            ws, request, session, base_headers=cfg.base_headers
        )
        results.append(
            {
                "index": i,
                "id": record.id,
                "status": record.response.status_code if record.response else None,
                "error": record.error,
            }
        )
        if interval and i < count - 1:
            time.sleep(interval)

    statuses = [r["status"] for r in results if r["status"] is not None]
    _emit(
        ctx,
        {
            "from": record_id,
            "count": count,
            "ids": [r["id"] for r in results],
            "statuses": statuses,
            "distinct_statuses": sorted(set(statuses)),
            "errors": sum(1 for r in results if r["error"]),
        },
        md_repeat,
    )


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
    _emit(
        ctx,
        {"count": len(found), "findings": [to_json(f) for f in found]},
        md_findings_list,
    )


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
