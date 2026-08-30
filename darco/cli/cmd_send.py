"""Request flow commands: send, diff, analyze, repeat."""

from __future__ import annotations

import sys
from pathlib import Path

import click

from ..configfile import DarcoConfig
from ..errors import DarcoError
from ..models import to_json

from ._group import cli
from ._context import _find_workspace, _one_shot_session
from ._oneshot import (
    _apply_send_mutations,
    _build_oneshot,
)
from ._output import _echo_json, _emit
from ._rawio import _raw_response



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
    from ..engine import send_and_record, send_request
    from ..mutate import apply_mutations, parse_mutation_ops
    from ..render import md_send

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
            from ..fuzz import run_fuzz

            cfg = (ctx.obj or {}).get("config") or DarcoConfig.empty()
            fres = run_fuzz(
                req,
                _one_shot_session(),
                baseline_response=response,
                concurrency=cfg.fuzz.concurrency,
            )
            from ..detection import detect_technologies, detect_waf

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

        from ..detection import detect_technologies, detect_waf

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
        from ..ingest import parse_curl

        base = parse_curl(curl_cmd)
    elif raw_file:
        from ..ingest import parse_raw_http

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

    from ..detection import detect_technologies, detect_waf

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
        from ..diff import diff_responses

        output["diff"] = diff_responses(other.response, record.response)
    if do_fuzz:
        from ..fuzz import run_fuzz

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

# ------------------------------------------------------------------ diff
@cli.command("diff")
@click.argument("id_a")
@click.argument("id_b")
@click.pass_context
def diff_cmd(ctx, id_a, id_b):
    from ..diff import diff_responses
    from ..render import md_diff

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
    from ..analyze import analyze_request, analyze_response
    from ..render import md_analyze

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

    from ..engine import send_and_record
    from ..mutate import apply_mutations, parse_mutation_ops
    from ..render import md_repeat

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
