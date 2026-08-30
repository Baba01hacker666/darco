"""Fuzz command (smart default engine)."""

from __future__ import annotations

from pathlib import Path

import click

from ..configfile import DarcoConfig
from ..errors import DarcoError

from ._group import cli
from ._oneshot import (
    _engine_execute,
    _resolve_base_request,
)
from ._output import _emit



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
@click.option(
    "--include-state",
    is_flag=True,
    default=False,
    help="Also fuzz framework state fields (__VIEWSTATE, CSRF tokens, etc.)",
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
    include_state,
):
    """Smart-default fuzz: auto-mutate params (flip, type-confuse numerics, boundaries, SQL/XSS) and report anomalies."""
    from ..render import md_fuzz

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

    # v2 smart fuzzer: context-aware payloads + semantic anomaly scoring
    from ..fuzz_v2 import run_fuzz

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
    result = run_fuzz(
        req,
        session,
        baseline_response=baseline,
        concurrency=conc,
        include_state_fields=include_state,
    )
    _emit(ctx, result, md_fuzz)
