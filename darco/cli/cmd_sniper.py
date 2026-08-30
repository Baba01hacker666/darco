from __future__ import annotations

from pathlib import Path

import click

from ..errors import DarcoError
from ..ingest import parse_curl, parse_raw_http
from ..models import to_json
from ..render import md_sniper
from ..sniper import execute_sniper, parse_payload_source
from ._context import _find_workspace
from ._group import cli
from ._oneshot import _build_oneshot
from ._output import _emit


@cli.command("sniper")
@click.argument("target", required=False, default=None)
@click.option("-u", "--url", "url_opt", default=None, help="Target URL (supports §marker§ positions)")
@click.option(
    "--from",
    "from_id",
    default=None,
    help="Workspace history ID (0001) to use as base template",
)
@click.option("--curl", "curl_cmd", default=None, help="Curl command with §marker§ positions")
@click.option("--raw", "raw_file", type=click.Path(), default=None, help="Raw HTTP request file with §marker§ positions")
@click.option(
    "-m",
    "--mode",
    type=click.Choice(["sniper", "battering_ram", "pitchfork", "cluster_bomb"], case_sensitive=False),
    default="sniper",
    help="Attack matrix mode: sniper, battering_ram, pitchfork, cluster_bomb",
)
@click.option(
    "-w",
    "--wordlist",
    "wordlists",
    multiple=True,
    help="Payload wordlist file or comma-separated list (can specify multiple times)",
)
@click.option(
    "-p",
    "--payload",
    "payloads",
    multiple=True,
    help="Inline payload string(s)",
)
@click.option(
    "--numbers",
    "numbers_range",
    default=None,
    help="Generate numbers range, e.g. '1-100' or '001-100:2'",
)
@click.option("-c", "--concurrency", type=int, default=10, help="Concurrent request workers")
@click.option("--delay", "delay_ms", type=int, default=0, help="Delay in milliseconds between requests")
@click.option("--match-status", "match_status", default=None, help="Filter/highlight status codes, e.g. '200,302'")
@click.option("--match-regex", "match_regex", default=None, help="Highlight responses matching regular expression")
@click.option("--extract-regex", "extract_regex", default=None, help="Extract regex group snippet from responses")
@click.option("--marker", default="§", help="Position marker character (default: '§')")
@click.option(
    "-H",
    "--header",
    "headers",
    multiple=True,
    help="Custom request header 'Name: Value'",
)
@click.option("-d", "--data", default=None, help="HTTP request body data")
@click.option("-X", "--method", default=None, help="HTTP method")
@click.pass_context
def sniper_cmd(
    ctx,
    target,
    url_opt,
    from_id,
    curl_cmd,
    raw_file,
    mode,
    wordlists,
    payloads,
    numbers_range,
    concurrency,
    delay_ms,
    match_status,
    match_regex,
    extract_regex,
    marker,
    headers,
    data,
    method,
):
    """Custom parameter sniper and multi-position payload matrix attack engine."""
    ws = _find_workspace(ctx, require=False)

    # 1. Resolve Base Request
    if from_id:
        if ws is None:
            raise DarcoError("need a workspace to load history: run 'darco init <target>'")
        record = ws.get_record(from_id)
        if not record:
            raise DarcoError(f"history record '{from_id}' not found")
        base_req = record.request.model_copy(deep=True)
    elif curl_cmd:
        base_req = parse_curl(curl_cmd)
    elif raw_file:
        base_req = parse_raw_http(Path(raw_file).read_text())
    else:
        url = url_opt or target
        if not url:
            raise DarcoError("provide a target URL with §marker§ positions, --curl, --raw, or --from <id>")
        base_req = _build_oneshot(
            url=url,
            method=method or ("POST" if data else "GET"),
            data=data,
            cli_header=headers,
        )

    # 2. Build Payload Lists
    payload_lists: list[list[str]] = []
    for w in wordlists:
        payload_lists.append(parse_payload_source(w))
    if payloads:
        inline_list = []
        for p in payloads:
            inline_list.extend(parse_payload_source(p))
        payload_lists.append(inline_list)
    if numbers_range:
        payload_lists.append(parse_payload_source(numbers_range))

    if not payload_lists:
        payload_lists = [["test", "admin", "guest"]]

    # 3. Status filter parse
    match_codes = None
    if match_status:
        match_codes = [int(s.strip()) for s in match_status.split(",") if s.strip().isdigit()]

    session = ws.load_session() if ws else None
    report = execute_sniper(
        base_request=base_req,
        session=session,
        mode=mode,
        payload_lists=payload_lists,
        concurrency=concurrency,
        match_status=match_codes,
        match_regex=match_regex,
        extract_regex=extract_regex,
        marker=marker,
        delay_ms=delay_ms,
    )

    _emit(ctx, to_json(report), md_sniper)
