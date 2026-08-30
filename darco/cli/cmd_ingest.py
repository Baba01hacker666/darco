"""Ingest commands: curl, raw, har."""

from __future__ import annotations

import sys
from datetime import UTC, datetime
from pathlib import Path

import click

from ..models import HistoryRecord, Request, to_json
from ..workspace import Workspace
from ._context import _find_workspace
from ._group import cli
from ._output import _emit


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
    from ..ingest import parse_curl
    from ..render import md_store

    ws = _find_workspace(ctx)
    if len(command) == 1 and " " in command[0]:
        request = parse_curl(command[0])
    else:
        request = parse_curl(list(command))
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
    from ..ingest import parse_raw_http
    from ..render import md_store

    ws = _find_workspace(ctx)
    text = sys.stdin.read() if file == "-" else Path(file).read_text()
    request = parse_raw_http(text, scheme=scheme)
    _emit(ctx, _store_parsed(ws, request, dry_run), md_store)


@ingest_group.command("har")
@click.argument("file", type=click.Path(exists=True))
@click.option("--dry-run", is_flag=True)
@click.pass_context
def ingest_har(ctx, file, dry_run):
    from ..ingest import parse_har
    from ..render import md_store

    ws = _find_workspace(ctx)
    requests = parse_har(file)
    if dry_run:
        _emit(ctx, {"requests": [to_json(r) for r in requests]}, md_store)
        return
    results = [_store_parsed(ws, r, dry_run) for r in requests]
    _emit(ctx, {"stored": len(results), "records": results}, md_store)
