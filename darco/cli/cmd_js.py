"""JS analysis commands: js / apis."""

from __future__ import annotations

import asyncio
from pathlib import Path

import click

from ..errors import DarcoError
from ..models import to_json

from ._group import cli
from ._context import _find_workspace
from ._output import _emit



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
    from ..js_analyzer import analyze_local_js, analyze_target_js
    from ..render import md_js

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
