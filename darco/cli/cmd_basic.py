"""Core commands: version, plugins, init, status, session, export, findings."""

from __future__ import annotations

from pathlib import Path

import click

from .. import __version__
from ..errors import DarcoError
from ..models import NameValue, SessionState, to_json
from ..workspace import Workspace

from ._group import cli
from ._context import _find_workspace
from ._output import _emit
from ._rawio import _raw_request, _raw_response



@cli.command("version")
def version_cmd():
    click.echo(f"darco {__version__}")


# ------------------------------------------------------------------ plugins
@cli.command("plugins")
@click.option(
    "--plugin-dir",
    "plugin_dirs",
    multiple=True,
    help="Load external plugin files (*.py) from this directory (repeatable)",
)
@click.pass_context
def plugins_cmd(ctx, plugin_dirs):
    """List registered scan plugins and custom template types."""
    from ..plugins import load_plugins_from_dir, registered_plugins
    from ..render import md_plugins
    from ..templates.custom import (
        registered_extractor_types,
        registered_matcher_types,
    )

    for d in plugin_dirs:
        load_plugins_from_dir(d)

    rows = [
        {
            "name": p.name,
            "description": p.description,
            "source": p.source,
        }
        for p in registered_plugins()
    ]
    _emit(
        ctx,
        {
            "plugins": rows,
            "custom_types": {
                "matchers": sorted(registered_matcher_types()),
                "extractors": sorted(registered_extractor_types()),
            },
        },
        md_plugins,
    )


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
    from ..render import md_init

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

# ------------------------------------------------------------------ status / session / export
@cli.command("status")
@click.pass_context
def status_cmd(ctx):
    from ..render import md_status

    ws = _find_workspace(ctx)
    _emit(ctx, ws.status(), md_status)


@cli.group("session", invoke_without_command=True)
@click.pass_context
def session_group(ctx):
    if ctx.invoked_subcommand is None:
        ws = _find_workspace(ctx)
        from ..render import md_session

        _emit(ctx, to_json(ws.load_session()), md_session)


@session_group.command("list")
@click.pass_context
def session_list(ctx):
    from ..render import md_session

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
    from ..render import md_record

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

# ------------------------------------------------------------------ findings
@cli.group("findings")
def findings_group():
    """Inspect findings accumulated in the workspace (via `analyze --save`)."""


@findings_group.command("list")
@click.pass_context
def findings_list(ctx):
    from ..render import md_findings_list

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
