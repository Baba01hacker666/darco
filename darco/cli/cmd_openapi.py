from __future__ import annotations

from pathlib import Path

import click

from ..errors import DarcoError
from ..openapi import export_openapi
from ..render import md_openapi
from ._context import _find_workspace
from ._group import cli
from ._output import _emit


@cli.command("openapi")
@click.option("-o", "--output", "out_file", type=click.Path(), help="File to write OpenAPI spec to")
@click.option("--yaml/--json", "as_yaml", default=False, help="Export format (JSON default, or YAML)")
@click.option("--title", default="Darco Discovered API", help="API title in OpenAPI spec")
@click.option("--version", default="1.0.0", help="API version string")
@click.pass_context
def openapi_cmd(ctx, out_file, as_yaml, title, version):
    """Export workspace sitemap and history into a standard OpenAPI 3.0 specification."""
    ws = _find_workspace(ctx, require=True)

    sitemap = ws.load_sitemap()
    history = ws.load_history()

    if not sitemap and not history:
        raise DarcoError("workspace has no crawled sitemap or history; run 'darco discover <url>' first")

    cfg = ws.load_config()
    target_url = cfg.target if cfg else ""

    spec = export_openapi(
        sitemap=sitemap,
        history=history,
        target_url=target_url,
        title=title,
        version=version,
        as_yaml=as_yaml,
    )

    if out_file:
        content = spec if isinstance(spec, str) else str(spec)
        if isinstance(spec, dict):
            import json
            content = json.dumps(spec, indent=2)
        Path(out_file).write_text(content)

    _emit(ctx, spec if isinstance(spec, dict) else {"spec": spec}, md_openapi)
