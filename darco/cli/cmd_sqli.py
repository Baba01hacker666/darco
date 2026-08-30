"""SQL injection testing commands: sql / sqli."""

from __future__ import annotations

import click

from ..errors import DarcoError
from ..models import to_json
from ._context import _find_workspace
from ._group import cli
from ._oneshot import (
    _resolve_base_request,
)
from ._output import _emit


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
    "--include-state",
    is_flag=True,
    default=False,
    help="Also audit framework state fields (__VIEWSTATE, CSRF tokens, etc.)",
)
@click.option(
    "--insecure", is_flag=True, default=False, help="Disable TLS verification"
)
@click.option("-X", "--method", default=None, help="HTTP method (GET, POST, etc.)")
@click.option("-d", "--data", default=None, help="Request body (prefix @file to read)")
@click.option(
    "-H",
    "--header",
    "cli_header",
    multiple=True,
    help="Header NAME:VALUE (repeatable)",
)
@click.option(
    "-F",
    "--form",
    "cli_form",
    multiple=True,
    help="Form field NAME=VALUE (repeatable)",
)
@click.option(
    "--plugin",
    "only_plugins",
    multiple=True,
    help="Run only these scan plugins (repeatable; see `darco plugins`)",
)
@click.option(
    "--skip-plugin",
    "skip_plugins",
    multiple=True,
    help="Disable a scan plugin (repeatable)",
)
@click.option(
    "--plugin-dir",
    "plugin_dirs",
    multiple=True,
    help="Load external plugin files (*.py) from this directory (repeatable)",
)
@click.pass_context
def sql_cmd(
    ctx,
    target,
    url,
    from_id,
    param,
    save,
    include_state,
    insecure,
    method,
    data,
    cli_header,
    cli_form,
    only_plugins,
    skip_plugins,
    plugin_dirs,
):
    """SQL injection testing: syntax break, quote balancing, arithmetic evaluation, and boolean differential."""
    from ..models import Finding
    from ..plugins import load_plugins_from_dir
    from ..render import md_sqli
    from ..sqli import scan_sqli

    for d in plugin_dirs:
        load_plugins_from_dir(d)

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
        base_req, session, is_oneshot = _resolve_base_request(
            ctx, None, None, None, url, method, data, cli_header, cli_form
        )
        if is_oneshot:
            base_req.verify = not insecure

    result = scan_sqli(
        base_req,
        session=session,
        param_filter=param,
        include_state_fields=include_state,
        only_plugins=list(only_plugins) if only_plugins else None,
        skip_plugins=list(skip_plugins) if skip_plugins else None,
    )

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
@click.option(
    "--include-state",
    is_flag=True,
    default=False,
    help="Also audit framework state fields (__VIEWSTATE, CSRF tokens, etc.)",
)
@click.option("--insecure", is_flag=True, default=False)
@click.option("-X", "--method", default=None, help="HTTP method (GET, POST, etc.)")
@click.option("-d", "--data", default=None, help="Request body (prefix @file to read)")
@click.option(
    "-H",
    "--header",
    "cli_header",
    multiple=True,
    help="Header NAME:VALUE (repeatable)",
)
@click.option(
    "-F",
    "--form",
    "cli_form",
    multiple=True,
    help="Form field NAME=VALUE (repeatable)",
)
@click.option("--plugin", "only_plugins", multiple=True)
@click.option("--skip-plugin", "skip_plugins", multiple=True)
@click.option("--plugin-dir", "plugin_dirs", multiple=True)
@click.pass_context
def sqli_cmd(
    ctx,
    target,
    url,
    from_id,
    param,
    save,
    include_state,
    insecure,
    method,
    data,
    cli_header,
    cli_form,
    only_plugins,
    skip_plugins,
    plugin_dirs,
):
    """Alias for SQL injection testing."""
    ctx.invoke(
        sql_cmd,
        target=target,
        url=url,
        from_id=from_id,
        param=param,
        save=save,
        include_state=include_state,
        insecure=insecure,
        method=method,
        data=data,
        cli_header=cli_header,
        cli_form=cli_form,
        only_plugins=only_plugins,
        skip_plugins=skip_plugins,
        plugin_dirs=plugin_dirs,
    )
