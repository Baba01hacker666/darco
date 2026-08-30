"""Open redirect testing commands: redirect / open-redirect."""

from __future__ import annotations


import click

from ..errors import DarcoError
from ..models import to_json

from ._group import cli
from ._context import _find_workspace
from ._oneshot import (
    _resolve_base_request,
)
from ._output import _emit



# ------------------------------------------------------------------ open redirect testing
@cli.command("redirect")
@click.argument("target", required=False, default=None)
@click.option(
    "-u",
    "--url",
    default=None,
    help="Target URL (e.g. http://example.com/next?r=/dashboard)",
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
@click.option("-X", "--method", default=None, help="HTTP method (GET, POST, etc.)")
@click.option("-d", "--data", default=None, help="Request body (prefix @file to read)")
@click.option(
    "-F",
    "--form",
    "cli_form",
    multiple=True,
    help="Form field NAME=VALUE (repeatable)",
)
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
@click.pass_context
def redirect_cmd(
    ctx, target, url, from_id, param, headers, cookies, method, data, cli_form,
    save, include_state, insecure,
):
    """Open redirect audit: probes redirect-prone parameters with off-site canaries and classifies the redirect mechanism."""
    from ..models import Cookie, Finding, NameValue
    from ..redirect import scan_redirect
    from ..render import md_redirect

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
                "provide a target URL with a redirect-prone parameter: 'darco redirect <url>' or -u <url> or --from <id>"
            )
        ws = _find_workspace(ctx, require=False)
        base_req, session, is_oneshot = _resolve_base_request(
            ctx, None, None, None, url, method, data, (), cli_form
        )
        if is_oneshot:
            base_req.verify = not insecure
            if ws:
                session = ws.load_session()

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

    result = scan_redirect(
        base_req,
        session=session,
        param_filter=param,
        include_state_fields=include_state,
    )

    if save:
        ws = ws or _find_workspace(ctx, auto_create_target=base_req.url)
        if ws:
            findings = []
            for r in result.findings:
                findings.append(
                    Finding(
                        id=f"redirect-{r.param}-{r.redirect_type}",
                        type=f"open_redirect_{r.redirect_type}",
                        severity=(
                            "high" if r.confidence == "confirmed" else "medium"
                        ),
                        location=f"{base_req.method} {base_req.url} ({r.param})",
                        evidence=r.evidence,
                        suggestion=r.suggestion,
                    )
                )
            ws.add_findings(findings)

    _emit(ctx, to_json(result), md_redirect)


@cli.command("open-redirect")
@click.argument("target", required=False, default=None)
@click.option("-u", "--url", default=None)
@click.option("--from", "from_id", default=None)
@click.option("-p", "--param", default=None)
@click.option("-H", "--header", "headers", multiple=True)
@click.option("-C", "--cookie", "cookies", multiple=True)
@click.option("-X", "--method", default=None)
@click.option("-d", "--data", default=None)
@click.option("-F", "--form", "cli_form", multiple=True)
@click.option("--save", is_flag=True)
@click.option("--include-state", is_flag=True, default=False)
@click.option("--insecure", is_flag=True, default=False)
@click.pass_context
def open_redirect_cmd(
    ctx, target, url, from_id, param, headers, cookies, method, data, cli_form,
    save, include_state, insecure,
):
    """Alias for the open redirect audit."""
    ctx.invoke(
        redirect_cmd,
        target=target,
        url=url,
        from_id=from_id,
        param=param,
        headers=headers,
        cookies=cookies,
        method=method,
        data=data,
        cli_form=cli_form,
        save=save,
        include_state=include_state,
        insecure=insecure,
    )
