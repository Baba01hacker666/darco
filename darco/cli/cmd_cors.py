from __future__ import annotations

import click

from ..cors import scan_cors
from ..errors import DarcoError
from ..models import to_json
from ..render import md_cors
from ._context import _find_workspace
from ._group import cli
from ._oneshot import _build_oneshot
from ._output import _emit


@cli.command("cors")
@click.argument("target", required=False, default=None)
@click.option("-u", "--url", "url_opt", default=None, help="Target URL to audit for CORS")
@click.option(
    "--from",
    "from_id",
    default=None,
    help="Workspace history ID (0001) to replay as base request",
)
@click.option(
    "--origin",
    "extra_origins",
    multiple=True,
    help="Extra custom Origin header(s) to probe",
)
@click.option(
    "-H",
    "--header",
    "headers",
    multiple=True,
    help="Custom request header 'Name: Value'",
)
@click.option("-b", "--cookie", "cookies", multiple=True, help="Cookie 'name=val'")
@click.option("--insecure", is_flag=True, help="Disable TLS verification")
@click.option("--timeout", type=float, default=10.0, help="HTTP timeout in seconds")
@click.pass_context
def cors_cmd(
    ctx,
    target,
    url_opt,
    from_id,
    extra_origins,
    headers,
    cookies,
    insecure,
    timeout,
):
    """Audit an endpoint for CORS misconfigurations (arbitrary origin, null, wildcard credentials)."""
    ws = _find_workspace(ctx, require=False)

    if from_id:
        if ws is None:
            raise DarcoError("need a workspace to load history: run 'darco init <target>'")
        record = ws.get_record(from_id)
        if not record:
            raise DarcoError(f"history record '{from_id}' not found")
        req = record.request.model_copy(deep=True)
    else:
        url = url_opt or target
        if not url:
            raise DarcoError("provide a target URL or --from <id>")
        req = _build_oneshot(
            url=url,
            method="GET",
            cli_header=headers,
        )
        if cookies:
            from ..ingest.curl import _parse_cookies
            req.cookies = _parse_cookies("; ".join(cookies))
        req.timeout = timeout
        req.verify = not insecure

    session = ws.load_session() if ws else None
    result = scan_cors(req, session=session, extra_origins=list(extra_origins) if extra_origins else None)

    if ws and result.findings:
        from ..models import Finding

        f_models = [
            Finding(
                id=ws.next_id(),
                type=f"cors_{f.misconfig_type}",
                severity="high" if f.confidence in ("confirmed", "high") else "medium",
                location=req.url,
                evidence=f.evidence,
                suggestion=f.suggestion,
            )
            for f in result.findings
        ]
        ws.add_findings(f_models)

    _emit(ctx, to_json(result), md_cors)
