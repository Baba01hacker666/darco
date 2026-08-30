"""XSS testing commands: xss, reflect, sxss/stored-xss."""

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



# ------------------------------------------------------------------ xss & reflection testing
@cli.command("xss")
@click.argument("target", required=False, default=None)
@click.option(
    "-u",
    "--url",
    default=None,
    help="Target URL (e.g. http://example.com/search?q=test)",
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
def xss_cmd(
    ctx, target, url, from_id, param, headers, cookies, method, data, cli_form,
    save, include_state, insecure,
):
    """XSS & reflection audit: probes inputs, classifies reflection contexts, and audits HTML encoding."""
    from ..models import Cookie, Finding, NameValue
    from ..render import md_xss
    from ..xss import scan_xss

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
                "provide a target URL with parameters: 'darco xss <url>' or -u <url> or --from <id>"
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

    result = scan_xss(
        base_req,
        session=session,
        param_filter=param,
        include_state_fields=include_state,
    )

    if save:
        ws = ws or _find_workspace(ctx, auto_create_target=base_req.url)
        if ws:
            findings = []
            for r in result.reflections:
                if r.confidence in ("confirmed", "high", "medium"):
                    findings.append(
                        Finding(
                            id=f"xss-{r.param}-{r.context}",
                            type=f"xss_{r.context}",
                            severity=(
                                "high"
                                if r.confidence in ("confirmed", "high")
                                else "medium"
                            ),
                            location=f"{base_req.method} {base_req.url} ({r.param})",
                            evidence=r.evidence,
                            suggestion=r.suggestion,
                        )
                    )
            ws.add_findings(findings)

    _emit(ctx, to_json(result), md_xss)


@cli.command("reflect")
@click.argument("target", required=False, default=None)
@click.option("-u", "--url", default=None, help="Target URL to test for reflection")
@click.option("--from", "from_id", default=None, help="Stored record ID to test")
@click.option("-p", "--param", default=None, help="Specific parameter name to test")
@click.option("-H", "--header", "headers", multiple=True)
@click.option("-C", "--cookie", "cookies", multiple=True)
@click.option("-X", "--method", default=None, help="HTTP method (GET, POST, etc.)")
@click.option("-d", "--data", default=None, help="Request body (prefix @file to read)")
@click.option("-F", "--form", "cli_form", multiple=True, help="Form field NAME=VALUE")
@click.option("--save", is_flag=True)
@click.option(
    "--include-state",
    is_flag=True,
    default=False,
    help="Also audit framework state fields (__VIEWSTATE, CSRF tokens, etc.)",
)
@click.option("--insecure", is_flag=True, default=False)
@click.pass_context
def reflect_cmd(
    ctx, target, url, from_id, param, headers, cookies, method, data, cli_form,
    save, include_state, insecure,
):
    """Alias for XSS & reflection audit."""
    ctx.invoke(
        xss_cmd,
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

# ------------------------------------------------------------------ stored xss testing
@cli.command("sxss")
@click.argument("target", required=False, default=None)
@click.option(
    "-u",
    "--url",
    default=None,
    help="Page containing storable forms (comments, profiles, reviews...)",
)
@click.option("--from", "from_id", default=None, help="Stored record ID; uses its URL")
@click.option("--save", is_flag=True, help="Save findings to workspace findings.json")
@click.option(
    "--insecure", is_flag=True, default=False, help="Disable TLS verification"
)
@click.pass_context
def sxss_cmd(ctx, target, url, from_id, save, insecure):
    """Stored XSS audit: submits canaries through storable forms and verifies raw rendering on later views."""
    import httpx as _httpx

    from ..discovery.parsers import extract_forms
    from ..models import Finding
    from ..render import md_stored_xss
    from ..stored_xss import USER_AGENT, audit_stored_xss
    from bs4 import BeautifulSoup

    if target:
        if target.isdigit() or (target.startswith("0") and len(target) == 4):
            from_id = from_id or target
        else:
            url = url or target

    ws = _find_workspace(ctx, require=False)
    if from_id and not url:
        _ws = _find_workspace(ctx)
        record = _ws.get_record(from_id)
        url = record.request.url

    if not url:
        cfg = (ctx.obj or {}).get("config")
        if cfg and cfg.target:
            url = cfg.target
        else:
            if ws:
                try:
                    url = ws.load_config().target
                except DarcoError:
                    pass
    if not url:
        raise DarcoError(
            "provide a page containing storable forms: 'darco sxss <url>' or --from <id>"
        )

    try:
        with _httpx.Client(
            verify=not insecure, timeout=10.0, trust_env=False, follow_redirects=True
        ) as client:
            resp = client.get(url, headers={"User-Agent": USER_AGENT})
            resp.raise_for_status()
            # Use the final URL after redirects as the form-discovery base.
            forms = extract_forms(BeautifulSoup(resp.text, "html.parser"), str(resp.url))
            result = audit_stored_xss(forms, target=url, verify=not insecure)
    except _httpx.HTTPError as exc:
        raise DarcoError(f"failed to fetch '{url}': {exc}") from exc

    if save:
        ws = ws or _find_workspace(ctx, auto_create_target=url)
        if ws:
            ws.add_findings(
                [
                    Finding(
                        id=f"stored-xss-{f.param}-{f.context}",
                        type=f"stored_xss_{f.context}",
                        severity="high",
                        location=f"{f.method} {f.form_action} ({f.param}) -> {f.render_url}",
                        evidence=f.evidence,
                        suggestion=f.suggestion,
                    )
                    for f in result.findings
                ]
            )

    _emit(ctx, to_json(result), md_stored_xss)


@cli.command("stored-xss")
@click.argument("target", required=False, default=None)
@click.option("-u", "--url", default=None)
@click.option("--from", "from_id", default=None)
@click.option("--save", is_flag=True)
@click.option("--insecure", is_flag=True, default=False)
@click.pass_context
def stored_xss_cmd(ctx, target, url, from_id, save, insecure):
    """Alias for the stored XSS audit."""
    ctx.invoke(
        sxss_cmd,
        target=target,
        url=url,
        from_id=from_id,
        save=save,
        insecure=insecure,
    )
