"""Detection and recon commands: detect/waf/tech, passive/enum/info."""

from __future__ import annotations


import click

from ..errors import DarcoError
from ..models import Request, to_json

from ._group import cli
from ._context import _find_workspace, _one_shot_session
from ._output import _emit



# ------------------------------------------------------------------ detect (tech & WAF)
@cli.command("detect")
@click.argument("target", required=False, default=None)
@click.option("-u", "--url", default=None, help="Target URL to fingerprint")
@click.option("--from", "from_id", default=None, help="Stored record id to inspect")
@click.option("--waf-only", is_flag=True, help="Only detect WAF / CDN shields")
@click.option("--tech-only", is_flag=True, help="Only detect web technologies")
@click.option(
    "--insecure", is_flag=True, default=False, help="Disable TLS verification"
)
@click.pass_context
def detect_cmd(ctx, target, url, from_id, waf_only, tech_only, insecure):
    """Detect WAF shields and web technologies from headers, cookies, and body."""
    from ..detection import detect_technologies, detect_waf
    from ..engine import send_request
    from ..render import md_detect

    if target:
        if target.isdigit() or (target.startswith("0") and len(target) == 4):
            from_id = from_id or target
        else:
            url = url or target

    req = None
    resp = None

    if from_id:
        ws = _find_workspace(ctx)
        record = ws.get_record(from_id)
        req = record.request
        resp = record.response
        if not resp:
            raise DarcoError(f"record {from_id!r} has no response to inspect")
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
                "provide a target URL (-u <url>) or record ID (--from <id>)"
            )
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        req = Request(method="GET", url=url, verify=not insecure)
        resp, _ = send_request(req, _one_shot_session())

    wafs = [to_json(w) for w in detect_waf(resp, req)] if not tech_only else []
    techs = [to_json(t) for t in detect_technologies(resp, req)] if not waf_only else []

    out = {
        "target": req.url,
        "status_code": resp.status_code,
        "wafs": wafs,
        "technologies": techs,
    }
    _emit(ctx, out, md_detect)


@cli.command("waf")
@click.argument("target", required=False, default=None)
@click.option("-u", "--url", default=None, help="Target URL to inspect for WAF")
@click.option("--from", "from_id", default=None, help="Stored record id to inspect")
@click.option(
    "--insecure", is_flag=True, default=False, help="Disable TLS verification"
)
@click.pass_context
def waf_cmd(ctx, target, url, from_id, insecure):
    """Detect WAF / CDN shields protecting the target."""
    ctx.invoke(
        detect_cmd,
        target=target,
        url=url,
        from_id=from_id,
        waf_only=True,
        tech_only=False,
        insecure=insecure,
    )


@cli.command("tech")
@click.argument("target", required=False, default=None)
@click.option(
    "-u", "--url", default=None, help="Target URL to fingerprint technologies"
)
@click.option("--from", "from_id", default=None, help="Stored record id to inspect")
@click.option(
    "--insecure", is_flag=True, default=False, help="Disable TLS verification"
)
@click.pass_context
def tech_cmd(ctx, target, url, from_id, insecure):
    """Detect web servers, frameworks, CMS, and frontend libraries."""
    ctx.invoke(
        detect_cmd,
        target=target,
        url=url,
        from_id=from_id,
        waf_only=False,
        tech_only=True,
        insecure=insecure,
    )


# ------------------------------------------------------------------ passive reconnaissance & enum
@cli.command("passive")
@click.argument("target", required=False, default=None)
@click.option("-u", "--url", default=None, help="Target domain or URL")
@click.option(
    "--no-subdomains",
    is_flag=True,
    help="Skip Certificate Transparency subdomain enumeration",
)
@click.option("--no-dns", is_flag=True, help="Skip DNS and email posture queries")
@click.option("--no-sec-txt", is_flag=True, help="Skip security.txt inspection")
@click.option("--no-headers", is_flag=True, help="Skip security headers audit")
@click.option("--save", is_flag=True, help="Save findings to workspace findings.json")
@click.option(
    "--timeout",
    type=float,
    default=8.0,
    help="HTTP/DNS request timeout in seconds",
)
@click.option(
    "--insecure", is_flag=True, default=False, help="Disable TLS verification"
)
@click.pass_context
def passive_cmd(
    ctx,
    target,
    url,
    no_subdomains,
    no_dns,
    no_sec_txt,
    no_headers,
    save,
    timeout,
    insecure,
):
    """Passive reconnaissance: DNS records, SPF/DMARC posture, subdomains, security.txt, and security headers."""
    import asyncio

    from ..passive import run_passive_enum
    from ..render import md_passive

    target_val = target or url
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
            "provide a target domain or URL: 'darco passive <target>' or -u <url>"
        )

    report = asyncio.run(
        run_passive_enum(
            target_val,
            subdomains=not no_subdomains,
            dns=not no_dns,
            security_txt=not no_sec_txt,
            headers=not no_headers,
            timeout=timeout,
            verify=not insecure,
        )
    )

    if save:
        ws = _find_workspace(ctx, auto_create_target=target_val)
        if ws:
            ws.add_findings(report.findings)

    _emit(ctx, to_json(report), md_passive)


@cli.command("enum")
@click.argument("target", required=False, default=None)
@click.option("-u", "--url", default=None, help="Target domain or URL")
@click.option(
    "--no-subdomains",
    is_flag=True,
    help="Skip Certificate Transparency subdomain enumeration",
)
@click.option("--no-dns", is_flag=True, help="Skip DNS and email posture queries")
@click.option("--no-sec-txt", is_flag=True, help="Skip security.txt inspection")
@click.option("--no-headers", is_flag=True, help="Skip security headers audit")
@click.option("--save", is_flag=True, help="Save findings to workspace findings.json")
@click.option("--timeout", type=float, default=8.0)
@click.option("--insecure", is_flag=True, default=False)
@click.pass_context
def enum_cmd(
    ctx,
    target,
    url,
    no_subdomains,
    no_dns,
    no_sec_txt,
    no_headers,
    save,
    timeout,
    insecure,
):
    """Alias for passive reconnaissance & enumeration."""
    ctx.invoke(
        passive_cmd,
        target=target,
        url=url,
        no_subdomains=no_subdomains,
        no_dns=no_dns,
        no_sec_txt=no_sec_txt,
        no_headers=no_headers,
        save=save,
        timeout=timeout,
        insecure=insecure,
    )


@cli.command("info")
@click.argument("target", required=False, default=None)
@click.option("-u", "--url", default=None, help="Target domain or URL")
@click.option("--no-subdomains", is_flag=True)
@click.option("--no-dns", is_flag=True)
@click.option("--no-sec-txt", is_flag=True)
@click.option("--no-headers", is_flag=True)
@click.option("--save", is_flag=True)
@click.option("--timeout", type=float, default=8.0)
@click.option("--insecure", is_flag=True, default=False)
@click.pass_context
def info_cmd(
    ctx,
    target,
    url,
    no_subdomains,
    no_dns,
    no_sec_txt,
    no_headers,
    save,
    timeout,
    insecure,
):
    """Alias for passive target information gathering."""
    ctx.invoke(
        passive_cmd,
        target=target,
        url=url,
        no_subdomains=no_subdomains,
        no_dns=no_dns,
        no_sec_txt=no_sec_txt,
        no_headers=no_headers,
        save=save,
        timeout=timeout,
        insecure=insecure,
    )
