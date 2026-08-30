"""Origin-IP discovery + DNS history command."""

from __future__ import annotations

import click

from ..errors import DarcoError
from ..origin import find_origin
from ..render import md_origin
from ._group import cli
from ._output import _emit


@cli.command("origin")
@click.argument("domain", required=False, default=None)
@click.option("-d", "--domain", "domain_opt", default=None, help="Target domain")
@click.option("--no-subenum", is_flag=True, help="Skip wordlist subdomain enumeration")
@click.option("--no-history", is_flag=True, help="Skip DNS history lookup")
@click.pass_context
def origin_cmd(ctx, domain, domain_opt, no_subenum, no_history):
    """Find the real origin IP behind a CDN/WAF: subdomain enum, DNS history, CNAME-chain follow."""
    target = domain or domain_opt
    if not target:
        cfg = (ctx.obj or {}).get("config")
        if cfg and cfg.target:
            target = cfg.target
    if not target:
        raise DarcoError("provide a domain: `darco origin <domain>` or -d <domain>")

    report = find_origin(
        target,
        enum_subdomains=not no_subenum,
        use_history=not no_history,
    )
    _emit(ctx, report.to_dict(), md_origin)
