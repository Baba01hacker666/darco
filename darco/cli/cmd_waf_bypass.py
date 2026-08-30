"""WAF bypass technique generator command."""

from __future__ import annotations

import click

from ..errors import DarcoError
from ..render import md_waf_bypass
from ..waf_bypass import build_bypass
from ._group import cli
from ._output import _emit


@cli.command("waf-bypass")
@click.argument("waf", required=False, default=None)
@click.option("--waf", "waf_opt", default=None, help="Detected WAF name (e.g. Cloudflare)")
@click.option("--origin-ip", default=None, help="Origin IP from `darco origin` for Host swap")
@click.pass_context
def waf_bypass_cmd(ctx, waf, waf_opt, origin_ip):
    """Generate tailored WAF-bypass techniques + copy-paste curl repro for a WAF."""
    name = waf or waf_opt
    if not name:
        cfg = (ctx.obj or {}).get("config")
        # fall back to a detection run if a target is configured
        name = None
    result = build_bypass(name, origin_ip)
    _emit(ctx, result, md_waf_bypass)
