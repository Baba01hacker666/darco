"""Deep transport probe command: HTTP/2, request smuggling, JA3/TLS fingerprint."""

from __future__ import annotations

import click

from ..errors import DarcoError
from ..render import md_transport
from ..transport import (
    ja3_fingerprint,
    probe_http2,
    probe_smuggling,
    run_transport_scan,
)
from ._group import cli
from ._output import _emit


@cli.command("transport")
@click.argument("target", required=False, default=None)
@click.option("-u", "--url", default=None, help="Target URL (https:// for TLS probes)")
@click.option("--http2", "only_h2", is_flag=True, help="Only probe HTTP/2 support")
@click.option("--smuggle", "only_smuggle", is_flag=True, help="Only probe request smuggling")
@click.option("--ja3", "only_ja3", is_flag=True, help="Only run TLS/JA3 fingerprint")
@click.pass_context
def transport_cmd(ctx, target, url, only_h2, only_smuggle, only_ja3):
    """Deep protocol-layer probe: HTTP/2 negotiation, request-smuggling desync, and a real TLS/JA3 fingerprint."""
    if target:
        url = url or target
    if not url:
        cfg = (ctx.obj or {}).get("config")
        if cfg and cfg.target:
            url = cfg.target
    if not url:
        raise DarcoError("provide a target: `darco transport <url>` or -u <url>")

    if only_h2:
        result = {"target": url, "http2": probe_http2(url), "smuggling": {}, "tls": {}}
    elif only_smuggle:
        result = {"target": url, "http2": {}, "smuggling": probe_smuggling(url), "tls": {}}
    elif only_ja3:
        result = {"target": url, "http2": {}, "smuggling": {}, "tls": ja3_fingerprint(url)}
    else:
        result = run_transport_scan(url)

    _emit(ctx, result, md_transport)
