"""Record-only forward proxy command."""

from __future__ import annotations

import json
import time

import click

from ._group import cli
from ._context import _find_workspace




# ------------------------------------------------------------------ proxy
@cli.command("proxy")
@click.option("--port", type=int, default=8080)
@click.option("--listen", default="127.0.0.1")
@click.option(
    "--record-only", is_flag=True, default=True, help="Record flows only (v1 mode)"
)
@click.option(
    "--bypass", is_flag=True, default=False,
    help="Inject WAF-bypass transforms on every forwarded request "
         "(so sqlmap/nuclei routed through darco evade the shield)",
)
@click.option(
    "--origin-ip", default=None,
    help="Origin IP to use for Host-header swap bypass (from `darco origin`)",
)
@click.option(
    "--techniques", default=None,
    help="Comma list of bypass technique ids to apply "
         "(header_case,path_normalize,encoding,http1_0,x_original_url,"
         "content_type,cookie_pad,host_swap)",
)
@click.pass_context
def proxy_cmd(ctx, port, listen, record_only, bypass, origin_ip, techniques):
    from ..proxy import ProxyServer

    ws = _find_workspace(ctx)
    session = ws.load_session()
    tech_list = (
        [t.strip() for t in techniques.split(",") if t.strip()]
        if techniques else None
    )
    server = ProxyServer(
        ws, session, host=listen, port=port,
        base_headers=ws.load_config().base_headers,
        bypass=bypass, bypass_techniques=tech_list, origin_ip=origin_ip,
    )
    bound = server.start()
    click.echo(
        json.dumps(
            {
                "status": "listening",
                "host": listen,
                "port": bound,
                "mode": "waf-bypass" if bypass else "record-only",
                "origin_ip": origin_ip,
            }
        )
    )
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()
