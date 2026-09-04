"""Root click group, custom Group class, and main() entrypoint."""

from __future__ import annotations

import os
import sys

import click

from ..configfile import load as load_config
from ..errors import DarcoError
from ._output import DEFAULT_FMT


class DarcoCLI(click.Group):
    """Custom Click Group that allows running URLs and history IDs directly (e.g. `darco https://target.com`)."""

    def resolve_command(self, ctx, args):
        cmd_name = args[0] if args else None
        if (
            cmd_name
            and cmd_name not in self.commands
            and not cmd_name.startswith("-")
            and (
                cmd_name.isdigit()
                or cmd_name.startswith(("http://", "https://", "localhost"))
                or "." in cmd_name
                or "/" in cmd_name
            )
        ):
            return "send", self.get_command(ctx, "send"), args
        return super().resolve_command(ctx, args)


# ------------------------------------------------------------------ root
@click.group(cls=DarcoCLI, invoke_without_command=True)
@click.option(
    "-u", "--url", "url", default=None, help="Target URL to send/inspect directly"
)
@click.option("-X", "--method", default=None, help="HTTP method (GET, POST, etc.)")
@click.option("-d", "--data", default=None, help="Request body (prefix @file to read)")
@click.option("-H", "--header", "cli_header", multiple=True, help="Header NAME:VALUE")
@click.option("-F", "--form", "cli_form", multiple=True, help="Form field NAME=VALUE")
@click.option(
    "--workspace",
    "-w",
    type=click.Path(),
    default=None,
    help="Workspace dir (auto-detected if omitted)",
)
@click.option(
    "--config",
    "config_path",
    default=None,
    help="Config file (darco.toml / darco.json); auto-discovered if omitted",
)
@click.option(
    "--format",
    "format",
    type=click.Choice(["json", "md", "table"]),
    default=DEFAULT_FMT,
    help="Output format (default: md)",
)
@click.option(
    "-J",
    "--json",
    "as_json",
    is_flag=True,
    help="Shorthand for --format json (agent contract)",
)
@click.option("--fuzz", "do_fuzz", is_flag=True, help="Auto-fuzz the target request")
@click.option("--raw", is_flag=True, help="Print raw HTTP response")
@click.option(
    "--proxy",
    "proxy",
    default=None,
    help="HTTP proxy URL (e.g. http://127.0.0.1:8080). Also uses HTTP_PROXY/HTTPS_PROXY env vars.",
)
@click.pass_context
def cli(
    ctx,
    url,
    method,
    data,
    cli_header,
    cli_form,
    workspace,
    config_path,
    format,
    as_json,
    do_fuzz,
    raw,
    proxy,
):
    ctx.ensure_object(dict)
    ctx.obj["workspace_path"] = workspace
    ctx.obj["format"] = "json" if as_json else format
    # Proxy: CLI flag wins, then env var
    if not proxy:
        proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("HTTP_PROXY") or os.environ.get("https_proxy") or os.environ.get("http_proxy")
    ctx.obj["proxy"] = proxy
    cfg = load_config(config_path)
    # config file wins on defaults but CLI flags still override per-command
    if as_json is False and format == DEFAULT_FMT and cfg.format != DEFAULT_FMT:
        ctx.obj["format"] = cfg.format
    ctx.obj["config"] = cfg

    if ctx.invoked_subcommand is None:
        if url:
            from .cmd_send import send_cmd  # lazy: avoids import cycle

            ctx.invoke(
                send_cmd,
                target=url,
                method=method,
                data=data,
                cli_header=cli_header,
                cli_form=cli_form,
                do_fuzz=do_fuzz,
                raw=raw,
            )
        else:
            click.echo(ctx.get_help())


def main() -> None:
    try:
        cli(standalone_mode=False)
    except DarcoError as exc:
        click.echo(f"error: {exc}", err=True)
        sys.exit(1)
    except click.ClickException as exc:
        click.echo(f"error: {exc.format_message()}", err=True)
        sys.exit(exc.exit_code)
