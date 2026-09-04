"""Crawling commands: discover, crawl, scan, auto."""
from __future__ import annotations

import asyncio

import click

from ..errors import DarcoError
from ..models import to_json
from ..workspace import Workspace
from ._context import _find_workspace
from ._group import cli
from ._output import _emit


# ------------------------------------------------------------------ discover / crawl / auto-scan
@cli.command("discover")
@click.argument("url_arg", required=False, default=None)
@click.option(
    "-u", "--url", "url_opt", default=None, help="Target URL to discover/crawl"
)
@click.option("--depth", type=int, default=3)
@click.option("--max-urls", type=int, default=500)
@click.option("--workers", type=int, default=5)
@click.option("--seed", "seed_files", multiple=True, type=click.Path(exists=True))
@click.option("--no-js", is_flag=True)
@click.option("--no-fuzz", is_flag=True, help="Disable parameter mutation fuzzing")
@click.option("--no-sqli", is_flag=True, help="Disable SQL injection testing")
@click.option("--no-xss", is_flag=True, help="Disable XSS reflection testing")
@click.option("--no-upload", is_flag=True, help="Disable file upload security auditing")
@click.option("--no-redirect", is_flag=True, help="Disable open redirect auditing")
@click.option("--no-traversal", is_flag=True, help="Disable path traversal auditing")
@click.option("--no-stored-xss", is_flag=True, help="Disable stored XSS auditing")
@click.option(
    "--include-state",
    is_flag=True,
    default=False,
    help="Also audit framework state fields (__VIEWSTATE, CSRF tokens, etc.)",
)
@click.option(
    "--default-creds/--no-default-creds",
    "default_creds",
    default=True,
    help="Auto-audit login forms for common default credentials",
)
@click.option(
    "--plugin", "plugins", multiple=True, help="Enable only these scan plugins"
)
@click.option("--skip-plugin", "skip_plugins", multiple=True, help="Skip these scan plugins")
@click.option("--insecure", is_flag=True)
@click.option("--timeout", type=float, default=10.0)
@click.pass_context
def discover_cmd(
    ctx,
    url_arg,
    url_opt,
    depth,
    max_urls,
    workers,
    seed_files,
    no_js,
    no_fuzz,
    no_sqli,
    no_xss,
    no_upload,
    no_redirect,
    no_traversal,
    no_stored_xss,
    include_state,
    default_creds,
    plugins,
    skip_plugins,
    insecure,
    timeout,
):
    """Discover site architecture, endpoints, forms, JS files, and security signals."""
    from ..render import md_scan
    from ..scanner import run_auto_scan

    url = url_opt or url_arg
    if not url:
        raise DarcoError(
            "provide a target URL: 'darco discover <url>' or 'darco discover -u <url>'"
        )
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    ws = _find_workspace(ctx, require=False, auto_create_target=url)
    if ws is None:
        ws = Workspace.create(url)

    cfg = ws.load_config()
    proxy = (ctx.obj or {}).get("proxy")

    # Smart default: run full scan unless explicitly disabled
    report = asyncio.run(
        run_auto_scan(
            ws,
            url,
            depth=depth,
            max_urls=max_urls,
            workers=workers,
            parse_js=not no_js,
            fuzz=not no_fuzz,
            sqli=not no_sqli,
            xss=not no_xss,
            upload=not no_upload,
            redirect=not no_redirect,
            traversal=not no_traversal,
            stored_xss=not no_stored_xss,
            default_creds=default_creds,
            include_state_fields=include_state,
            timeout=timeout,
            verify=not (cfg.insecure or insecure),
            plugins=list(plugins) if plugins else None,
            skip_plugins=list(skip_plugins) if skip_plugins else None,
            proxy=proxy,
        )
    )
    _emit(ctx, to_json(report), md_scan)


@cli.command("crawl")
@click.argument("url_arg", required=False, default=None)
@click.option("-u", "--url", "url_opt", default=None, help="Target URL to crawl")
@click.option("--depth", type=int, default=3)
@click.option("--max-urls", type=int, default=500)
@click.option("--workers", type=int, default=5)
@click.option("--seed", "seed_files", multiple=True, type=click.Path(exists=True))
@click.option("--no-js", is_flag=True)
@click.option("--no-fuzz", is_flag=True, help="Disable parameter mutation fuzzing")
@click.option("--no-sqli", is_flag=True, help="Disable SQL injection testing")
@click.option("--no-xss", is_flag=True, help="Disable XSS reflection testing")
@click.option("--no-upload", is_flag=True, help="Disable file upload security auditing")
@click.option("--no-redirect", is_flag=True, help="Disable open redirect auditing")
@click.option("--no-traversal", is_flag=True, help="Disable path traversal auditing")
@click.option("--no-stored-xss", is_flag=True, help="Disable stored XSS auditing")
@click.option(
    "--include-state",
    is_flag=True,
    default=False,
    help="Also audit framework state fields (__VIEWSTATE, CSRF tokens, etc.)",
)
@click.option(
    "--default-creds/--no-default-creds",
    "default_creds",
    default=True,
    help="Auto-audit login forms for common default credentials",
)
@click.option(
    "--plugin", "plugins", multiple=True, help="Enable only these scan plugins"
)
@click.option("--skip-plugin", "skip_plugins", multiple=True, help="Skip these scan plugins")
@click.option("--insecure", is_flag=True)
@click.option("--timeout", type=float, default=10.0)
@click.pass_context
def crawl_cmd(
    ctx,
    url_arg,
    url_opt,
    depth,
    max_urls,
    workers,
    seed_files,
    no_js,
    no_fuzz,
    no_sqli,
    no_xss,
    no_upload,
    no_redirect,
    no_traversal,
    no_stored_xss,
    include_state,
    default_creds,
    plugins,
    skip_plugins,
    insecure,
    timeout,
):
    """Crawl a target website and extract endpoints, forms, and JavaScript references."""
    ctx.invoke(
        discover_cmd,
        url_arg=url_arg,
        url_opt=url_opt,
        depth=depth,
        max_urls=max_urls,
        workers=workers,
        seed_files=seed_files,
        no_js=no_js,
        no_fuzz=no_fuzz,
        no_sqli=no_sqli,
        no_xss=no_xss,
        no_upload=no_upload,
        no_redirect=no_redirect,
        no_traversal=no_traversal,
        no_stored_xss=no_stored_xss,
        include_state=include_state,
        default_creds=default_creds,
        plugins=plugins,
        skip_plugins=skip_plugins,
        insecure=insecure,
        timeout=timeout,
    )


@cli.command("scan")
@click.argument("url_arg", required=False, default=None)
@click.option("-u", "--url", "url_opt", default=None, help="Target URL to auto-scan")
@click.option("--depth", type=int, default=3)
@click.option("--max-urls", type=int, default=200)
@click.option("--workers", type=int, default=5)
@click.option("--no-fuzz", is_flag=True, help="Disable parameter mutation fuzzing")
@click.option("--no-sqli", is_flag=True, help="Disable SQL injection testing")
@click.option("--no-xss", is_flag=True, help="Disable XSS reflection testing")
@click.option("--no-upload", is_flag=True, help="Disable file upload security auditing")
@click.option("--no-redirect", is_flag=True, help="Disable open redirect auditing")
@click.option("--no-traversal", is_flag=True, help="Disable path traversal auditing")
@click.option("--no-stored-xss", is_flag=True, help="Disable stored XSS auditing")
@click.option(
    "--no-default-creds", is_flag=True, help="Disable default credentials testing"
)
@click.option("--no-js", is_flag=True)
@click.option(
    "--include-state",
    is_flag=True,
    default=False,
    help="Also audit framework state fields (__VIEWSTATE, CSRF tokens, etc.)",
)
@click.option(
    "--plugin", "plugins", multiple=True, help="Enable only these scan plugins"
)
@click.option("--skip-plugin", "skip_plugins", multiple=True, help="Skip these scan plugins")
@click.option("--insecure", is_flag=True)
@click.option("--timeout", type=float, default=10.0)
@click.pass_context
def scan_cmd(
    ctx,
    url_arg,
    url_opt,
    depth,
    max_urls,
    workers,
    no_fuzz,
    no_sqli,
    no_xss,
    no_upload,
    no_redirect,
    no_traversal,
    no_stored_xss,
    no_default_creds,
    no_js,
    include_state,
    plugins,
    skip_plugins,
    insecure,
    timeout,
):
    """All-in-one automated pipeline: crawl target, detect WAF/tech, and auto-fuzz/audit for SQLi, XSS, file uploads, and default credentials."""
    ctx.invoke(
        discover_cmd,
        url_arg=url_arg,
        url_opt=url_opt,
        depth=depth,
        max_urls=max_urls,
        workers=workers,
        seed_files=(),
        no_js=no_js,
        no_fuzz=no_fuzz,
        no_sqli=no_sqli,
        no_xss=no_xss,
        no_upload=no_upload,
        no_redirect=no_redirect,
        no_traversal=no_traversal,
        no_stored_xss=no_stored_xss,
        include_state=include_state,
        default_creds=not no_default_creds,
        plugins=plugins,
        skip_plugins=skip_plugins,
        insecure=insecure,
        timeout=timeout,
    )


@cli.command("auto")
@click.argument("url_arg", required=False, default=None)
@click.option("-u", "--url", "url_opt", default=None, help="Target URL to auto-scan")
@click.option("--depth", type=int, default=3)
@click.option("--max-urls", type=int, default=200)
@click.option("--workers", type=int, default=5)
@click.option("--no-fuzz", is_flag=True)
@click.option("--no-sqli", is_flag=True)
@click.option("--no-xss", is_flag=True)
@click.option("--no-upload", is_flag=True)
@click.option("--no-redirect", is_flag=True)
@click.option("--no-traversal", is_flag=True)
@click.option("--no-stored-xss", is_flag=True)
@click.option("--no-default-creds", is_flag=True)
@click.option("--no-js", is_flag=True)
@click.option(
    "--include-state",
    is_flag=True,
    default=False,
    help="Also audit framework state fields (__VIEWSTATE, CSRF tokens, etc.)",
)
@click.option(
    "--plugin", "plugins", multiple=True, help="Enable only these scan plugins"
)
@click.option("--skip-plugin", "skip_plugins", multiple=True, help="Skip these scan plugins")
@click.option("--insecure", is_flag=True)
@click.option("--timeout", type=float, default=10.0)
@click.pass_context
def auto_cmd(
    ctx,
    url_arg,
    url_opt,
    depth,
    max_urls,
    workers,
    no_fuzz,
    no_sqli,
    no_xss,
    no_upload,
    no_redirect,
    no_traversal,
    no_stored_xss,
    no_default_creds,
    no_js,
    include_state,
    plugins,
    skip_plugins,
    insecure,
    timeout,
):
    """Alias for automated crawl and security scan."""
    ctx.invoke(
        scan_cmd,
        url_arg=url_arg,
        url_opt=url_opt,
        depth=depth,
        max_urls=max_urls,
        workers=workers,
        no_fuzz=no_fuzz,
        no_sqli=no_sqli,
        no_xss=no_xss,
        no_upload=no_upload,
        no_redirect=no_redirect,
        no_traversal=no_traversal,
        no_stored_xss=no_stored_xss,
        no_default_creds=no_default_creds,
        no_js=no_js,
        include_state=include_state,
        plugins=plugins,
        skip_plugins=skip_plugins,
        insecure=insecure,
        timeout=timeout,
    )
