"""Auth surface commands: login/auth bypass, admin finder, upload audit."""

from __future__ import annotations

import click

from ..errors import DarcoError
from ..models import to_json
from ._context import _find_workspace, _one_shot_session
from ._group import cli
from ._output import _emit


# ------------------------------------------------------------------ login finder & SQLi bypass audit
@cli.command("login")
@click.argument("target", required=False, default=None)
@click.option("-u", "--url", default=None, help="Target login page or site root")
@click.option(
    "--find-only",
    is_flag=True,
    help="Only find login forms — skip the SQLi bypass audit",
)
@click.option(
    "--username", "user_field", default=None, help="Force username field name"
)
@click.option(
    "--password", "pass_field", default=None, help="Force password field name"
)
@click.option(
    "--payload",
    "extra_payloads",
    multiple=True,
    help="Extra login-bypass payload to try (repeatable)",
)
@click.option(
    "--test-password",
    is_flag=True,
    help="Also probe the password field with bypass payloads",
)
@click.option(
    "--default-creds/--no-default-creds",
    default=True,
    help="Probe forms with smart credentials (admin:admin, admin@domain.com, etc.)",
)
@click.option(
    "--email",
    "emails",
    multiple=True,
    help="Target email address to test in smart credentials (repeatable)",
)
@click.option("--save", is_flag=True, help="Save findings to workspace findings.json")
@click.option(
    "--insecure", is_flag=True, default=False, help="Disable TLS verification"
)
@click.option("--timeout", type=float, default=10.0)
@click.pass_context
def login_cmd(
    ctx,
    target,
    url,
    find_only,
    user_field,
    pass_field,
    extra_payloads,
    test_password,
    default_creds,
    emails,
    save,
    insecure,
    timeout,
):
    """Find login forms and test them for SQL authentication-bypass and smart credentials."""
    from ..login import LOGIN_BYPASS_PAYLOADS, audit_login_forms, find_login_forms
    from ..models import Finding
    from ..render import md_login

    target_val = url or target
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
            "provide a target URL: 'darco login <url>' or 'darco login -u <url>'"
        )
    if not target_val.startswith(("http://", "https://")):
        target_val = "http://" + target_val

    forms = find_login_forms(
        target_val,
        timeout=timeout,
        verify=not insecure,
    )
    payloads = tuple(extra_payloads) or LOGIN_BYPASS_PAYLOADS
    result = audit_login_forms(
        forms,
        target=target_val,
        payloads=payloads,
        test_default_creds=default_creds,
        emails=emails,
        timeout=timeout,
        verify=not insecure,
        test_password_field=test_password,
        username_override=user_field,
        password_override=pass_field,
    )

    if save and result.bypasses:
        ws = _find_workspace(ctx, auto_create_target=target_val)
        findings = []
        for b in result.bypasses:
            is_cred = b.param == "credentials" and ":" in b.payload
            ftype = "default_credentials" if is_cred else "login_sqli_bypass"
            findings.append(
                Finding(
                    id=f"login-{ftype}-{b.payload[:16]}",
                    type=ftype,
                    severity="high"
                    if b.confidence in ("confirmed", "high")
                    else "medium",
                    location=f"{result.target} ({b.param})",
                    evidence=b.evidence,
                    suggestion=b.suggestion,
                )
            )
        ws.add_findings(findings)

    _emit(ctx, to_json(result), md_login)


@cli.command("auth")
@click.argument("target", required=False, default=None)
@click.option("-u", "--url", default=None, help="Target login page or site root")
@click.option("--find-only", is_flag=True)
@click.option("--username", "user_field", default=None)
@click.option("--password", "pass_field", default=None)
@click.option("--payload", "extra_payloads", multiple=True)
@click.option("--test-password", is_flag=True)
@click.option(
    "--default-creds/--no-default-creds",
    default=True,
    help="Probe forms with common default credentials",
)
@click.option("--email", "emails", multiple=True, help="Target email address to test")
@click.option("--save", is_flag=True)
@click.option("--insecure", is_flag=True, default=False)
@click.option("--timeout", type=float, default=10.0)
@click.pass_context
def auth_cmd(
    ctx,
    target,
    url,
    find_only,
    user_field,
    pass_field,
    extra_payloads,
    test_password,
    default_creds,
    emails,
    save,
    insecure,
    timeout,
):
    """Alias for the login form finder + SQLi bypass / default credentials audit."""
    ctx.invoke(
        login_cmd,
        target=target,
        url=url,
        find_only=find_only,
        user_field=user_field,
        pass_field=pass_field,
        extra_payloads=extra_payloads,
        test_password=test_password,
        default_creds=default_creds,
        emails=emails,
        save=save,
        insecure=insecure,
        timeout=timeout,
    )


# ------------------------------------------------------------------ admin panel discovery
@cli.command("admin")
@click.argument("target", required=False, default=None)
@click.option("-u", "--url", default=None, help="Target URL or root domain")
@click.option(
    "--default-creds/--no-default-creds",
    default=True,
    help="Probe discovered admin login forms with smart credentials and domain emails",
)
@click.option(
    "--email",
    "emails",
    multiple=True,
    help="Target email address to test in smart credentials (repeatable)",
)
@click.option("--paths", default=None, help="Comma-separated custom paths to probe")
@click.option("--workers", type=int, default=10, help="Concurrent probe workers")
@click.option("--save", is_flag=True, help="Save findings to workspace findings.json")
@click.option(
    "--insecure", is_flag=True, default=False, help="Disable TLS verification"
)
@click.option("--timeout", type=float, default=8.0)
@click.pass_context
def admin_cmd(
    ctx,
    target,
    url,
    paths,
    default_creds,
    emails,
    workers,
    save,
    insecure,
    timeout,
):
    """Probe target for administrative panels, backend portals, and management consoles."""
    from ..admin import audit_admin_panels_sync
    from ..render import md_admin

    target_val = url or target
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
            "provide a target URL: 'darco admin <url>' or 'darco admin -u <url>'"
        )
    if not target_val.startswith(("http://", "https://")):
        target_val = "http://" + target_val

    combined_emails = list(emails)
    if not combined_emails:
        ws = _find_workspace(ctx, require=False)
        if ws:
            try:
                sitemap = ws.load_sitemap()
                if sitemap and sitemap.emails:
                    combined_emails.extend(sitemap.emails)
            except (DarcoError, OSError, ValueError):
                pass

    custom_paths = [p.strip() for p in paths.split(",") if p.strip()] if paths else None

    report = audit_admin_panels_sync(
        target_val,
        emails=combined_emails,
        test_creds=default_creds,
        timeout=timeout,
        verify=not insecure,
        workers=workers,
        paths=custom_paths,
    )

    if save and report.findings:
        ws = _find_workspace(ctx, auto_create_target=target_val)
        ws.add_findings(report.findings)

    _emit(ctx, to_json(report), md_admin)


@cli.command("admin-finder")
@click.argument("target", required=False, default=None)
@click.option("-u", "--url", default=None, help="Target URL or root domain")
@click.option("--paths", default=None, help="Comma-separated custom paths to probe")
@click.option(
    "--default-creds/--no-default-creds",
    default=True,
    help="Probe discovered admin login forms with smart credentials",
)
@click.option(
    "--email",
    "emails",
    multiple=True,
    help="Target email address to test in credentials",
)
@click.option("--workers", type=int, default=10)
@click.option("--save", is_flag=True)
@click.option("--insecure", is_flag=True, default=False)
@click.option("--timeout", type=float, default=8.0)
@click.pass_context
def admin_finder_cmd(
    ctx,
    target,
    url,
    paths,
    default_creds,
    emails,
    workers,
    save,
    insecure,
    timeout,
):
    """Alias for administrative panel and management console discovery."""
    ctx.invoke(
        admin_cmd,
        target=target,
        url=url,
        paths=paths,
        default_creds=default_creds,
        emails=emails,
        workers=workers,
        save=save,
        insecure=insecure,
        timeout=timeout,
    )


# ------------------------------------------------------------------ file upload audit
@cli.command("upload")
@click.argument("target", required=False, default=None)
@click.option(
    "-u",
    "--url",
    default=None,
    help="Target upload URL (e.g. http://example.com/api/upload)",
)
@click.option("--from", "from_id", default=None, help="Stored record ID to audit")
@click.option(
    "-p",
    "--param",
    "file_field",
    default=None,
    help="File input field name (e.g. file, avatar, upload)",
)
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
@click.option("--save", is_flag=True, help="Save findings to workspace findings.json")
@click.option(
    "--insecure", is_flag=True, default=False, help="Disable TLS verification"
)
@click.pass_context
def upload_cmd(ctx, target, url, from_id, file_field, headers, cookies, save, insecure):
    """File upload security audit: tests SVG (XSS vector), HTML, MIME bypass, and storage security."""
    from ..models import Cookie, Finding, NameValue, Request
    from ..render import md_upload
    from ..upload import audit_file_upload

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
                "provide a target upload URL: 'darco upload <url>' or -u <url> or --from <id>"
            )
        if not url.startswith(("http://", "https://")):
            url = "http://" + url

        base_req = Request(
            method="POST",
            url=url,
            verify=not insecure,
            source="oneshot",
        )
        ws = _find_workspace(ctx, require=False)
        session = ws.load_session() if ws else _one_shot_session()

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

    result = audit_file_upload(base_req, session=session, file_field=file_field)

    if save:
        ws = ws or _find_workspace(ctx, auto_create_target=base_req.url)
        if ws:
            findings = []
            for f in result.findings:
                findings.append(
                    Finding(
                        id=f"upload-{f.param}-{f.vulnerability_type}",
                        type=f"upload_{f.vulnerability_type}",
                        severity=(
                            "high"
                            if f.confidence in ("confirmed", "high")
                            else "medium"
                        ),
                        location=f"{base_req.method} {base_req.url} ({f.param})",
                        evidence=f.evidence,
                        suggestion=f.suggestion,
                    )
                )
            ws.add_findings(findings)

    _emit(ctx, to_json(result), md_upload)
