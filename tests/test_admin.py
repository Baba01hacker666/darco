import json
import os
import pytest
from click.testing import CliRunner
import httpx

from darco.admin import find_admin_panels, audit_admin_panels, ADMIN_PATHS
from darco.cli import cli
from darco.login import generate_smart_credentials
from darco.models import AdminPanel, AdminPanelReport, LoginForm


class CliResult:
    def __init__(self, returncode: int, stdout: str, stderr: str = ""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def run(args, cwd, json_only=True):
    runner = CliRunner()
    if json_only:
        args = ["--json", *args]
    old_cwd = os.getcwd()
    os.chdir(cwd)
    try:
        res = runner.invoke(cli, args)
        stderr = str(res.exception) if res.exception else getattr(res, "stderr", "")
        return CliResult(res.exit_code, res.stdout, stderr)
    finally:
        os.chdir(old_cwd)


# ------------------------------------------------------------------ smart credentials
def test_generate_smart_credentials_domain_and_emails():
    target = "https://portal.mycompany.org"
    emails = ["alice.smith@mycompany.org", "bob@external.com"]
    creds = generate_smart_credentials(target, emails=emails)

    assert len(creds) > 10
    # Standard admin
    assert ("admin", "admin") in creds
    # Domain admin email
    assert ("admin@portal.mycompany.org", "admin") in creds or ("admin@mycompany.org", "admin") in creds
    # Found email
    assert ("alice.smith@mycompany.org", "password") in creds
    assert ("alice.smith", "alice.smith") in creds
    assert ("alice", "password") in creds
    # Domain-derived password
    assert any("mycompany" in p for u, p in creds)
    # Deduplication check: no duplicate pairs
    assert len(creds) == len(set(creds))


# ------------------------------------------------------------------ admin panel discovery
class MockAdminTransport(httpx.AsyncBaseTransport):
    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        url_str = str(request.url)
        path = request.url.path

        if path in ("/admin", "/admin/"):
            return httpx.Response(
                200,
                headers={"Content-Type": "text/html"},
                text="<html><head><title>Admin Control Panel</title></head><body><h1>Welcome Admin</h1></body></html>",
            )
        elif path in ("/admin/login", "/login/admin"):
            return httpx.Response(
                200,
                headers={"Content-Type": "text/html"},
                text="<html><head><title>Admin Login</title></head><body><form action=\"/admin/login\" method=\"POST\"><input name=\"username\" type=\"text\"><input name=\"password\" type=\"password\"></form></body></html>",
            )
        elif path == "/administrator":
            return httpx.Response(
                302,
                headers={"Location": "/admin/login"},
            )
        elif path == "/cpanel":
            return httpx.Response(401, headers={"WWW-Authenticate": "Basic realm=\"cPanel\""})
        elif path == "/manager/html":
            return httpx.Response(403, text="Forbidden")
        else:
            return httpx.Response(404, text="Not Found")


def test_find_admin_panels_mock():
    async def _run():
        client = httpx.AsyncClient(transport=MockAdminTransport())
        try:
            panels = await find_admin_panels(
                "http://test.local",
                paths=["/admin", "/admin/login", "/administrator", "/cpanel", "/manager/html", "/nonexistent"],
                client=client,
            )
            assert len(panels) == 5

            admin_p = next(p for p in panels if p.path == "/admin")
            assert admin_p.status_code == 200
            assert admin_p.auth_type == "exposed_dashboard"
            assert "Admin Control Panel" in admin_p.title

            login_p = next(p for p in panels if p.path == "/admin/login")
            assert login_p.status_code == 200
            assert login_p.auth_type == "login_form"
            assert login_p.login_form is not None

            cpanel_p = next(p for p in panels if p.path == "/cpanel")
            assert cpanel_p.status_code == 401
            assert cpanel_p.auth_type == "basic_auth"

            redir_p = next(p for p in panels if p.path == "/administrator")
            assert redir_p.status_code == 302
            assert redir_p.auth_type == "portal_redirect"
        finally:
            await client.aclose()

    import asyncio
    asyncio.run(_run())


# ------------------------------------------------------------------ CLI
def test_cli_admin_command(app, tmp_path):
    res = run(["admin", f"{app}/login", "--no-default-creds"], tmp_path)
    assert res.returncode == 0, res.stderr
    data = json.loads(res.stdout)
    assert "target" in data
    assert "panels_found" in data
    assert "scanned_paths" in data


def test_cli_admin_finder_alias(app, tmp_path):
    res = run(["admin-finder", f"{app}/login", "--no-default-creds"], tmp_path)
    assert res.returncode == 0, res.stderr
    data = json.loads(res.stdout)
    assert "panels_found" in data


def test_cli_admin_with_email_flag(app, tmp_path):
    res = run(["admin", f"{app}/login", "--email", "admin@target.local", "--no-default-creds"], tmp_path)
    assert res.returncode == 0, res.stderr
    data = json.loads(res.stdout)
    assert "admin@target.local" in data.get("emails_used", [])
