import json
import os

import httpx
import pytest
from click.testing import CliRunner

from darco.cli import cli
from darco.login import (
    LOGIN_BYPASS_PAYLOADS,
    audit_login_forms,
    find_login_forms,
    is_login_form,
)
from darco.models import Form, FormInput, LoginForm


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


# ------------------------------------------------------------------ form detection
def test_is_login_form_password_input():
    form = Form(
        action="http://app.test/do-login",
        inputs=[
            FormInput(name="username", type="text"),
            FormInput(name="password", type="password"),
        ],
    )
    assert is_login_form(form)


def test_is_login_form_auth_action():
    form = Form(action="http://app.test/signin", inputs=[FormInput(name="user")])
    assert is_login_form(form)


def test_is_login_form_plain_search_is_not():
    form = Form(
        action="http://app.test/search",
        inputs=[FormInput(name="q", type="text")],
    )
    assert not is_login_form(form)


# ------------------------------------------------------------------ finder (integration with fixture)
def test_find_login_forms_fixture(app):
    forms = find_login_forms(f"{app}/login", probe_common_paths=False)
    assert len(forms) == 1
    f = forms[0]
    assert f.username_field == "username"
    assert f.password_field == "password"
    assert f.csrf_field == "csrf"


# ------------------------------------------------------------------ audit
def test_audit_login_forms_no_bypass_fixture(app):
    forms = find_login_forms(f"{app}/login", probe_common_paths=False)
    result = audit_login_forms(forms, target=f"{app}/login")
    assert result.tested_forms >= 1
    assert result.bypasses == []


class FakeResp:
    def __init__(self, status=200, text="", headers=None, cookie_names=()):
        self.status_code = status
        self.text = text
        self.headers = headers or {}
        self.url = "http://fake/"
        cookies = httpx.Cookies()
        for name in cookie_names:
            cookies.set(name, "x")
        self.cookies = cookies


class FakeLoginClient:
    """Simulates an app where username payloads starting with a quote log you in."""

    def __init__(self, success_field="username"):
        self._field = success_field

    def get(self, url, headers=None):
        if "login" in url:
            return FakeResp(
                200,
                '<form method="POST" action="http://fake/login">'
                '<input type="hidden" name="csrf" value="tok">'
                '<input name="username">'
                '<input name="password" type="password"></form>',
            )
        return FakeResp(404, "not found")

    def post(self, url, data=None, headers=None):
        value = data.get(self._field, "")
        if value.startswith("'"):
            return FakeResp(
                302,
                "",
                headers={"location": "/my-account"},
                cookie_names=["session"],
            )
        return FakeResp(401, "Invalid username or password")

    def close(self):
        pass


def _fake_form():
    return LoginForm(
        url="http://fake/login",
        action="http://fake/login",
        method="POST",
        username_field="username",
        password_field="password",
        csrf_field="csrf",
    )


def test_audit_login_bypass_redirect_detected():
    result = audit_login_forms(
        [_fake_form()],
        target="http://fake/login",
        client_factory=lambda t, v: FakeLoginClient(success_field="username"),
    )
    assert result.tested_forms == 1
    assert len(result.bypasses) >= 1
    b = result.bypasses[0]
    assert b.param == "username"
    assert b.confidence == "high"
    assert b.success_indicator == "redirect_to_account"
    assert any(p.startswith("'") for p in LOGIN_BYPASS_PAYLOADS)


def test_audit_login_bypass_password_field_when_enabled():
    result = audit_login_forms(
        [_fake_form()],
        target="http://fake/login",
        test_password_field=True,
        client_factory=lambda t, v: FakeLoginClient(success_field="password"),
    )
    assert len(result.bypasses) >= 1
    assert all(b.param == "password" for b in result.bypasses)


class FakeLandingClient(FakeLoginClient):
    """Payload redirects to /my-account, which serves a logged-in page."""

    def get(self, url, headers=None):
        if "my-account" in url:
            return FakeResp(200, "Welcome back! <a>Logout</a>")
        return super().get(url, headers=headers)


def test_audit_login_bypass_keyword_match_on_landing_page():
    result = audit_login_forms(
        [_fake_form()],
        target="http://fake/login",
        client_factory=lambda t, v: FakeLandingClient(success_field="username"),
    )
    assert len(result.bypasses) >= 1
    b = result.bypasses[0]
    assert b.success_indicator == "redirect_to_account"
    assert "logout" in b.evidence
    assert "welcome" in b.evidence


class FakeKeywordClient(FakeLoginClient):
    """Payload succeeds with a 200 page that contains logged-in keywords."""

    def post(self, url, data=None, headers=None):
        value = data.get(self._field, "")
        if value.startswith("'"):
            return FakeResp(200, "Welcome back! <a>Logout</a>")
        return FakeResp(401, "Invalid username or password")


def test_audit_login_bypass_keyword_content_no_redirect():
    result = audit_login_forms(
        [_fake_form()],
        target="http://fake/login",
        client_factory=lambda t, v: FakeKeywordClient(success_field="username"),
    )
    assert len(result.bypasses) >= 1
    b = result.bypasses[0]
    assert b.success_indicator == "authenticated_content"
    assert "welcome" in b.evidence


class FakeDefaultCredClient:
    """Accepts admin:admin default credentials."""

    def get(self, url, headers=None, params=None):
        if params and params.get("username") == "admin" and params.get("password") == "admin":
            return FakeResp(302, "", headers={"location": "/dashboard"})
        return FakeResp(200, '<form method="GET" action="http://fake/login"><input name="username"><input name="password" type="password"></form>')

    def post(self, url, data=None, headers=None):
        u = data.get("username", "") if data else ""
        p = data.get("password", "") if data else ""
        if u == "admin" and p == "admin":
            return FakeResp(302, "", headers={"location": "/dashboard"})
        return FakeResp(401, "Invalid credentials")

    def close(self):
        pass


def test_audit_login_default_credentials():
    result = audit_login_forms(
        [_fake_form()],
        target="http://fake/login",
        test_default_creds=True,
        client_factory=lambda t, v: FakeDefaultCredClient(),
    )
    assert result.tested_forms == 1
    assert any(b.param == "credentials" and b.payload == "admin:admin" for b in result.bypasses)
    cred_finding = next(b for b in result.bypasses if b.payload == "admin:admin")
    assert cred_finding.confidence == "confirmed"
    assert "Default credentials accepted" in cred_finding.evidence


def test_audit_login_get_method():
    get_form = LoginForm(
        url="http://fake/login",
        action="http://fake/login",
        method="GET",
        username_field="username",
        password_field="password",
    )
    result = audit_login_forms(
        [get_form],
        target="http://fake/login",
        test_default_creds=True,
        client_factory=lambda t, v: FakeDefaultCredClient(),
    )
    assert any(b.payload == "admin:admin" for b in result.bypasses)


# ------------------------------------------------------------------ CLI
def test_cli_login_command_fixture(app, tmp_path):
    res = run(["login", f"{app}/login"], tmp_path)
    assert res.returncode == 0, res.stderr
    data = json.loads(res.stdout)
    assert data["target"] == f"{app}/login"
    assert len(data["forms_found"]) >= 1
    assert data["tested_forms"] >= 1
    assert data["bypasses"] == []


def test_cli_login_find_only(app, tmp_path):
    res = run(["login", f"{app}/login", "--find-only"], tmp_path)
    assert res.returncode == 0, res.stderr
    data = json.loads(res.stdout)
    assert len(data["forms_found"]) >= 1
    assert data["tested_forms"] >= 1


def test_cli_auth_alias(app, tmp_path):
    res = run(["auth", f"{app}/login", "--find-only"], tmp_path)
    assert res.returncode == 0, res.stderr
    data = json.loads(res.stdout)
    assert "forms_found" in data
