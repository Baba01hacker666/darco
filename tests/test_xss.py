import json
import os

from click.testing import CliRunner

from darco.cli import cli
from darco.models import BodyType, NameValue, Request, Response
from darco.xss import scan_xss


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


# ------------------------------------------------------------------ Unit Tests for XSS Reflection
def test_xss_html_body_unencoded(monkeypatch):
    req = Request(
        method="GET",
        url="http://app.test/search",
        params=[NameValue(name="q", value="hello")],
    )

    def mock_send(r, session):
        val = next((p.value for p in r.params if p.name == "q"), "")
        # Raw unencoded reflection in body
        return Response(
            status_code=200,
            body=f"<html><body><h1>Results for {val}</h1></body></html>",
            body_len=100,
        )

    monkeypatch.setattr("darco.xss._send", mock_send)

    result = scan_xss(req)
    assert len(result.reflections) >= 1
    r = result.reflections[0]
    assert r.param == "q"
    assert r.context == "html_body"
    assert "<" in r.unencoded_chars
    assert ">" in r.unencoded_chars
    assert r.confidence == "confirmed"


def test_xss_skips_framework_state_fields_by_default(monkeypatch):
    req = Request(
        method="POST",
        url="http://app.test/login",
        headers=[
            NameValue(
                name="Content-Type", value="application/x-www-form-urlencoded"
            )
        ],
        body_type=BodyType.FORM,
        body_form=[
            NameValue(name="__VIEWSTATE", value="abc"),
            NameValue(name="q", value="hello"),
        ],
    )

    def mock_send(r, session):
        val = next((p.value for p in r.body_form if p.name == "q"), "")
        return Response(
            status_code=200,
            body=f"<html><body>Results for {val}</body></html>",
            body_len=100,
        )

    monkeypatch.setattr("darco.xss._send", mock_send)
    result = scan_xss(req)
    assert "__VIEWSTATE" not in result.tested_params
    assert "q" in result.tested_params
    assert all(r.param == "q" for r in result.reflections)


def test_xss_include_framework_state_fields(monkeypatch):
    req = Request(
        method="POST",
        url="http://app.test/login",
        headers=[
            NameValue(
                name="Content-Type", value="application/x-www-form-urlencoded"
            )
        ],
        body_type=BodyType.FORM,
        body_form=[
            NameValue(name="__VIEWSTATE", value="abc"),
            NameValue(name="q", value="hello"),
        ],
    )

    def mock_send(r, session):
        return Response(
            status_code=200,
            body="<html><body>ok</body></html>",
            body_len=24,
        )

    monkeypatch.setattr("darco.xss._send", mock_send)
    result = scan_xss(req, include_state_fields=True)
    assert "__VIEWSTATE" in result.tested_params
    assert "q" in result.tested_params


def test_xss_html_attribute_unencoded_quotes(monkeypatch):
    req = Request(
        method="GET",
        url="http://app.test/edit",
        params=[NameValue(name="name", value="admin")],
    )

    def mock_send(r, session):
        val = next((p.value for p in r.params if p.name == "name"), "")
        # Escapes < and > but leaves quotes unencoded inside input attribute
        filtered = val.replace("<", "&lt;").replace(">", "&gt;")
        return Response(
            status_code=200,
            body=f'<html><body><input type="text" name="name" value="{filtered}"></body></html>',
            body_len=100,
        )

    monkeypatch.setattr("darco.xss._send", mock_send)

    result = scan_xss(req)
    assert len(result.reflections) >= 1
    r = result.reflections[0]
    assert r.param == "name"
    assert r.context == "html_attribute"
    assert '"' in r.unencoded_chars
    assert r.confidence == "high"


def test_xss_script_context(monkeypatch):
    req = Request(
        method="GET",
        url="http://app.test/page",
        params=[NameValue(name="theme", value="dark")],
    )

    def mock_send(r, session):
        val = next((p.value for p in r.params if p.name == "theme"), "")
        return Response(
            status_code=200,
            body=f"<script>var currentTheme = '{val}';</script>",
            body_len=100,
        )

    monkeypatch.setattr("darco.xss._send", mock_send)

    result = scan_xss(req)
    assert len(result.reflections) >= 1
    r = result.reflections[0]
    assert r.param == "theme"
    assert r.context == "script_context"
    assert r.confidence == "confirmed"


def test_xss_fully_encoded_safe(monkeypatch):
    req = Request(
        method="GET",
        url="http://app.test/view",
        params=[NameValue(name="msg", value="test")],
    )

    def mock_send(r, session):
        val = next((p.value for p in r.params if p.name == "msg"), "")
        # Full HTML entity encoding
        encoded = (
            val.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#39;")
        )
        return Response(
            status_code=200,
            body=f"<html><body><div>{encoded}</div></body></html>",
            body_len=100,
        )

    monkeypatch.setattr("darco.xss._send", mock_send)

    result = scan_xss(req)
    assert len(result.reflections) >= 1
    r = result.reflections[0]
    assert r.param == "msg"
    assert r.confidence == "low"
    assert len(r.unencoded_chars) == 0
    assert len(r.encoded_chars) > 0


def test_xss_encoded_inside_attribute_surrounded_by_template_quotes(monkeypatch):
    req = Request(
        method="GET",
        url="http://app.test/view",
        params=[NameValue(name="msg", value="test")],
    )

    def mock_send(r, session):
        val = next((p.value for p in r.params if p.name == "msg"), "")
        # Attribute is fully encoded, but surrounded by template double-quotes
        encoded = (
            val.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#39;")
        )
        return Response(
            status_code=200,
            body=f'<html><body><input value="{encoded}" class="form-control" id="field"></body></html>',
            body_len=120,
        )

    monkeypatch.setattr("darco.xss._send", mock_send)

    result = scan_xss(req)
    assert len(result.reflections) >= 1
    r = result.reflections[0]
    assert r.param == "msg"
    assert r.confidence == "low"
    assert '"' not in r.unencoded_chars
    assert "'" not in r.unencoded_chars


# ------------------------------------------------------------------ CLI Integration Tests
def test_cli_xss_command(app, tmp_path):
    res = run(["xss", f"{app}/echo?q=hello"], tmp_path)
    assert res.returncode == 0, res.stderr
    data = json.loads(res.stdout)
    assert "target" in data
    assert "tested_params" in data
    assert "reflections" in data


def test_cli_xss_with_auth_cookie_and_header(app, tmp_path):
    res = run(
        [
            "xss",
            f"{app}/echo?user=bob",
            "-H",
            "Authorization: Bearer token123",
            "-C",
            "session=sess_xyz",
        ],
        tmp_path,
    )
    assert res.returncode == 0, res.stderr
    data = json.loads(res.stdout)
    assert "user" in data["tested_params"]


def test_cli_reflect_alias(app, tmp_path):
    res = run(["reflect", f"{app}/echo?msg=test"], tmp_path)
    assert res.returncode == 0, res.stderr
    data = json.loads(res.stdout)
    assert "msg" in data["tested_params"]
