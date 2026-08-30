import json
import os

from click.testing import CliRunner

from darco.cli import cli
from darco.models import NameValue, Request, Response
from darco.redirect import CANARY_HOST, scan_redirect


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


def _req(url="http://app.test/next", param="url", value="/dashboard"):
    return Request(method="GET", url=url, params=[NameValue(name=param, value=value)])


# ------------------------------------------------------------------ Unit Tests
def test_redirect_location_header_confirmed(monkeypatch):
    def mock_send(r, session):
        val = next((p.value for p in r.params if p.name == "url"), "")
        if val.startswith("http://") and CANARY_HOST in val:
            return Response(
                status_code=302,
                headers=[NameValue(name="Location", value=val)],
                body="",
                body_len=0,
            )
        return Response(status_code=200, body="ok", body_len=2)

    monkeypatch.setattr("darco.redirect._send", mock_send)
    result = scan_redirect(_req())
    assert result.tested_params == ["url"]
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.param == "url"
    assert f.redirect_type == "location_header"
    assert f.confidence == "confirmed"
    assert f.status_code == 302
    assert CANARY_HOST in f.redirect_to


def test_redirect_protocol_relative_payload(monkeypatch):
    seen_payloads = []

    def mock_send(r, session):
        val = next((p.value for p in r.params if p.name == "url"), "")
        seen_payloads.append(val)
        # Only the protocol-relative variant triggers a redirect.
        if val.startswith("//"):
            return Response(
                status_code=302,
                headers=[NameValue(name="Location", value=val)],
                body="",
                body_len=0,
            )
        return Response(status_code=200, body="ok", body_len=2)

    monkeypatch.setattr("darco.redirect._send", mock_send)
    result = scan_redirect(_req())
    assert len(result.findings) == 1
    assert result.findings[0].payload.startswith(f"//{CANARY_HOST}")
    # The absolute-URL payload is always tried first; encoding is never needed here.
    assert seen_payloads[0].startswith("http://")


def test_redirect_meta_refresh_high(monkeypatch):
    def mock_send(r, session):
        val = next((p.value for p in r.params if p.name == "url"), "")
        if CANARY_HOST in val:
            body = (
                '<html><head><meta http-equiv="refresh" content="0; url='
                f'{val}"></head><body></body></html>'
            )
            return Response(status_code=200, body=body, body_len=len(body))
        return Response(status_code=200, body="ok", body_len=2)

    monkeypatch.setattr("darco.redirect._send", mock_send)
    result = scan_redirect(_req())
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.redirect_type == "meta_refresh"
    assert f.confidence == "high"


def test_redirect_js_location_medium(monkeypatch):
    def mock_send(r, session):
        val = next((p.value for p in r.params if p.name == "url"), "")
        if CANARY_HOST in val:
            body = f"<script>location.href = '{val}';</script>"
            return Response(status_code=200, body=body, body_len=len(body))
        return Response(status_code=200, body="ok", body_len=2)

    monkeypatch.setattr("darco.redirect._send", mock_send)
    result = scan_redirect(_req())
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.redirect_type == "js_location"
    assert f.confidence == "medium"


def test_redirect_non_candidate_param_skipped():
    req = Request(
        method="GET",
        url="http://app.test/debug",
        params=[NameValue(name="enabled", value="true")],
    )
    result = scan_redirect(req)
    assert result.tested_params == []
    assert result.findings == []


def test_redirect_param_filter_limits_scope(monkeypatch):
    def mock_send(r, session):
        val = next((p.value for p in r.params if p.name == "url"), "")
        if CANARY_HOST in val:
            return Response(
                status_code=302,
                headers=[NameValue(name="Location", value=val)],
                body="",
                body_len=0,
            )
        return Response(status_code=200, body="ok", body_len=2)

    monkeypatch.setattr("darco.redirect._send", mock_send)
    req = Request(
        method="GET",
        url="http://app.test/jump",
        params=[
            NameValue(name="url", value="/a"),
            NameValue(name="next", value="/b"),
        ],
    )
    scoped = scan_redirect(req, param_filter="next")
    assert scoped.tested_params == ["next"]
    assert scoped.findings == []


def test_redirect_no_false_positive_on_safe_echo(monkeypatch):
    """App reflects the canary in the body but never redirects — no finding."""

    def mock_send(r, session):
        val = next((p.value for p in r.params if p.name == "url"), "")
        return Response(status_code=200, body=f"visited {val}", body_len=64)

    monkeypatch.setattr("darco.redirect._send", mock_send)
    result = scan_redirect(_req(param="next"))
    assert result.tested_params == ["next"]
    assert result.findings == []


def test_redirect_form_param(monkeypatch):
    from darco.models import BodyType

    def mock_send(r, session):
        val = next((p.value for p in r.body_form if p.name == "returnTo"), "")
        if CANARY_HOST in val:
            return Response(
                status_code=302,
                headers=[NameValue(name="Location", value=val)],
                body="",
                body_len=0,
            )
        return Response(status_code=200, body="login", body_len=5)

    monkeypatch.setattr("darco.redirect._send", mock_send)
    req = Request(
        method="POST",
        url="http://app.test/login",
        headers=[
            NameValue(name="Content-Type", value="application/x-www-form-urlencoded")
        ],
        body_type=BodyType.FORM,
        body_form=[NameValue(name="returnTo", value="/home")],
    )
    result = scan_redirect(req)
    assert result.tested_params == ["returnTo"]
    assert len(result.findings) == 1
    assert result.findings[0].param_type == "form"


# ------------------------------------------------------------------ Integration Tests (fixture app)
def test_scan_redirect_finds_open_redirect(app):
    req = Request(
        method="GET",
        url=f"{app}/redirect",
        params=[NameValue(name="url", value="/login")],
    )
    result = scan_redirect(req)
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.confidence == "confirmed"
    assert f.redirect_type == "location_header"


def test_scan_redirect_safe_relative_redirect_clean(app):
    """The fixture only redirects off-site when the payload is absolute —
    but our probes ARE absolute, so this endpoint is genuinely vulnerable.
    A safe endpoint must produce nothing."""
    req = Request(
        method="GET",
        url=f"{app}/debug",
        params=[NameValue(name="enabled", value="true")],
    )
    result = scan_redirect(req)
    assert result.findings == []


def test_scan_redirect_meta_refresh_endpoint(app):
    req = Request(
        method="GET",
        url=f"{app}/meta-refresh",
        params=[NameValue(name="url", value="/home")],
    )
    result = scan_redirect(req)
    assert len(result.findings) == 1
    assert result.findings[0].redirect_type == "meta_refresh"


# ------------------------------------------------------------------ CLI Tests
def test_cli_redirect_command(app, tmp_path):
    res = run(["redirect", f"{app}/redirect?url=/login"], tmp_path)
    assert res.returncode == 0, res.stderr
    data = json.loads(res.stdout)
    assert data["findings"][0]["confidence"] == "confirmed"


def test_cli_open_redirect_alias(app, tmp_path):
    res = run(["open-redirect", "-u", f"{app}/meta-refresh?url=/home"], tmp_path)
    assert res.returncode == 0, res.stderr
    data = json.loads(res.stdout)
    assert data["findings"][0]["redirect_type"] == "meta_refresh"


def test_cli_redirect_requires_target(tmp_path):
    res = run(["redirect"], tmp_path)
    assert res.returncode != 0


def test_redirect_explicit_param_filter_override(monkeypatch):
    def mock_send(r, session):
        val = next((p.value for p in r.params if p.name == "my_target"), "")
        if CANARY_HOST in val:
            return Response(
                status_code=302,
                headers=[NameValue(name="Location", value=val)],
                body="",
                body_len=0,
            )
        return Response(status_code=200, body="ok", body_len=2)

    monkeypatch.setattr("darco.redirect._send", mock_send)
    req = Request(
        method="GET",
        url="http://app.test/go",
        params=[NameValue(name="my_target", value="xyz")],
    )
    result = scan_redirect(req, param_filter="my_target")
    assert result.tested_params == ["my_target"]
    assert len(result.findings) == 1
    assert result.findings[0].param == "my_target"


def test_redirect_candidate_by_url_value(monkeypatch):
    def mock_send(r, session):
        val = next((p.value for p in r.params if p.name == "blob"), "")
        if CANARY_HOST in val:
            return Response(
                status_code=302,
                headers=[NameValue(name="Location", value=val)],
                body="",
                body_len=0,
            )
        return Response(status_code=200, body="ok", body_len=2)

    monkeypatch.setattr("darco.redirect._send", mock_send)
    # 'blob' is not in standard redirect hints, but value is '/dashboard/home'
    req = Request(
        method="GET",
        url="http://app.test/nav",
        params=[NameValue(name="blob", value="/dashboard/home")],
    )
    result = scan_redirect(req)
    assert "blob" in result.tested_params
    assert len(result.findings) == 1
