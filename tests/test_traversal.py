import json
import os

from click.testing import CliRunner

from darco.cli import cli
from darco.models import NameValue, Request, Response
from darco.traversal import scan_traversal


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


def _req(param="path", value="report.pdf"):
    return Request(
        method="GET",
        url="http://app.test/download",
        params=[NameValue(name=param, value=value)],
    )


# ------------------------------------------------------------------ Unit Tests
def test_traversal_passwd_confirmed(monkeypatch):
    passwd = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1\n"

    def mock_send(r, session):
        val = next((p.value for p in r.params if p.name == "file"), "")
        if ".." in val and val.endswith("passwd"):
            return Response(status_code=200, body=passwd, body_len=len(passwd))
        return Response(status_code=200, body="report.pdf", body_len=10)

    monkeypatch.setattr("darco.traversal._send", mock_send)
    result = scan_traversal(_req(param="file"))
    assert result.tested_params == ["file"]
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.param == "file"
    assert f.target_file == "etc/passwd"
    assert f.confidence == "confirmed"
    assert "root:x:0:0" in f.evidence


def test_traversal_winini_confirmed(monkeypatch):
    winini = "; for 16-bit app support\n[fonts]\n[extensions]\n"

    def mock_send(r, session):
        val = next((p.value for p in r.params if p.name == "path"), "")
        if ".." in val and "win.ini" in val.lower():
            return Response(status_code=200, body=winini, body_len=len(winini))
        return Response(status_code=200, body="report.pdf", body_len=10)

    monkeypatch.setattr("darco.traversal._send", mock_send)
    result = scan_traversal(_req())
    assert len(result.findings) == 1
    assert result.findings[0].target_file == "windows/win.ini"


def test_traversal_encoded_payload(monkeypatch):
    """Only the percent-encoded variant gets through a decoding app."""
    passwd = "root:x:0:0:root:/root:/bin/bash\n"

    def mock_send(r, session):
        val = next((p.value for p in r.params if p.name == "doc"), "")
        # App decodes %2f but strips literal "../" sequences.
        if "..%2f" in val or "%2e%2e" in val:
            return Response(status_code=200, body=passwd, body_len=len(passwd))
        return Response(status_code=200, body="denied", body_len=6)

    monkeypatch.setattr("darco.traversal._send", mock_send)
    result = scan_traversal(_req(param="doc"))
    assert len(result.findings) == 1
    assert "%2f" in result.findings[0].payload.lower()


def test_traversal_non_candidate_param_skipped():
    req = Request(
        method="GET",
        url="http://app.test/debug",
        params=[NameValue(name="enabled", value="true")],
    )
    result = scan_traversal(req)
    assert result.tested_params == []
    assert result.findings == []


def test_traversal_no_false_positive_on_normal_response(monkeypatch):
    def mock_send(r, session):
        return Response(status_code=200, body="file not found", body_len=14)

    monkeypatch.setattr("darco.traversal._send", mock_send)
    result = scan_traversal(_req())
    assert result.findings == []


def test_traversal_json_body_param(monkeypatch):
    from darco.models import BodyType

    passwd = "root:x:0:0:root:/root:/bin/bash\n"

    def mock_send(r, session):
        doc = (r.body_json or {}).get("template")
        if isinstance(doc, str) and ".." in doc:
            return Response(status_code=200, body=passwd, body_len=len(passwd))
        return Response(status_code=200, body="rendered", body_len=8)

    monkeypatch.setattr("darco.traversal._send", mock_send)
    req = Request(
        method="POST",
        url="http://app.test/render",
        body_type=BodyType.JSON,
        body_json={"template": "home.html"},
    )
    result = scan_traversal(req)
    assert result.tested_params == ["template"]
    assert len(result.findings) == 1
    assert result.findings[0].param_type == "json"


# ------------------------------------------------------------------ Integration Tests (fixture app)
def test_scan_traversal_finds_passwd(app):
    req = Request(
        method="GET",
        url=f"{app}/file",
        params=[NameValue(name="path", value="report.pdf")],
    )
    result = scan_traversal(req)
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.param == "path"
    assert f.confidence == "confirmed"
    assert f.status_code == 200


def test_scan_traversal_safe_endpoint_clean(app):
    req = Request(
        method="GET",
        url=f"{app}/debug",
        params=[NameValue(name="enabled", value="true")],
    )
    result = scan_traversal(req)
    assert result.findings == []


# ------------------------------------------------------------------ CLI Tests
def test_cli_trav_command(app, tmp_path):
    res = run(["trav", f"{app}/file?path=report.pdf"], tmp_path)
    assert res.returncode == 0, res.stderr
    data = json.loads(res.stdout)
    assert data["findings"][0]["confidence"] == "confirmed"
    assert data["findings"][0]["target_file"] == "etc/passwd"


def test_cli_traversal_alias(app, tmp_path):
    res = run(["traversal", "-u", f"{app}/file?path=notes.txt"], tmp_path)
    assert res.returncode == 0, res.stderr
    data = json.loads(res.stdout)
    assert data["tested_params"] == ["path"]


def test_cli_trav_requires_target(tmp_path):
    res = run(["trav"], tmp_path)
    assert res.returncode != 0


def test_traversal_explicit_param_filter_override(monkeypatch):
    passwd = "root:x:0:0:root:/root:/bin/bash\n"

    def mock_send(r, session):
        val = next((p.value for p in r.params if p.name == "custom_blob"), "")
        if ".." in val:
            return Response(status_code=200, body=passwd, body_len=len(passwd))
        return Response(status_code=200, body="normal", body_len=6)

    monkeypatch.setattr("darco.traversal._send", mock_send)
    req = Request(
        method="GET",
        url="http://app.test/view",
        params=[NameValue(name="custom_blob", value="data123")],
    )
    result = scan_traversal(req, param_filter="custom_blob")
    assert result.tested_params == ["custom_blob"]
    assert len(result.findings) == 1
    assert result.findings[0].param == "custom_blob"


def test_traversal_candidate_by_path_value(monkeypatch):
    passwd = "root:x:0:0:root:/root:/bin/bash\n"

    def mock_send(r, session):
        val = next((p.value for p in r.params if p.name == "item"), "")
        if ".." in val:
            return Response(status_code=200, body=passwd, body_len=len(passwd))
        return Response(status_code=200, body="normal", body_len=6)

    monkeypatch.setattr("darco.traversal._send", mock_send)
    # 'item' is not in standard traversal hints, but value is 'images/avatar.png'
    req = Request(
        method="GET",
        url="http://app.test/view",
        params=[NameValue(name="item", value="images/avatar.png")],
    )
    result = scan_traversal(req)
    assert "item" in result.tested_params
    assert len(result.findings) == 1
