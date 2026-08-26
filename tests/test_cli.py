import json
import os
from pathlib import Path

from click.testing import CliRunner

from darco.cli import cli

REPO = Path(__file__).resolve().parent.parent


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


def test_cli_init_and_ingest_curl(tmp_path):
    result = run(["init", "http://target.test"], tmp_path)
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    assert data["status"] == "created"
    ws_dir = tmp_path / "target.test.darco"
    assert ws_dir.exists()

    result = run(
        [
            "ingest",
            "curl",
            "curl",
            "-X",
            "POST",
            "http://target.test/login",
            "-d",
            "user=u",
            "--dry-run",
        ],
        tmp_path,
    )
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    assert data["request"]["method"] == "POST"
    assert data["request"]["body_type"] == "form"

    result = run(
        [
            "ingest",
            "curl",
            "curl",
            "-X",
            "POST",
            "http://target.test/login",
            "-d",
            "user=u",
        ],
        tmp_path,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["id"] == "0001"

    result = run(["status"], tmp_path)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["history_count"] == 1


def test_cli_send_and_diff(app, tmp_path):
    result = run(["init", app], tmp_path)
    assert result.returncode == 0, result.stderr

    result = run(
        ["ingest", "curl", "curl", "-s", f"{app}/debug?enabled=true"], tmp_path
    )
    assert result.returncode == 0, result.stderr
    first_id = json.loads(result.stdout)["id"]

    result = run(["send", "--from", first_id], tmp_path)
    assert result.returncode == 0, result.stderr
    base_id = json.loads(result.stdout)["id"]
    assert "SECRET=super-secret-value" in json.loads(result.stdout)["response"]["body"]

    result = run(["send", "--from", base_id, "--flip-param", "enabled"], tmp_path)
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    assert data["response"]["status_code"] == 200
    assert "SECRET=super-secret-value" not in data["response"]["body"]
    assert data["request"]["mutations"] == ["flip param enabled"]

    second_id = data["id"]
    result = run(["diff", base_id, second_id], tmp_path)
    assert result.returncode == 0, result.stderr
    diff = json.loads(result.stdout)
    assert diff["body"]["changed"] is True

    result = run(["analyze", second_id], tmp_path)
    assert result.returncode == 0, result.stderr
    assert any(
        f["type"] == "boolean_param" for f in json.loads(result.stdout)["findings"]
    )


def test_cli_export_raw(app, tmp_path):
    result = run(["init", app], tmp_path)
    run(["ingest", "curl", "curl", "-X", "POST", f"{app}/echo", "-d", "a=1"], tmp_path)
    result = run(["send", "--from", "0001"], tmp_path)
    assert result.returncode == 0, result.stderr
    result = run(["export", "0001", "--raw"], tmp_path)
    assert result.returncode == 0, result.stderr
    assert result.stdout.startswith("POST /echo HTTP/1.1")
    assert "Host:" in result.stdout


def test_cli_no_workspace_errors(tmp_path):
    result = run(["status"], tmp_path)
    assert result.returncode == 1
    assert "no workspace" in result.stderr


def test_cli_direct_url_without_send(app, tmp_path):
    result = run([f"{app}/echo", "-X", "POST", "-d", "direct=yes"], tmp_path)
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    assert data["oneshot"] is True
    assert data["response"]["status_code"] == 200
    assert "direct=yes" in data["response"]["body"]


def test_cli_direct_url_with_dash_u(app, tmp_path):
    result = run(["-u", f"{app}/echo", "-d", "foo=bar"], tmp_path)
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    assert data["oneshot"] is True
    assert data["response"]["status_code"] == 200
    assert "foo=bar" in data["response"]["body"]


def test_cli_discover_auto_workspace(app, tmp_path):
    result = run(["discover", app, "--depth", "1", "--max-urls", "5"], tmp_path)
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    assert "endpoints" in data


def test_cli_ingest_preserves_header_value(tmp_path):
    """-H 'Content-Type: application/xml' must not lose its value at the CLI."""
    run(["init", "http://target.test"], tmp_path)
    result = run(
        [
            "ingest",
            "curl",
            "curl",
            "-X",
            "POST",
            "http://target.test/product/stock",
            "-H",
            "Content-Type: application/xml",
            "--data-binary",
            "<storeId>1</storeId>",
            "--dry-run",
        ],
        tmp_path,
    )
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    req = data["request"]
    assert req["body_type"] == "raw"
    assert req["body_raw"] == "<storeId>1</storeId>"
    ct = [h for h in req["headers"] if h["name"] == "Content-Type"]
    assert ct and ct[0]["value"] == "application/xml"


def test_table_renderer_nested_and_lists():
    from darco.cli import _table_from_json

    out = _table_from_json(
        {
            "target": "http://t.test",
            "stats": {"visited": 3, "errors": 0},
            "endpoints": [
                {"url": "http://t.test/a", "methods": ["GET"], "status": 200},
                {"url": "http://t.test/b", "methods": ["POST"], "status": 403},
            ],
            "emails": ["a@t.test"],
            "debrief": {
                "verdict": "Checked 2 endpoints.",
                "highlights": ["Found /admin"],
                "next_steps": ["Verify auth."],
            },
        }
    )
    assert "target\thttp://t.test" in out
    assert "visited" in out
    assert "url" in out
    assert "http://t.test/a" in out
    assert "a@t.test" in out
    assert "verdict\tChecked 2 endpoints." in out
    assert "- Found /admin" in out


def test_cli_table_format_send(app, tmp_path):
    res = run(
        ["--format", "table", "send", "-u", f"{app}/api/items"],
        tmp_path,
        json_only=False,
    )
    assert res.returncode == 0, res.stderr
    assert "status_code" in res.stdout
    assert "name" in res.stdout  # response headers rendered as a sub-table
