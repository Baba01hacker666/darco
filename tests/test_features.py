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


def _ws_name(app):
    return app.split("//")[1].split(":")[0]


# ------------------------------------------------------------------ repeat
def test_cli_repeat_otp_until_rate_limit(app, tmp_path):
    run(["init", app], tmp_path)
    run(
        ["ingest", "curl", "curl", "-X", "POST", f"{app}/otp", "-d", "otp_code=000000"],
        tmp_path,
    )
    # send once to create 0001
    r = run(["send", "--from", "0001"], tmp_path)
    assert r.returncode == 0, r.stderr
    # repeat 5 times: first 3 ok (200), 4th/5th hit the 429 because the bucket
    # shares the anonymous session across replays
    r = run(["repeat", "0001", "--count", "5"], tmp_path)
    assert r.returncode == 0, r.stderr
    data = json.loads(r.stdout)
    assert data["count"] == 5
    assert len(data["ids"]) == 5
    # at least one 429 must appear once the per-bucket limit is exceeded
    assert 429 in data["statuses"]


def test_cli_repeat_with_set_param(app, tmp_path):
    run(["init", app], tmp_path)
    run(["ingest", "curl", "curl", f"{app}/debug?enabled=true"], tmp_path)
    run(["send", "--from", "0001"], tmp_path)
    r = run(
        ["repeat", "0001", "--count", "2", "--set-param", "enabled=false"], tmp_path
    )
    assert r.returncode == 0, r.stderr
    data = json.loads(r.stdout)
    assert data["count"] == 2
    assert all(s == 200 for s in data["statuses"])


# ------------------------------------------------------------------ analyze --save + findings
def test_cli_analyze_save_and_findings_list(app, tmp_path):
    run(["init", app], tmp_path)
    run(["ingest", "curl", "curl", f"{app}/debug?enabled=true"], tmp_path)
    run(["send", "--from", "0001"], tmp_path)
    r = run(["analyze", "0001", "--save"], tmp_path)
    assert r.returncode == 0, r.stderr
    saved = json.loads(r.stdout)["saved"]
    assert saved >= 1  # boolean_param and/or interesting_path expected

    r = run(["findings", "list"], tmp_path)
    assert r.returncode == 0, r.stderr
    listing = json.loads(r.stdout)
    assert listing["count"] >= 1
    types = {f["type"] for f in listing["findings"]}
    assert "boolean_param" in types or "interesting_path" in types


def test_cli_findings_clear(app, tmp_path):
    run(["init", app], tmp_path)
    run(["ingest", "curl", "curl", f"{app}/error"], tmp_path)
    run(["send", "--from", "0001"], tmp_path)
    run(["analyze", "0001", "--save"], tmp_path)
    r = run(["findings", "clear"], tmp_path)
    assert r.returncode == 0, r.stderr
    assert json.loads(r.stdout)["status"] == "cleared"
    r = run(["findings", "list"], tmp_path)
    assert json.loads(r.stdout)["count"] == 0


# ------------------------------------------------------------------ md default + on-the-fly (-u)
def test_cli_default_output_is_markdown(app, tmp_path):
    run(["init", app], tmp_path)
    run(["ingest", "curl", "curl", f"{app}/echo"], tmp_path)
    rr = run(["send", "--from", "0001"], tmp_path, json_only=False)
    assert rr.returncode == 0, rr.stderr
    # markdown marker present, raw JSON braces not on first line
    assert "# Sent" in rr.stdout
    assert not rr.stdout.lstrip().startswith("{")


def test_cli_oneshot_send_without_workspace(app, tmp_path):
    rr = run(
        ["send", "-u", f"{app}/echo", "-X", "POST", "--data", "a=1", "--header", "X-Probe: 9"],
        tmp_path,
        json_only=True,
    )
    assert rr.returncode == 0, rr.stderr
    d = json.loads(rr.stdout)
    assert d["oneshot"] is True
    assert d["response"]["status_code"] == 200
    assert "x-probe" in d["response"]["body"].lower()
    assert "a=1" in d["response"]["body"]


def test_cli_oneshot_fuzz_without_workspace(app, tmp_path):
    rr = run(
        ["send", "-u", f"{app}/debug?enabled=true", "--fuzz"],
        tmp_path,
        json_only=True,
    )
    assert rr.returncode == 0, rr.stderr
    d = json.loads(rr.stdout)
    assert d["oneshot"] is True
    assert d["fuzz"]["total_variants"] >= 1
    # flip:enabled should be among the surfaced anomalies
    assert any(x["label"].startswith("flip:enabled") for x in d["fuzz"]["results"])
