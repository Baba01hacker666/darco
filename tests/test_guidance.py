import json
import os

from click.testing import CliRunner

from darco.cli import cli
from darco.guidance import build_notes, render_notes


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


# ------------------------------------------------------------------ guidance unit tests
def test_sqli_notes_include_manual_verification():
    notes = build_notes(
        {
            "target": "http://app.test/filter",
            "tested_params": ["category"],
            "vulnerabilities": [
                {
                    "param": "category",
                    "param_type": "query",
                    "injection_type": "sql_logic",
                    "confidence": "high",
                    "payload": "Gifts' OR 1=1--",
                    "baseline_status": 200,
                    "payload_status": 200,
                }
            ],
        }
    )
    assert notes is not None
    assert "SQL injection" in notes["verdict"]
    assert any("curl" in s for s in notes["next_steps"])
    assert any("OR-logic" in s for s in notes["next_steps"])


def test_sqli_notes_clean_target():
    notes = build_notes(
        {
            "target": "http://app.test/filter",
            "tested_params": ["category"],
            "vulnerabilities": [],
        }
    )
    assert notes is not None
    assert "No SQL injection signals" in notes["verdict"]


def test_xss_notes_reflect_execution_potential():
    notes = build_notes(
        {
            "target": "http://app.test/search",
            "tested_params": ["q"],
            "reflections": [
                {
                    "param": "q",
                    "context": "html_body",
                    "confidence": "high",
                    "unencoded_chars": ["<", ">"],
                    "encoded_chars": [],
                }
            ],
        }
    )
    assert notes is not None
    assert "unencoded" in notes["highlights"][0]
    assert any("alert(document.domain)" in s for s in notes["next_steps"])


def test_scan_notes_prioritize_high_medium():
    notes = build_notes(
        {
            "target": "http://app.test/",
            "crawled_endpoints": 5,
            "crawled_forms": 3,
            "sqli_vulnerabilities": [{"param": "id"}],
            "xss_reflections": [],
            "upload_findings": [],
            "findings": [
                {"severity": "high", "type": "sqli_quote_balancing", "location": "/filter"},
                {"severity": "info", "type": "tech_detected", "location": "/"},
            ],
        }
    )
    assert notes is not None
    assert "1 SQLi" in notes["verdict"]
    assert any("sqli_quote_balancing" in h for h in notes["highlights"])


def test_detect_notes_mention_cve_hunting():
    notes = build_notes(
        {
            "target": "http://app.test/",
            "status_code": 200,
            "wafs": [],
            "technologies": [
                {"name": "ASP.NET", "version": "2.0.50727", "confidence": "high"}
            ],
        }
    )
    assert notes is not None
    assert "CVE" in notes["next_steps"][0]


def test_login_notes_highlight_bypass():
    notes = build_notes(
        {
            "target": "http://app.test/login",
            "forms_found": [{"action": "http://app.test/login"}],
            "tested_forms": 1,
            "bypasses": [
                {
                    "param": "username",
                    "payload": "administrator'--",
                    "confidence": "high",
                    "success_indicator": "redirect_to_account",
                }
            ],
            "notes": [],
        }
    )
    assert notes is not None
    assert "login-bypass" in notes["verdict"]
    assert any("administrator'--" in h for h in notes["highlights"])
    assert any("browser" in s for s in notes["next_steps"])


def test_unrelated_data_gets_no_notes():
    assert build_notes({"status": "created", "workspace": "/tmp/x"}) is None
    assert build_notes("not a dict") is None


def test_render_notes_markdown():
    out = render_notes(
        {
            "verdict": "Found 1 SQL injection point.",
            "highlights": ["`HIGH` — `id` looks injectable"],
            "next_steps": ["Replay the probe manually."],
        }
    )
    assert "## What Darco thinks" in out
    assert "**Highlights**" in out
    assert "**Do this next**" in out


# ------------------------------------------------------------------ CLI integration
def test_cli_sql_json_includes_notes(app, tmp_path):
    res = run(["sql", f"{app}/echo?id=1"], tmp_path)
    assert res.returncode == 0, res.stderr
    data = json.loads(res.stdout)
    assert "debrief" in data
    assert "verdict" in data["debrief"]


def test_cli_md_output_includes_debrief(app, tmp_path):
    res = run(["sql", f"{app}/echo?id=1"], tmp_path, json_only=False)
    assert res.returncode == 0, res.stderr
    assert "What Darco thinks" in res.stdout
    assert "Do this next" in res.stdout
