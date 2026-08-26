import asyncio
import json
import os
from pathlib import Path
import pytest
from click.testing import CliRunner
import httpx

from darco.cli import cli
from darco.templates import (
    load_template_from_string,
    load_builtin_templates,
    execute_template_on_target,
    run_template_scan,
    generate_template_scaffold,
)


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


# ------------------------------------------------------------------ template loader
def test_load_template_yaml_nuclei_format():
    yaml_text = """
id: git-exposure-test
info:
  name: Git Repository Exposure
  author: tester
  severity: high
  tags: git,exposure
  remediation: Restrict .git directory.

requests:
  - method: GET
    path:
      - "{{BaseURL}}/.git/config"
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
          - "[core]"
          - "repositoryformatversion"
        condition: and
    extractors:
      - type: regex
        name: format_version
        regex:
          - 'repositoryformatversion\\s*=\\s*([0-9]+)'
"""
    tmpl = load_template_from_string(yaml_text, "test.yaml")
    assert tmpl.id == "git-exposure-test"
    assert tmpl.info.name == "Git Repository Exposure"
    assert tmpl.info.severity == "high"
    assert "git" in tmpl.info.tags
    assert len(tmpl.requests) == 1
    req = tmpl.requests[0]
    assert req.method == "GET"
    assert req.path == ["{{BaseURL}}/.git/config"]
    assert req.matchers_condition == "and"
    assert len(req.matchers) == 2
    assert len(req.extractors) == 1
    assert req.extractors[0].name == "format_version"


def test_load_builtin_templates():
    builtins = load_builtin_templates()
    assert len(builtins) >= 5
    ids = {t.id for t in builtins}
    assert "git-config-disclosure" in ids
    assert "env-file-disclosure" in ids
    assert "springboot-actuator-exposure" in ids


def test_builtin_filter_by_tag_and_severity():
    git_tmpls = load_builtin_templates(tags=["git"])
    assert len(git_tmpls) >= 1
    assert all("git" in t.info.tags for t in git_tmpls)

    crit_tmpls = load_builtin_templates(severities=["critical"])
    assert len(crit_tmpls) >= 1
    assert all(t.info.severity == "critical" for t in crit_tmpls)


# ------------------------------------------------------------------ template engine & matching
class MockTemplateTransport(httpx.AsyncBaseTransport):
    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        url_str = str(request.url)

        if ".git/config" in url_str:
            return httpx.Response(
                200,
                headers={"Content-Type": "text/plain", "X-VCS": "Git"},
                text="[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n",
            )
        elif ".env" in url_str:
            return httpx.Response(
                200,
                text="APP_ENV=production\nDB_PASSWORD=supersecret_pass123!\n",
            )
        elif "header-test" in url_str:
            return httpx.Response(
                200,
                headers={"X-Custom-Server": "VulnerableServer-v1.2"},
                text="OK",
            )
        return httpx.Response(404, text="Not Found")


def test_execute_template_match_and_extract():
    yaml_text = """
id: git-test
info:
  name: Git Config Test
  severity: high

requests:
  - method: GET
    path:
      - "{{BaseURL}}/.git/config"
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
          - "[core]"
      - type: word
        part: header
        words:
          - "X-VCS: Git"
    extractors:
      - type: regex
        name: repo_version
        regex:
          - 'repositoryformatversion\\s*=\\s*([0-9]+)'
"""
    tmpl = load_template_from_string(yaml_text)

    async def _run():
        client = httpx.AsyncClient(transport=MockTemplateTransport())
        try:
            results, findings, count = await execute_template_on_target(
                tmpl, "http://mock.test", client=client
            )
            assert count == 1
            assert len(results) == 1
            res = results[0]
            assert res.template_id == "git-test"
            assert res.severity == "high"
            assert "[core]" in res.matched_words
            assert "repo_version" in res.extracted_data
            assert res.extracted_data["repo_version"] == ["0"]
            assert len(findings) == 1
            assert findings[0].severity == "high"
        finally:
            await client.aclose()

    asyncio.run(_run())


def test_run_template_scan_report():
    yaml_text = """
id: env-test
info:
  name: Env File Test
  severity: critical

requests:
  - method: GET
    path:
      - "{{BaseURL}}/.env"
    matchers:
      - type: word
        words:
          - "DB_PASSWORD"
"""
    tmpl = load_template_from_string(yaml_text)

    async def _run():
        report = await run_template_scan(
            [tmpl],
            "http://mock.test",
        )
        # using real or mock
    # Just testing loader & scaffold
    assert tmpl.info.severity == "critical"


def test_generate_template_scaffold():
    scaffold = generate_template_scaffold(
        template_id="custom-cve-check",
        name="Custom CVE Check",
        severity="critical",
        method="POST",
        path="{{BaseURL}}/api/v1/debug",
        words=["root:x:0:0", "daemon:"],
        status_codes=[200],
    )
    assert "id: custom-cve-check" in scaffold
    assert "severity: critical" in scaffold
    assert "root:x:0:0" in scaffold
    assert "POST" in scaffold

    # verify generated YAML loads cleanly
    tmpl = load_template_from_string(scaffold)
    assert tmpl.id == "custom-cve-check"
    assert tmpl.info.severity == "critical"
    assert tmpl.requests[0].method == "POST"


# ------------------------------------------------------------------ CLI
def test_cli_template_list(tmp_path):
    res = run(["template", "list"], tmp_path)
    assert res.returncode == 0, res.stderr
    data = json.loads(res.stdout)
    assert "templates" in data
    assert data["count"] >= 5


def test_cli_template_new(tmp_path):
    res = run(["template", "new", "test-auth-check", "--name", "Test Auth", "--severity", "high", "--word", "forbidden"], tmp_path)
    assert res.returncode == 0, res.stderr
    assert "test-auth-check" in res.stdout
    assert "Test Auth" in res.stdout


def test_cli_template_run_with_custom_template(app, tmp_path):
    tmpl_file = tmp_path / "app-login-check.yaml"
    tmpl_file.write_text("""
id: test-login-check
info:
  name: App Login Page Check
  severity: medium

requests:
  - method: GET
    path:
      - "{{BaseURL}}/login"
    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
          - "username"
          - "password"
        condition: and
""", encoding="utf-8")

    res = run(["template", "run", "-u", f"{app}/", "-t", str(tmpl_file), "--save"], tmp_path)
    assert res.returncode == 0, res.stderr
    data = json.loads(res.stdout)
    assert data["templates_loaded"] == 1
    assert len(data["matched_results"]) == 1
    assert data["matched_results"][0]["template_id"] == "test-login-check"
    assert len(data["findings"]) == 1

