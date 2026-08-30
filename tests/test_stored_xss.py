import json
import os

import pytest
from click.testing import CliRunner

from darco.cli import cli
from darco.discovery.parsers import extract_forms
from darco.models import Form, FormInput
from darco.stored_xss import audit_stored_xss
from bs4 import BeautifulSoup


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


def _forms_from(app, path):
    import httpx

    resp = httpx.get(f"{app}{path}", trust_env=False, timeout=10)
    return extract_forms(BeautifulSoup(resp.text, "html.parser"), str(resp.url))


# ------------------------------------------------------------------ Integration Tests (fixture app)
def test_stored_xss_confirmed_on_comment_form(app):
    forms = _forms_from(app, "/post?postId=1")
    assert forms, "comment form should be discovered"
    result = audit_stored_xss(forms, target=app)
    assert result.submissions >= 1
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.param == "comment"
    assert f.confidence == "confirmed"
    assert f.context == "html_body"
    assert "/post" in f.render_url
    # The canary really is stored server-side and echoed raw.
    assert "<darcostore" in f.evidence


def test_stored_xss_refreshes_csrf_tokens(app):
    """A form carrying a stale crawl-time CSRF value must still be auditable:
    the auditor re-fetches the source page for a fresh token."""
    stale_form = Form(
        action=f"{app}/post/comment",
        method="POST",
        inputs=[
            FormInput(name="csrf", type="hidden", hidden=True, default="STALE-TOKEN"),
            FormInput(name="postId", type="hidden", hidden=True, default="2"),
            FormInput(name="comment"),
            FormInput(name="name"),
            FormInput(name="email", type="email"),
        ],
        url=f"{app}/post?postId=2",
    )
    result = audit_stored_xss([stale_form], target=app)
    assert len(result.findings) == 1
    assert result.findings[0].confidence == "confirmed"


def test_stored_xss_safe_page_not_flagged(app):
    """The sanitized page escapes stored comments — no findings allowed."""
    forms = _forms_from(app, "/safe-post?postId=1")
    assert forms
    result = audit_stored_xss(forms, target=app)
    assert all(f.confidence != "confirmed" for f in result.findings)


def test_stored_xss_skips_forms_without_injectable_fields():
    form = Form(
        action="http://app.test/vote",
        method="POST",
        inputs=[FormInput(name="choice", type="radio")],
    )
    result = audit_stored_xss([form], target="http://app.test")
    assert result.tested_forms == 0
    assert result.findings == []


def test_stored_xss_submission_budget(app):
    forms = _forms_from(app, "/post?postId=3")
    result = audit_stored_xss(forms, target=app, max_submissions=0)
    assert result.submissions == 0
    assert result.findings == []


# ------------------------------------------------------------------ Pipeline Test
@pytest.mark.anyio
async def test_run_auto_scan_reports_stored_xss(app, tmp_path):
    from darco.scanner import run_auto_scan
    from darco.workspace import Workspace

    old_cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        ws = Workspace.create(app)
        report = await run_auto_scan(
            ws,
            app,
            depth=1,
            max_urls=30,
            workers=4,
            parse_js=False,
            fuzz=False,
            sqli=False,
            xss=False,
            upload=False,
            default_creds=False,
        )
        f = next((f for f in report.stored_xss_findings if f.param == "comment"), None)
        assert f is not None
        assert f.confidence == "confirmed"
        types = {x.type for x in report.findings}
        assert any(t.startswith("stored_xss_") for t in types)
    finally:
        os.chdir(old_cwd)


# ------------------------------------------------------------------ CLI Tests
def test_cli_sxss_command(app, tmp_path):
    res = run(["sxss", f"{app}/post?postId=4"], tmp_path)
    assert res.returncode == 0, res.stderr
    data = json.loads(res.stdout)
    assert data["findings"][0]["param"] == "comment"
    assert data["findings"][0]["confidence"] == "confirmed"


def test_cli_stored_xss_alias(app, tmp_path):
    res = run(["stored-xss", "-u", f"{app}/safe-post?postId=5"], tmp_path)
    assert res.returncode == 0, res.stderr
    data = json.loads(res.stdout)
    assert data["findings"] == []


def test_cli_sxss_requires_target(tmp_path):
    res = run(["sxss"], tmp_path)
    assert res.returncode != 0
