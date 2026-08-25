import json
import os

import pytest
from click.testing import CliRunner

from darco.cli import cli
from darco.models import NameValue, Response
from darco.passive.headers import audit_security_headers
from darco.passive.runner import run_passive_enum
from darco.passive.security_txt import inspect_security_txt


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


# ------------------------------------------------------------------ Headers Audit Tests
def test_audit_security_headers_all_present():
    resp = Response(
        status_code=200,
        headers=[
            NameValue(name="Strict-Transport-Security", value="max-age=31536000; includeSubDomains"),
            NameValue(name="Content-Security-Policy", value="default-src 'self'"),
            NameValue(name="X-Frame-Options", value="DENY"),
            NameValue(name="X-Content-Type-Options", value="nosniff"),
            NameValue(name="Referrer-Policy", value="strict-origin-when-cross-origin"),
            NameValue(name="Permissions-Policy", value="camera=(), microphone=()"),
        ],
        url="https://secure.example.com",
    )
    present, missing, findings = audit_security_headers(resp, "https://secure.example.com")
    assert len(present) == 6
    assert len(missing) == 0
    assert len(findings) == 0


def test_audit_security_headers_missing():
    resp = Response(
        status_code=200,
        headers=[],
        url="https://insecure.example.com",
    )
    present, missing, findings = audit_security_headers(resp, "https://insecure.example.com")
    assert len(present) == 0
    assert "Strict-Transport-Security" in missing
    assert "Content-Security-Policy" in missing
    assert any(f.type == "missing_csp" for f in findings)
    assert any(f.type == "missing_hsts" for f in findings)


# ------------------------------------------------------------------ Security.txt Inspection Tests
@pytest.mark.anyio
async def test_security_txt_parsing(app):
    # App has no security.txt by default
    sec, findings = await inspect_security_txt(app)
    assert not sec.present
    assert any(f.type == "missing_security_txt" for f in findings)


# ------------------------------------------------------------------ Runner Tests
@pytest.mark.anyio
async def test_passive_enum_runner():
    report = await run_passive_enum(
        "example.com",
        subdomains=False,  # Skip external CT logs in unit test
        dns=True,
        security_txt=True,
        headers=True,
    )
    assert report.domain == "example.com"
    assert len(report.dns_records) > 0
    assert len(report.findings) > 0


# ------------------------------------------------------------------ CLI Commands
def test_cli_passive_command(app, tmp_path):
    res = run(["passive", f"{app}/echo", "--no-subdomains"], tmp_path)
    assert res.returncode == 0, res.stderr
    data = json.loads(res.stdout)
    assert "target" in data
    assert "domain" in data
    assert "dns_records" in data
    assert "security_headers" in data
    assert "findings" in data


def test_cli_enum_and_info_aliases(app, tmp_path):
    res = run(["enum", f"{app}/echo", "--no-subdomains", "--no-dns"], tmp_path)
    assert res.returncode == 0, res.stderr
    data = json.loads(res.stdout)
    assert "domain" in data

    res = run(["info", f"{app}/echo", "--no-subdomains", "--no-dns"], tmp_path)
    assert res.returncode == 0, res.stderr
    data = json.loads(res.stdout)
    assert "domain" in data
