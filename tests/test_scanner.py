import json
import os

import pytest
from click.testing import CliRunner

from darco.cli import cli
from darco.scanner import run_auto_scan
from darco.workspace import Workspace


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


# ------------------------------------------------------------------ Core Scanner Tests
def test_build_requests_from_sitemap():
    from darco.models import Endpoint, Form, FormInput, NameValue, SiteMap
    from darco.scanner import _build_requests_from_sitemap

    sitemap = SiteMap(
        target="http://example.com",
        endpoints=[
            Endpoint(
                url="http://example.com/items",
                methods=["GET"],
                params=[NameValue(name="id", value="42"), NameValue(name="cat", value="books")],
            ),
            Endpoint(
                url="http://example.com/search?q=test",
                methods=["GET"],
            ),
        ],
        forms=[
            Form(
                action="http://example.com/login",
                method="POST",
                inputs=[FormInput(name="username", default="admin"), FormInput(name="password")],
            )
        ],
    )

    reqs = _build_requests_from_sitemap(sitemap)
    assert len(reqs) == 3
    get_req = next(r for r in reqs if r.url == "http://example.com/items")
    assert get_req.method == "GET"
    assert len(get_req.params) == 2
    assert any(p.name == "id" and p.value == "42" for p in get_req.params)

    post_req = next(r for r in reqs if r.url == "http://example.com/login")
    assert post_req.method == "POST"
    assert len(post_req.body_form) == 2


@pytest.mark.anyio
async def test_run_auto_scan(app, tmp_path):
    old_cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        ws = Workspace.create(app)
        report = await run_auto_scan(
            ws,
            app,
            depth=2,
            max_urls=20,
            workers=2,
            parse_js=False,
            fuzz=True,
            sqli=True,
            xss=True,
        )
        assert report.target == app
        assert report.crawled_endpoints > 0
        assert report.crawled_forms >= 0
        assert report.fuzzed_requests >= 0
    finally:
        os.chdir(old_cwd)


# ------------------------------------------------------------------ CLI Integration Tests
def test_cli_discover_with_fuzz(app, tmp_path):
    res = run(["discover", app, "--fuzz", "--max-urls", "10", "--no-js"], tmp_path)
    assert res.returncode == 0, res.stderr
    data = json.loads(res.stdout)
    assert "target" in data
    assert "crawled_endpoints" in data
    assert "fuzzed_requests" in data


def test_cli_crawl_with_fuzz(app, tmp_path):
    res = run(["crawl", app, "--fuzz", "--max-urls", "10", "--no-js"], tmp_path)
    assert res.returncode == 0, res.stderr
    data = json.loads(res.stdout)
    assert "crawled_endpoints" in data


def test_cli_scan_command(app, tmp_path):
    res = run(["scan", app, "--max-urls", "10", "--no-js"], tmp_path)
    assert res.returncode == 0, res.stderr
    data = json.loads(res.stdout)
    assert "target" in data
    assert "anomalies" in data
    assert "findings" in data


def test_cli_auto_alias(app, tmp_path):
    res = run(["auto", app, "--max-urls", "10", "--no-js"], tmp_path)
    assert res.returncode == 0, res.stderr
    data = json.loads(res.stdout)
    assert "target" in data
