import asyncio
import json
import os

import httpx
from click.testing import CliRunner

from darco.cli import cli
from darco.templates import (
    execute_template_on_target,
    generate_template_scaffold,
    load_builtin_templates,
    load_template_from_string,
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
    assert tmpl.id == "env-test"
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
    res = run(
        [
            "template",
            "new",
            "test-auth-check",
            "--name",
            "Test Auth",
            "--severity",
            "high",
            "--word",
            "forbidden",
        ],
        tmp_path,
    )
    assert res.returncode == 0, res.stderr
    assert "test-auth-check" in res.stdout
    assert "Test Auth" in res.stdout


def test_cli_template_run_with_custom_template(app, tmp_path):
    tmpl_file = tmp_path / "app-login-check.yaml"
    tmpl_file.write_text(
        """
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
""",
        encoding="utf-8",
    )

    res = run(
        ["template", "run", "-u", f"{app}/", "-t", str(tmpl_file), "--save"], tmp_path
    )
    assert res.returncode == 0, res.stderr
    data = json.loads(res.stdout)
    assert data["templates_loaded"] == 1
    assert len(data["matched_results"]) == 1
    assert data["matched_results"][0]["template_id"] == "test-login-check"
    assert len(data["findings"]) == 1


def test_cli_template_run_builtin_by_name(app, tmp_path):
    res = run(["template", "run", "-u", f"{app}/", "-t", "git-config"], tmp_path)
    assert res.returncode == 0, res.stderr
    data = json.loads(res.stdout)
    assert data["templates_loaded"] == 1
    assert data["templates_executed"] == 1


# ------------------------------------------------------------------ custom types / dsl
from darco.templates.custom import (
    get_matcher_type,
    register_matcher_type,
    registered_matcher_types,
)
from darco.templates.dsl import evaluate_dsl
from darco.templates.engine import (
    _evaluate_extractor,
    _evaluate_matcher,
)


def _resp(status=200, text="", headers=None):
    return httpx.Response(status, headers=headers or {}, text=text)


def test_dsl_evaluator_basics():
    vars = {
        "status_code": 200,
        "content_length": 42,
        "body": "Hello Admin World",
        "header": "Server: nginx",
    }
    assert evaluate_dsl("status_code == 200 && contains(body, 'Admin')", vars)
    assert evaluate_dsl("contains_any(body, 'nope', 'World')", vars)
    assert evaluate_dsl("!contains(body, 'nope')", vars)
    assert evaluate_dsl("status_code == 200 || status_code == 500", vars)
    assert not evaluate_dsl("content_length > 100", vars)
    assert evaluate_dsl("(status_code == 200) && len(body) >= 17", vars)
    assert evaluate_dsl("regex(body, 'Admin\\s+World')", vars)
    assert evaluate_dsl("to_lower(header) == 'server: nginx'", vars)
    assert not evaluate_dsl("missing_var == 1", vars)
    # unparseable -> False, never raises
    assert not evaluate_dsl("status_code ===", vars)


def test_dsl_matcher_via_engine():
    m = load_template_from_string("""
id: dsl-check
info:
  name: dsl
requests:
  - path: ["{{BaseURL}}/"]
    matchers:
      - type: dsl
        dsl:
          - "status_code == 404 && contains(body, 'ghost')"
""").requests[0]
    ok, items = _evaluate_matcher(m.matchers[0], _resp(404, "the ghost page"))
    assert ok and items


def test_binary_matcher():
    from darco.templates.models import TemplateMatcher as TM

    m = TM(type="binary", binary=["89504e47"])
    ok, _ = _evaluate_matcher(m, httpx.Response(200, content=b"\x89PNG\r\n\x1a\nrest"))
    assert ok
    ok2, _ = _evaluate_matcher(m, httpx.Response(200, content=b"plain"))
    assert not ok2


def test_xpath_matcher_and_extractor():
    xml = "<users><user role='admin'>bob</user><user>jane</user></users>"
    m = load_template_from_string("""
id: xpath-check
info:
  name: x
requests:
  - path: ["{{BaseURL}}/"]
    matchers:
      - type: xpath
        xpath: ["/users/user[@role='admin']"]
""").requests[0]
    ok, items = _evaluate_matcher(m.matchers[0], _resp(200, xml))
    assert ok and items == ["/users/user[@role='admin']"]

    ext = load_template_from_string("""
id: x
info:
  name: x
requests:
  - path: ["{{BaseURL}}/"]
    extractors:
      - type: xpath
        name: admins
        xpath: ["/users/user[@role='admin']"]
""").requests[0]
    got = _evaluate_extractor(ext.extractors[0], _resp(200, xml))
    assert got["admins"] == ["bob"]


def test_json_matcher_nested_paths():
    body = '{"user": {"role": "admin", "tokens": ["a", "b"]}, "ok": true}'
    m = load_template_from_string("""
id: json-check
info:
  name: j
requests:
  - path: ["{{BaseURL}}/"]
    matchers-condition: and
    matchers:
      - type: json
        json:
          - user.role=admin
          - user.tokens.1
""").requests[0]
    ok, items = _evaluate_matcher(m.matchers[0], _resp(200, body))
    assert ok and sorted(items) == ["user.role=admin", "user.tokens.1"]

    # nested extractor through the native json extractor too
    ext = load_template_from_string("""
id: x
info:
  name: x
requests:
  - path: ["{{BaseURL}}/"]
    extractors:
      - type: json
        name: role
        json: ["user.role"]
""").requests[0]
    assert _evaluate_extractor(ext.extractors[0], _resp(200, body))["role"] == ["admin"]


def test_size_matcher_uses_sizes_field():
    m = load_template_from_string("""
id: size-check
info:
  name: s
requests:
  - path: ["{{BaseURL}}/"]
    matchers:
      - type: size
        sizes: [11]
""").requests[0]
    ok, items = _evaluate_matcher(m.matchers[0], _resp(200, "hello world"))
    assert ok and items == ["11"]


def test_delay_matcher_from_timing_plugin():
    """The timing plugin contributes 'delay' — templates can use it directly."""
    assert "delay" in registered_matcher_types()
    tmpl = load_template_from_string("""
id: slow-check
info:
  name: t
requests:
  - path: ["{{BaseURL}}/"]
    matchers:
      - type: delay
        min_ms: 1000000
""")
    m = tmpl.requests[0].matchers[0]
    ok, _ = _evaluate_matcher(m, _resp(200, "x"), elapsed_ms=5.0)
    assert not ok
    ok2, items2 = _evaluate_matcher(m, _resp(200, "x"), elapsed_ms=1_500_000.0)
    assert ok2 and items2 and "ms" in items2[0]

    fast = (
        load_template_from_string("""
id: fast
info:
  name: f
requests:
  - path: ["{{BaseURL}}/"]
    matchers:
      - type: delay
        min_ms: 0
""")
        .requests[0]
        .matchers[0]
    )
    ok3, items3 = _evaluate_matcher(fast, _resp(200, "x"), elapsed_ms=12.4)
    assert ok3 and items3 and "ms" in items3[0]


def test_custom_matcher_type_python_api():
    @register_matcher_type("_test_always_true", description="always matches")
    def always(matcher, resp, elapsed_ms=0.0):
        return True, ["always"]

    try:
        assert get_matcher_type("_test_always_true") is not None
        assert "_test_always_true" in registered_matcher_types()
        tmpl = load_template_from_string("""
id: custom-type
info:
  name: c
requests:
  - path: ["{{BaseURL}}/"]
    matchers:
      - type: _test_always_true
""")
        results, _, count = asyncio.run(_run_custom(tmpl))
        assert count == 1 and len(results) == 1
        assert results[0].matched_words == ["always"]
    finally:
        from darco.templates import custom as _c

        _c._MATCHER_TYPES.pop("_test_always_true", None)


async def _run_custom(tmpl):
    client = httpx.AsyncClient(transport=MockTemplateTransport())
    try:
        return await execute_template_on_target(tmpl, "http://mock.test", client=client)
    finally:
        await client.aclose()


def test_extractor_chaining_feeds_later_requests():
    yaml_text = """
id: chain-test
info:
  name: Chain
requests:
  - method: GET
    path:
      - "{{BaseURL}}/.env"
    matchers:
      - type: word
        words: ["DB_PASSWORD"]
    extractors:
      - type: regex
        internal: true
        name: dbpass
        regex:
          - 'DB_PASSWORD=(\\S+)'
  - method: GET
    path:
      - "{{BaseURL}}/leak?secret={{dbpass}}"
    matchers:
      - type: status
        status: [200]
"""
    tmpl = load_template_from_string(yaml_text)
    assert tmpl.requests[0].extractors[0].internal is True

    seen_urls = []

    class ChainTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            seen_urls.append(str(request.url))
            if ".env" in str(request.url):
                return httpx.Response(200, text="DB_PASSWORD=hunter2!\n")
            return httpx.Response(200, text="used")

    async def _run():
        client = httpx.AsyncClient(transport=ChainTransport())
        try:
            results, findings, count = await execute_template_on_target(
                tmpl, "http://chain.test", client=client
            )
            return results, findings, count
        finally:
            await client.aclose()

    results, _findings, count = asyncio.run(_run())
    assert count == 2
    assert any("secret=hunter2!" in u for u in seen_urls)
    # internal extractor value stays out of public output
    assert all("dbpass" not in r.extracted_data for r in results)


def test_cli_template_run_extra_vars(app, tmp_path):
    res = run(
        [
            "template",
            "run",
            "-u",
            f"{app}/",
            "-t",
            "git-config",
            "--var",
            "team=pentest",
        ],
        tmp_path,
    )
    assert res.returncode == 0, res.stderr
    data = json.loads(res.stdout)
    assert data["templates_loaded"] == 1

    bad = run(
        ["template", "run", "-u", f"{app}/", "-t", "git-config", "--var", "NOEQUALS"],
        tmp_path,
    )
    assert bad.returncode != 0
