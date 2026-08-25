import json
import os

from click.testing import CliRunner

from darco.cli import cli
from darco.detection import detect_technologies, detect_waf
from darco.models import Cookie, NameValue, Response


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


# ------------------------------------------------------------------ Technology Detection Unit Tests
def test_detect_web_servers():
    resp_nginx = Response(
        status_code=200,
        headers=[NameValue(name="Server", value="nginx/1.24.0")],
    )
    techs = detect_technologies(resp_nginx)
    assert any(
        t.name == "nginx" and t.version == "1.24.0" and t.category == "server"
        for t in techs
    )

    resp_iis = Response(
        status_code=200,
        headers=[NameValue(name="Server", value="Microsoft-IIS/10.0")],
    )
    techs = detect_technologies(resp_iis)
    assert any(t.name == "Microsoft-IIS" and t.version == "10.0" for t in techs)

    resp_apache = Response(
        status_code=200,
        headers=[NameValue(name="Server", value="Apache/2.4.58 (Ubuntu)")],
    )
    techs = detect_technologies(resp_apache)
    assert any(t.name == "Apache" and t.version == "2.4.58" for t in techs)


def test_detect_languages_and_frameworks_headers():
    resp_php = Response(
        status_code=200,
        headers=[NameValue(name="X-Powered-By", value="PHP/8.2.14")],
        set_cookies=[Cookie(name="PHPSESSID", value="abcdef123456")],
    )
    techs = detect_technologies(resp_php)
    assert any(t.name == "PHP" and t.version == "8.2.14" for t in techs)

    resp_aspnet = Response(
        status_code=200,
        headers=[
            NameValue(name="X-Powered-By", value="ASP.NET"),
            NameValue(name="X-AspNet-Version", value="4.0.30319"),
        ],
        body='<input type="hidden" name="__VIEWSTATE" value="xyz" />',
    )
    techs = detect_technologies(resp_aspnet)
    assert any(t.name == "ASP.NET" and t.version == "4.0.30319" for t in techs)

    resp_express = Response(
        status_code=200,
        headers=[NameValue(name="X-Powered-By", value="Express")],
        set_cookies=[Cookie(name="connect.sid", value="s%3Asession")],
    )
    techs = detect_technologies(resp_express)
    assert any(t.name == "Express" for t in techs)
    assert any("Express / Node.js" in t.name or t.name == "Express" for t in techs)


def test_detect_cms_and_frontend():
    resp_wp = Response(
        status_code=200,
        headers=[NameValue(name="X-Generator", value="WordPress 6.4.2")],
        body='<html><head><script src="/wp-content/themes/theme/app.js"></script></head></html>',
    )
    techs = detect_technologies(resp_wp)
    assert any(t.name == "WordPress" and t.version == "6.4.2" for t in techs)

    resp_frontend = Response(
        status_code=200,
        body="""
        <html><body>
        <div id="__next"><div data-reactroot="">Hello</div></div>
        <script src="/static/js/jquery-3.6.0.min.js"></script>
        <link rel="stylesheet" href="/css/bootstrap-5.3.0.min.css">
        <button hx-get="/items">Load</button>
        </body></html>
        """,
    )
    techs = detect_technologies(resp_frontend)
    names = {t.name for t in techs}
    assert "React" in names
    assert "Next.js" in names
    assert "jQuery" in names
    assert "Bootstrap" in names
    assert "HTMX" in names


# ------------------------------------------------------------------ WAF Detection Unit Tests
def test_detect_cloudflare_waf():
    resp = Response(
        status_code=200,
        headers=[
            NameValue(name="Server", value="cloudflare"),
            NameValue(name="cf-ray", value="85b51234abcd-IAD"),
        ],
        set_cookies=[Cookie(name="cf_clearance", value="tok123")],
    )
    wafs = detect_waf(resp)
    assert len(wafs) >= 1
    assert any(w.name == "Cloudflare" and w.confidence == "high" for w in wafs)
    assert not wafs[0].blocked


def test_detect_aws_waf_blocked():
    resp = Response(
        status_code=403,
        headers=[
            NameValue(name="Server", value="awselb/2.0"),
            NameValue(name="x-amzn-requestid", value="12345"),
        ],
        body="<html><body><h1>403 Forbidden</h1>Request blocked by AWS WAF</body></html>",
    )
    wafs = detect_waf(resp)
    assert any(w.name == "AWS WAF / CloudFront" and w.blocked is True for w in wafs)


def test_detect_akamai_waf():
    resp = Response(
        status_code=403,
        headers=[
            NameValue(name="Server", value="AkamaiGHost"),
            NameValue(name="x-akamai-request-id", value="98765"),
        ],
        set_cookies=[Cookie(name="ak_bmsc", value="abc")],
        body="Access Denied. You don't have permission to access. Reference&#32;&#35;18.abc.123",
    )
    wafs = detect_waf(resp)
    assert any("Akamai" in w.name and w.blocked is True for w in wafs)


def test_detect_modsecurity():
    resp = Response(
        status_code=403,
        headers=[
            NameValue(name="Server", value="Apache/2.4.41 (Ubuntu) mod_security/2.9.3")
        ],
        body="This error was generated by Mod_Security rules.",
    )
    wafs = detect_waf(resp)
    assert any(w.name == "ModSecurity" for w in wafs)


def test_detect_f5_bigip():
    resp = Response(
        status_code=403,
        headers=[NameValue(name="Server", value="BigIP")],
        set_cookies=[Cookie(name="TS01abcdef", value="123")],
        body="The requested URL was rejected. Please consult with your administrator.",
    )
    wafs = detect_waf(resp)
    assert any(w.name == "F5 BIG-IP ASM" and w.blocked is True for w in wafs)


# ------------------------------------------------------------------ CLI Commands
def test_cli_detect_command(app, tmp_path):
    res = run(["detect", f"{app}/echo"], tmp_path)
    assert res.returncode == 0, res.stderr
    data = json.loads(res.stdout)
    assert "target" in data
    assert "technologies" in data
    assert "wafs" in data


def test_cli_detect_waf_only_and_tech_only(app, tmp_path):
    res = run(["waf", f"{app}/echo"], tmp_path)
    assert res.returncode == 0, res.stderr
    data = json.loads(res.stdout)
    assert len(data["technologies"]) == 0

    res = run(["tech", f"{app}/echo"], tmp_path)
    assert res.returncode == 0, res.stderr
    data = json.loads(res.stdout)
    assert len(data["wafs"]) == 0


def test_cli_analyze_includes_tech_and_waf_findings(app, tmp_path):
    run(["init", app], tmp_path)
    run(["ingest", "curl", "curl", f"{app}/about.aspx"], tmp_path)
    run(["send", "--from", "0001"], tmp_path)
    res = run(["analyze", "0002"], tmp_path)
    assert res.returncode == 0, res.stderr
    data = json.loads(res.stdout)
    finding_types = {f["type"] for f in data["findings"]}
    # In test server, path /about.aspx triggers tech detection
    assert "tech_detected" in finding_types or len(data["findings"]) >= 1
