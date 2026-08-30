import json

from click.testing import CliRunner

from darco.cli import cli
from darco.cors import scan_cors
from darco.models import NameValue, Request, Response


def _resp(status=200, headers=None, body="ok"):
    return Response(
        status_code=status,
        reason="OK",
        headers=headers or [],
        body=body,
        body_len=len(body),
    )


def test_cors_arbitrary_origin_with_credentials(monkeypatch):
    req = Request(method="GET", url="http://app.test/api/profile")
    baseline_resp = _resp(
        200,
        headers=[
            NameValue(name="Access-Control-Allow-Origin", value="https://evil.com"),
            NameValue(name="Access-Control-Allow-Credentials", value="true"),
        ],
        body='{"secret": "sensitive-data"}',
    )

    def mock_send(r, session):
        return baseline_resp

    monkeypatch.setattr("darco.cors._send", mock_send)
    result = scan_cors(req)
    assert len(result.findings) >= 1
    f = result.findings[0]
    assert f.misconfig_type == "arbitrary_origin_allowed"
    assert f.confidence == "confirmed"
    assert f.allow_credentials is True
    assert f.allow_origin == "https://evil.com"
    assert "fetch('http://app.test/api/profile'" in f.poc_html
    assert "curl -i" in f.curl


def test_cors_null_origin_allowed(monkeypatch):
    req = Request(method="GET", url="http://app.test/api/data")

    def mock_send(r, session):
        origin_val = next((h.value for h in r.headers if h.name.lower() == "origin"), "")
        if origin_val == "null":
            return _resp(
                200,
                headers=[
                    NameValue(name="Access-Control-Allow-Origin", value="null"),
                    NameValue(name="Access-Control-Allow-Credentials", value="true"),
                ],
            )
        return _resp(200)

    monkeypatch.setattr("darco.cors._send", mock_send)
    result = scan_cors(req)
    null_findings = [f for f in result.findings if f.misconfig_type == "null_origin_allowed"]
    assert len(null_findings) == 1
    assert null_findings[0].confidence == "confirmed"
    assert null_findings[0].allow_origin == "null"


def test_cors_wildcard_with_credentials(monkeypatch):
    req = Request(method="GET", url="http://app.test/api/public")

    def mock_send(r, session):
        return _resp(
            200,
            headers=[
                NameValue(name="Access-Control-Allow-Origin", value="*"),
                NameValue(name="Access-Control-Allow-Credentials", value="true"),
            ],
        )

    monkeypatch.setattr("darco.cors._send", mock_send)
    result = scan_cors(req)
    wild_findings = [f for f in result.findings if f.misconfig_type == "wildcard_with_credentials"]
    assert len(wild_findings) == 1
    assert wild_findings[0].allow_origin == "*"


def test_cors_clean_origin_no_misconfig(monkeypatch):
    req = Request(method="GET", url="http://app.test/api/strict")

    def mock_send(r, session):
        # Server does not echo untrusted origins
        return _resp(
            200,
            headers=[
                NameValue(name="Access-Control-Allow-Origin", value="https://trusted.app.test"),
                NameValue(name="Access-Control-Allow-Credentials", value="true"),
            ],
        )

    monkeypatch.setattr("darco.cors._send", mock_send)
    result = scan_cors(req)
    assert len(result.findings) == 0


def test_cli_cors_command(app, tmp_path):
    runner = CliRunner()
    res = runner.invoke(cli, ["--json", "cors", f"{app}/echo"])
    assert res.exit_code == 0, res.output
    data = json.loads(res.stdout)
    assert "target" in data
    assert "tested_origins" in data
    assert len(data["tested_origins"]) >= 4
