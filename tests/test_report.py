import json

from click.testing import CliRunner

from darco.cli import cli
from darco.models import Finding
from darco.report import export_html, export_junit, export_sarif
from darco.workspace import Workspace


def test_export_sarif_structure():
    findings = [
        Finding(
            id="0001",
            type="sqli_error_based",
            severity="high",
            location="http://app.test/api?id=1",
            evidence="MySQL syntax error in response",
            suggestion="Use parameterized queries",
        ),
        Finding(
            id="0002",
            type="missing_hsts",
            severity="low",
            location="http://app.test/",
            evidence="Strict-Transport-Security header missing",
            suggestion="Add Strict-Transport-Security: max-age=31536000",
        ),
    ]

    sarif = export_sarif(findings, target_url="http://app.test")
    assert sarif["version"] == "2.1.0"
    runs = sarif["runs"]
    assert len(runs) == 1
    driver = runs[0]["tool"]["driver"]
    assert driver["name"] == "darco"
    assert len(driver["rules"]) == 2
    results = runs[0]["results"]
    assert len(results) == 2
    assert results[0]["level"] == "error"
    assert results[1]["level"] == "warning"


def test_export_junit_xml():
    findings = [
        Finding(
            id="0001",
            type="xss_reflection",
            severity="high",
            location="http://app.test/search",
            evidence="Payload reflected unencoded in HTML body",
        )
    ]
    xml_str = export_junit(findings, suite_name="darco-test")
    assert '<?xml version="1.0"' in xml_str
    assert '<testsuite name="darco-test"' in xml_str
    assert '<failure message=' in xml_str


def test_export_html_report():
    findings = [
        Finding(
            id="0001",
            type="open_redirect",
            severity="medium",
            location="http://app.test/redirect",
            evidence="Reflects canary in Location header",
        )
    ]
    html_doc = export_html(findings, target_url="http://app.test")
    assert "<!DOCTYPE html>" in html_doc
    assert "Darco Security Report" in html_doc
    assert "open_redirect" in html_doc
    assert "Medium" in html_doc


def test_cli_report_command(tmp_path):
    ws = Workspace.create("http://target.test", path=tmp_path / ".darco")
    ws.add_findings(
        [
            Finding(
                id="0001",
                type="test_finding",
                severity="high",
                location="http://target.test/a",
                evidence="found evidence",
            )
        ]
    )

    runner = CliRunner()
    # SARIF format
    res = runner.invoke(cli, ["--workspace", str(tmp_path / ".darco"), "--json", "report", "--format", "sarif"])
    assert res.exit_code == 0, res.output
    sarif_data = json.loads(res.stdout)
    assert sarif_data["version"] == "2.1.0"

    # HTML format to file
    out_html = tmp_path / "report.html"
    res_html = runner.invoke(
        cli,
        [
            "--workspace",
            str(tmp_path / ".darco"),
            "report",
            "--format",
            "html",
            "-o",
            str(out_html),
        ],
    )
    assert res_html.exit_code == 0, res_html.output
    assert out_html.exists()
    assert "<!DOCTYPE html>" in out_html.read_text()
