import json
import os

from click.testing import CliRunner

from darco.cli import cli
from darco.models import NameValue, Request, Response
from darco.sqli import scan_sqli


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


# ------------------------------------------------------------------ Unit Tests for SQLi Heuristics
def test_sqli_error_based_detection(monkeypatch):
    req = Request(
        method="GET",
        url="http://app.test/item",
        params=[NameValue(name="id", value="1")],
    )

    baseline_resp = Response(
        status_code=200,
        body="<html><body>Item 1 Details</body></html>",
        body_len=40,
    )

    def mock_send(r, session):
        # If payload has single quote, return MySQL syntax error
        for p in r.params:
            if p.name == "id" and "'" in p.value:
                return Response(
                    status_code=500,
                    body="You have an error in your SQL syntax near '' at line 1",
                    body_len=55,
                )
        return baseline_resp

    monkeypatch.setattr("darco.sqli._send", mock_send)

    result = scan_sqli(req, baseline_response=baseline_resp)
    assert len(result.vulnerabilities) >= 1
    vuln = result.vulnerabilities[0]
    assert vuln.param == "id"
    assert vuln.injection_type == "error_based"
    assert vuln.db_engine == "MySQL"
    assert vuln.confidence == "confirmed"


def test_sqli_quote_balancing_detection(monkeypatch):
    req = Request(
        method="GET",
        url="http://app.test/user",
        params=[NameValue(name="user", value="alice")],
    )

    baseline_resp = Response(
        status_code=200,
        body="<html><body>Profile: Alice</body></html>",
        body_len=40,
    )

    def mock_send(r, session):
        for p in r.params:
            if p.name == "user":
                # Single quote causes error / change
                if p.value == "alice'":
                    return Response(
                        status_code=500, body="Internal Server Error", body_len=21
                    )
                # Two single quotes balances the string and restores page
                elif p.value == "alice''":
                    return baseline_resp
        return baseline_resp

    monkeypatch.setattr("darco.sqli._send", mock_send)

    result = scan_sqli(req, baseline_response=baseline_resp)
    assert len(result.vulnerabilities) >= 1
    vuln = result.vulnerabilities[0]
    assert vuln.param == "user"
    assert vuln.injection_type == "quote_balancing"
    assert vuln.confidence == "high"


def test_sqli_arithmetic_evaluation(monkeypatch):
    req = Request(
        method="GET",
        url="http://app.test/product",
        params=[NameValue(name="id", value="5")],
    )

    resp_5 = Response(
        status_code=200,
        body="<html><body>Product 5 Details: Laptop</body></html>",
        body_len=50,
    )

    def mock_send(r, session):
        for p in r.params:
            if p.name == "id":
                if p.value in ("5", "6-1", "5+0"):
                    return resp_5
                else:
                    return Response(
                        status_code=404, body="Product not found", body_len=17
                    )
        return resp_5

    monkeypatch.setattr("darco.sqli._send", mock_send)

    result = scan_sqli(req, baseline_response=resp_5)
    assert len(result.vulnerabilities) >= 1
    vuln = result.vulnerabilities[0]
    assert vuln.param == "id"
    assert vuln.injection_type == "arithmetic_evaluation"
    assert vuln.confidence == "confirmed"


def test_sqli_boolean_differential(monkeypatch):
    req = Request(
        method="GET",
        url="http://app.test/search",
        params=[NameValue(name="query", value="book")],
    )

    baseline_resp = Response(
        status_code=200,
        body="<html><body>Found 10 books</body></html>",
        body_len=40,
    )

    def mock_send(r, session):
        for p in r.params:
            if p.name == "query":
                if "AND '1'='1" in p.value:
                    return baseline_resp
                elif "AND '1'='2" in p.value:
                    return Response(
                        status_code=200,
                        body="<html><body>No results found</body></html>",
                        body_len=43,
                    )
        return baseline_resp

    monkeypatch.setattr("darco.sqli._send", mock_send)

    result = scan_sqli(req, baseline_response=baseline_resp)
    assert len(result.vulnerabilities) >= 1
    vuln = result.vulnerabilities[0]
    assert vuln.param == "query"
    assert vuln.injection_type == "boolean_differential"
    assert vuln.confidence == "high"


# ------------------------------------------------------------------ CLI Integration Tests
def test_cli_sql_command(app, tmp_path):
    res = run(["sql", f"{app}/echo?id=1"], tmp_path)
    assert res.returncode == 0, res.stderr
    data = json.loads(res.stdout)
    assert "target" in data
    assert "tested_params" in data
    assert "vulnerabilities" in data


def test_cli_sql_from_stored_record(app, tmp_path):
    run(["init", app], tmp_path)
    run(["ingest", "curl", "curl", f"{app}/echo?cat=5"], tmp_path)
    res = run(["sql", "--from", "0001"], tmp_path)
    assert res.returncode == 0, res.stderr
    data = json.loads(res.stdout)
    assert "cat" in data["tested_params"]


def test_cli_sqli_alias(app, tmp_path):
    res = run(["sqli", f"{app}/echo?param=test"], tmp_path)
    assert res.returncode == 0, res.stderr
    data = json.loads(res.stdout)
    assert "param" in data["tested_params"]
