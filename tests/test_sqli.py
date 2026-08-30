import json
import os

from click.testing import CliRunner

from darco.cli import cli
from darco.models import BodyType, NameValue, Request, Response
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


def test_sqli_skips_framework_state_fields_by_default(monkeypatch):
    req = Request(
        method="POST",
        url="http://app.test/login",
        headers=[
            NameValue(name="Content-Type", value="application/x-www-form-urlencoded")
        ],
        body_type=BodyType.FORM,
        body_form=[
            NameValue(name="__VIEWSTATE", value="abc"),
            NameValue(name="__EVENTVALIDATION", value="def"),
            NameValue(name="tbUsername", value="admin"),
        ],
    )
    baseline_resp = Response(
        status_code=200,
        body="<html><body>ok</body></html>",
        body_len=24,
    )

    def mock_send(r, session):
        return baseline_resp

    monkeypatch.setattr("darco.sqli._send", mock_send)
    result = scan_sqli(req, baseline_response=baseline_resp)
    assert "__VIEWSTATE" not in result.tested_params
    assert "__EVENTVALIDATION" not in result.tested_params
    assert "tbUsername" in result.tested_params


def test_sqli_include_framework_state_fields(monkeypatch):
    req = Request(
        method="POST",
        url="http://app.test/login",
        headers=[
            NameValue(name="Content-Type", value="application/x-www-form-urlencoded")
        ],
        body_type=BodyType.FORM,
        body_form=[
            NameValue(name="__VIEWSTATE", value="abc"),
            NameValue(name="tbUsername", value="admin"),
        ],
    )
    baseline_resp = Response(
        status_code=200,
        body="<html><body>ok</body></html>",
        body_len=24,
    )

    def mock_send(r, session):
        return baseline_resp

    monkeypatch.setattr("darco.sqli._send", mock_send)
    result = scan_sqli(req, baseline_response=baseline_resp, include_state_fields=True)
    assert "__VIEWSTATE" in result.tested_params
    assert "tbUsername" in result.tested_params


def test_sqli_state_validation_error_not_flagged(monkeypatch):
    req = Request(
        method="POST",
        url="http://app.test/login",
        headers=[
            NameValue(name="Content-Type", value="application/x-www-form-urlencoded")
        ],
        body_type=BodyType.FORM,
        body_form=[NameValue(name="__VIEWSTATE", value="x")],
    )
    baseline_resp = Response(
        status_code=200,
        body="<html><body>ok</body></html>",
        body_len=24,
    )

    def mock_send(r, session):
        for p in r.body_form:
            if p.name == "__VIEWSTATE" and p.value.endswith("'"):
                return Response(
                    status_code=500,
                    body="The state information is invalid for this page and might be corrupted.",
                    body_len=80,
                )
        return baseline_resp

    monkeypatch.setattr("darco.sqli._send", mock_send)
    result = scan_sqli(req, baseline_response=baseline_resp, include_state_fields=True)
    assert not any(
        v.param == "__VIEWSTATE"
        and v.injection_type in ("status_anomaly", "quote_balancing")
        for v in result.vulnerabilities
    )


def test_sqli_or_logic_injection_detection(monkeypatch):
    req = Request(
        method="GET",
        url="http://app.test/filter",
        params=[NameValue(name="category", value="Gifts")],
    )
    baseline_resp = Response(
        status_code=200,
        body="<h3>Gift A</h3><h3>Gift B</h3>",
        body_len=40,
    )

    def mock_send(r, session):
        for p in r.params:
            if p.name == "category":
                if "OR 1=1" in p.value or "OR '1'='1" in p.value:
                    return Response(
                        status_code=200,
                        body="<h3>Hidden</h3><h3>Gift A</h3><h3>Gift B</h3>",
                        body_len=120,
                    )
                if "AND 1=2" in p.value:
                    return Response(
                        status_code=200,
                        body="<html>No products</html>",
                        body_len=5,
                    )
        return baseline_resp

    monkeypatch.setattr("darco.sqli._send", mock_send)
    result = scan_sqli(req, baseline_response=baseline_resp)
    assert any(
        v.injection_type == "sql_logic"
        and v.param == "category"
        and v.confidence == "high"
        and v.payload == "Gifts' OR 1=1--"
        for v in result.vulnerabilities
    )


def test_sqli_or_logic_requires_negative_control(monkeypatch):
    req = Request(
        method="GET",
        url="http://app.test/filter",
        params=[NameValue(name="category", value="Gifts")],
    )
    baseline_resp = Response(
        status_code=200,
        body="<h3>Gift A</h3><h3>Gift B</h3>",
        body_len=40,
    )

    def mock_send(r, session):
        # Both OR and AND probes inflate the body (e.g. plain reflection) —
        # no conditional logic, so no sql_logic finding.
        for p in r.params:
            if p.name == "category" and ("OR" in p.value or "AND" in p.value):
                return Response(
                    status_code=200,
                    body=f"<h3>Echo {p.value}</h3>",
                    body_len=120,
                )
        return baseline_resp

    monkeypatch.setattr("darco.sqli._send", mock_send)
    result = scan_sqli(req, baseline_response=baseline_resp)
    assert not any(v.injection_type == "sql_logic" for v in result.vulnerabilities)


# ------------------------------------------------------------------ CLI Integration Tests
def test_cli_sql_command(app, tmp_path):
    res = run(["sql", f"{app}/echo?id=1"], tmp_path)
    assert res.returncode == 0, res.stderr
    data = json.loads(res.stdout)
    assert "target" in data
    assert "tested_params" in data
    assert "vulnerabilities" in data


def test_cli_sql_post_body_xml(app, tmp_path):
    res = run(
        [
            "sql",
            f"{app}/product/stock",
            "-X",
            "POST",
            "-d",
            "<storeId>1</storeId>",
            "-H",
            "Content-Type: application/xml",
        ],
        tmp_path,
    )
    assert res.returncode == 0, res.stderr
    data = json.loads(res.stdout)
    assert "storeId" in data["tested_params"]


def test_cli_sql_include_state_flag(app, tmp_path):
    res = run(["sql", f"{app}/echo?__VIEWSTATE=1&q=x"], tmp_path)
    assert res.returncode == 0, res.stderr
    data = json.loads(res.stdout)
    assert "__VIEWSTATE" not in data["tested_params"]

    res = run(["sql", f"{app}/echo?__VIEWSTATE=1&q=x", "--include-state"], tmp_path)
    assert res.returncode == 0, res.stderr
    data = json.loads(res.stdout)
    assert "__VIEWSTATE" in data["tested_params"]


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


def test_sqli_finding_reproduction_curl(monkeypatch):
    req = Request(
        method="GET",
        url="http://app.test/item",
        params=[NameValue(name="id", value="1")],
        headers=[NameValue(name="Authorization", value="Bearer secret-token")],
    )

    baseline_resp = Response(
        status_code=200,
        body="<html><body>Item 1 Details</body></html>",
        body_len=40,
    )

    def mock_send(r, session):
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
    assert vuln.curl
    assert "curl -i" in vuln.curl
    assert "Authorization: Bearer secret-token" in vuln.curl


def test_sqli_reproduction_curl_escapes_single_quotes():
    from darco.sqli import _build_repro_curl

    req = Request(
        method="POST",
        url="http://app.test/api",
        headers=[NameValue(name="X-Custom", value="user's header")],
        body_type=BodyType.RAW,
        body_raw="<data>' OR '1'='1</data>",
    )
    curl = _build_repro_curl(
        req,
        param_type="xml",
        param_name="data",
        payload="admin'--",
        orig_val="' OR '1'='1",
    )
    assert "user'\\''s header" in curl
    assert "admin'\\''--" in curl
