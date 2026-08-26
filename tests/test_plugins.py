"""Tests for the scan plugin system and the built-in xml_inject plugin."""

import json
import os
import re as _re

from click.testing import CliRunner

from darco.cli import cli
from darco.models import BodyType, NameValue, Request, Response, SessionState
from darco.plugins import (
    ScanPlugin,
    active_plugins,
    get_plugin,
    register_plugin,
    registered_plugins,
)
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


# ------------------------------------------------------------------ registry
def test_registry_lists_xml_inject():
    names = [p.name for p in registered_plugins()]
    assert "xml_inject" in names
    assert get_plugin("xml_inject") is not None


def test_active_plugins_filters():
    assert [p.name for p in active_plugins(only=["xml_inject"])] == ["xml_inject"]
    assert active_plugins(skip=["xml_inject"]) == []
    assert active_plugins(only=["does_not_exist"]) == []
    assert active_plugins(skip=["does_not_exist"]) != []


def test_register_plugin_requires_name():
    with __import__("pytest").raises(ValueError):

        @register_plugin
        class _NoName(ScanPlugin):
            pass


# ------------------------------------------------------------- hook dispatch
def test_scan_sqli_dispatches_plugin_hooks(monkeypatch):
    from darco.plugins import _REGISTRY

    calls = {"collect": 0, "after": [], "scan": 0}

    class Dummy(ScanPlugin):
        name = "_test_dummy"
        description = "test"

        def collect_params(self, request, include_state_fields=False, param_filter=None):
            calls["collect"] += 1
            return []

        def after_param(
            self, request, session, ptype, pname, oval, baseline, result
        ):
            calls["after"].append((ptype, pname))

        def after_scan(self, request, session, result):
            calls["scan"] += 1

    _REGISTRY["_test_dummy"] = Dummy()
    try:
        req = Request(
            method="GET",
            url="http://app.test/item",
            params=[NameValue(name="id", value="1")],
        )
        baseline = Response(status_code=200, body="ok", body_len=2)

        def mock_send(r, session):
            return baseline

        monkeypatch.setattr("darco.sqli._send", mock_send)
        scan_sqli(req, baseline_response=baseline)
        assert calls["collect"] == 1
        assert ("query", "id") in calls["after"]
        assert calls["scan"] == 1
    finally:
        _REGISTRY.pop("_test_dummy", None)


# ------------------------------------------------------------ xml_inject unit
def _xml_req(url: str) -> Request:
    return Request(
        method="POST",
        url=f"{url}/product/stock",
        headers=[NameValue(name="Content-Type", value="application/xml")],
        body_type=BodyType.RAW,
        body_raw="<root><storeId>1</storeId></root>",
    )


def test_xml_plugin_collect_params():
    plugin = get_plugin("xml_inject")
    req = _xml_req("http://app.test")
    assert plugin.collect_params(req) == [("xml", "storeId", "1")]
    assert plugin.collect_params(req, param_filter="other") == []
    # not an XML body -> nothing collected
    plain = Request(
        method="POST",
        url="http://app.test/x",
        body_type=BodyType.FORM,
        body_form=[NameValue(name="storeId", value="1")],
    )
    assert plugin.collect_params(plain) == []


def test_xml_probes_behavioral(monkeypatch):
    from darco.xmlinject import probe_xml_parsing

    req = _xml_req("http://app.test")
    baseline = Response(status_code=200, body="{\"stock\": 853}", body_len=16)

    def mock_send(r, session):
        body = r.body_raw
        ctype = next(
            (h.value for h in r.headers if h.name.lower() == "content-type"), ""
        )
        if "form" in ctype:  # probe D: non-XML rejected
            return Response(status_code=400, body="XML parsing error", body_len=18)
        if "&abc;" in body:  # probe C: undefined entity -> parse failure
            return Response(status_code=400, body="XML parsing error", body_len=18)
        if not body.rstrip().endswith("</root>"):  # probe A: unclosed tag
            return Response(status_code=400, body="XML parsing error", body_len=18)
        return baseline  # probe B + baseline: numeric ref decodes to 1

    monkeypatch.setattr("darco.xmlinject.send", mock_send)

    probe = probe_xml_parsing(
        req, SessionState(), "storeId", "1", baseline=baseline
    )
    assert probe is not None
    assert probe.decodes_entities
    assert probe.parses_xml
    assert probe.requires_xml
    labels = {p["label"] for p in probe.probes}
    assert labels == {"unclosed_tag", "numeric_ref", "undefined_entity", "non_xml"}


def test_xml_plugin_skip_disables_encoded_findings(app):
    req = _xml_req(app)
    result = scan_sqli(req, skip_plugins=["xml_inject"])
    types = {v.injection_type for v in result.vulnerabilities}
    assert not (types & {"xml_entity_decoding", "xml_encoded_sqli"})


# ------------------------------------------------------ xml_inject integration
def test_xml_encoded_waf_bypass_integration(app):
    """Full stack against the fixture: WAF blocks raw SQL, encoded channel fires."""
    req = _xml_req(app)
    result = scan_sqli(req)
    types = {v.injection_type for v in result.vulnerabilities}
    assert "xml_entity_decoding" in types
    assert "xml_encoded_sqli" in types

    enc = next(
        v for v in result.vulnerabilities if v.injection_type == "xml_encoded_sqli"
    )
    assert enc.confidence == "confirmed"  # raw channel was 403-blocked
    assert enc.param_type == "xml"
    assert enc.param == "storeId"
    assert "&#x" in enc.payload
    assert "&#x" in enc.curl

    dec = next(
        v for v in result.vulnerabilities if v.injection_type == "xml_entity_decoding"
    )
    assert dec.confidence == "high"
    assert "numeric_ref" in dec.evidence


def test_xml_encoded_string_param(monkeypatch):
    """String-typed XML element: quoted payloads go through the encoded channel."""
    req = Request(
        method="POST",
        url="http://app.test/search",
        headers=[NameValue(name="Content-Type", value="application/xml")],
        body_type=BodyType.RAW,
        body_raw="<query>book</query>",
    )
    baseline_body = (
        "<html><ul>" + "".join(f"<li>{i}</li>" for i in range(10)) + "</ul></html>"
    )
    baseline = Response(
        status_code=200, body=baseline_body, body_len=len(baseline_body)
    )

    def decode(body):
        return _re.sub(
            r"&#x([0-9A-Fa-f]+);", lambda m: chr(int(m.group(1), 16)), body
        )

    def mock_send(r, session):
        raw = r.body_raw
        val = decode(raw)
        if "&#x" in raw:
            if " OR 1=1" in val:
                body = (
                    "<html>"
                    + "".join(f"<li>{i}</li>" for i in range(200))
                    + "</html>"
                )
                return Response(status_code=200, body=body, body_len=len(body))
            if "AND '1'='2" in val:
                return Response(status_code=404, body="none", body_len=4)
            if "AND '1'='1" in val:
                return baseline
            return baseline
        if _re.search(r"\sor\s|--", raw):
            return Response(status_code=403, body="Attack detected", body_len=15)
        if "'" in raw and "''" not in raw:
            return Response(status_code=500, body="error", body_len=5)
        return baseline

    monkeypatch.setattr("darco.sqli._send", mock_send)
    monkeypatch.setattr("darco.xmlinject.send", mock_send)

    result = scan_sqli(req, baseline_response=baseline)
    types = {v.injection_type for v in result.vulnerabilities}
    assert "xml_encoded_sqli" in types
    enc = next(
        v for v in result.vulnerabilities if v.injection_type == "xml_encoded_sqli"
    )
    assert enc.confidence == "confirmed"
    assert enc.payload.startswith("&#x62;&#x6F;&#x6F;&#x6B;")  # 'book'


# ------------------------------------------------------------------ CLI wiring
def test_cli_plugins_command(tmp_path):
    res = run(["plugins"], tmp_path)
    assert res.returncode == 0, res.stderr
    data = json.loads(res.stdout)
    assert any(p["name"] == "xml_inject" for p in data["plugins"])


def _ingest_xml_stock(app, tmp_path):
    run(["init", app], tmp_path)
    run(
        [
            "ingest",
            "curl",
            "curl",
            "-X",
            "POST",
            f"{app}/product/stock",
            "-H",
            "Content-Type: application/xml",
            "--data-binary",
            "<root><storeId>1</storeId></root>",
        ],
        tmp_path,
    )


def test_cli_sql_xml_encoded_flow(app, tmp_path):
    """Ingest an XML stock-check curl, then scan it end-to-end via --from."""
    _ingest_xml_stock(app, tmp_path)
    res = run(["sql", "--from", "0001"], tmp_path)
    assert res.returncode == 0, res.stderr
    data = json.loads(res.stdout)
    types = {v["injection_type"] for v in data["vulnerabilities"]}
    assert "xml_entity_decoding" in types
    assert "xml_encoded_sqli" in types
    assert data["tested_params"] == ["storeId"]
    # debrief attached so the output reads like a teammate's notes
    assert "debrief" in data
    assert any("XML" in h for h in data["debrief"]["highlights"])


def test_cli_sql_skip_plugin(app, tmp_path):
    _ingest_xml_stock(app, tmp_path)
    res = run(
        ["sql", "--from", "0001", "--skip-plugin", "xml_inject"], tmp_path
    )
    assert res.returncode == 0, res.stderr
    data = json.loads(res.stdout)
    assert not any(
        v["injection_type"].startswith("xml_") for v in data["vulnerabilities"]
    )


def test_cli_sql_only_plugin_unknown_name(app, tmp_path):
    _ingest_xml_stock(app, tmp_path)
    res = run(["sql", "--from", "0001", "--plugin", "nope"], tmp_path)
    assert res.returncode == 0, res.stderr
    data = json.loads(res.stdout)
    # only-mode: unknown plugin filters everything out, tolerated gracefully
    assert data["tested_params"] == []
    assert data["vulnerabilities"] == []
