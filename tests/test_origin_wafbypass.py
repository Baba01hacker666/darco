"""Tests for origin-IP discovery, WAF-bypass engine, and proxy bypass mode."""

import json
from unittest import mock

import pytest
from click.testing import CliRunner

from darco.cli import cli
from darco.models import NameValue, Request
from darco.waf_bypass import apply_bypass, build_bypass


# ------------------------------------------------------------------ waf_bypass engine
def test_build_bypass_cloudflare_has_host_swap_when_origin():
    r = build_bypass("Cloudflare", origin_ip="1.2.3.4")
    ids = [t["id"] for t in r["techniques"]]
    assert "host_swap" in ids
    host_swap = next(t for t in r["techniques"] if t["id"] == "host_swap")
    assert "1.2.3.4" in host_swap["description"]


def test_build_bypass_cloudflare_no_host_swap_without_origin():
    r = build_bypass("Cloudflare")
    ids = [t["id"] for t in r["techniques"]]
    assert "host_swap" in ids  # present but as a hint, not applied
    host_swap = next(t for t in r["techniques"] if t["id"] == "host_swap")
    assert "run `darco origin`" in host_swap["description"] or \
        "darco origin" in host_swap["description"]


def test_build_bypass_modsecurity_has_comment_injection():
    r = build_bypass("ModSecurity")
    ids = [t["id"] for t in r["techniques"]]
    assert "comment_injection" in ids
    assert "null_byte" in ids


def test_build_bypass_unknown_uses_generic():
    r = build_bypass(None)
    ids = [t["id"] for t in r["techniques"]]
    assert "header_case" in ids
    assert "encoding" in ids


def test_apply_bypass_injects_header_case_and_x_original_url():
    req = Request(
        method="GET",
        url="http://target/admin/login",
        headers=[NameValue(name="Host", value="target")],
    )
    out, applied = apply_bypass(req)
    assert "header_case" in applied
    assert "x_original_url" in applied
    names = [h.name for h in out.headers]
    assert "X-Original-URL" in names  # normalized on output
    # mixed-case injection: at least one header name is not all-lowercase
    assert any(n != n.lower() for n in names if "forward" in n.lower())


def test_apply_bypass_host_swap_changes_host():
    req = Request(
        method="GET",
        url="http://target/login",
        headers=[NameValue(name="Host", value="target")],
    )
    out, applied = apply_bypass(req, ["host_swap"], origin_ip="9.9.9.9")
    assert "host_swap" in applied
    host = next(h.value for h in out.headers if h.name.lower() == "host")
    assert host == "9.9.9.9"


def test_apply_bypass_path_normalize():
    req = Request(method="GET", url="http://target/admin")
    out, applied = apply_bypass(req, ["path_normalize"])
    assert "path_normalize" in applied
    assert "/./" in out.url or out.url.endswith("/admin")


# ------------------------------------------------------------------ origin: pure logic
def test_origin_cdn_cname_detection():
    from darco.origin import _is_cdn_cname
    assert _is_cdn_cname("xxx.cloudflare.net")
    assert _is_cdn_cname("xxx.amazonaws.com")
    assert not _is_cdn_cname("origin.internal.corp.com")


def test_origin_dig_parses_only_ips():
    from darco.origin import _dig
    with mock.patch("darco.origin.subprocess.run") as run:
        run.return_value = mock.Mock(
            stdout="1.2.3.4\nfoo.cloudflare.net\n5.6.7.8\n", stderr=""
        )
        ips = _dig("A", "x.test")
    assert ips == ["1.2.3.4", "5.6.7.8"]


def test_origin_find_origin_merges_and_flags():
    from darco.origin import find_origin

    def fake_dig(records, host, resolver="8.8.8.8"):
        if records == "A":
            return ["10.0.0.5"] if host == "direct.test" else []
        if records == "CNAME":
            return []
        return []

    class FakeResp:
        status_code = 200
        text = "api.test,10.0.0.9\nwww.test,10.0.0.5\n"

    with mock.patch("darco.origin._dig", side_effect=fake_dig), \
         mock.patch("darco.origin.httpx.get", return_value=FakeResp()):
        report = find_origin("test", enum_subdomains=False, use_history=True)

    hosts = {h.host: h for h in report.hosts}
    assert "api.test" in hosts
    assert hosts["api.test"].ips == ["10.0.0.9"]
    # historical merged with direct
    assert "www.test" in hosts


# ------------------------------------------------------------------ CLI wiring
def test_waf_bypass_cli():
    r = CliRunner().invoke(cli, ["--json", "waf-bypass", "Cloudflare", "--origin-ip", "1.2.3.4"])
    assert r.exit_code == 0, r.output
    d = json.loads(r.stdout)
    assert d["waf"] == "Cloudflare"
    assert any(t["id"] == "host_swap" for t in d["techniques"])


def test_origin_cli_runs():
    # origin hits the network; just assert the command is wired and errors gracefully
    # when offline by mocking find_origin.
    from darco.origin import OriginReport
    with mock.patch(
        "darco.cli.cmd_origin.find_origin",
        return_value=OriginReport(target="x.test", error="offline test"),
    ):
        r = CliRunner().invoke(cli, ["origin", "x.test"])
    assert r.exit_code == 0, r.output
    assert "x.test" in r.stdout
