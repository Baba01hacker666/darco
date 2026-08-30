"""Tests for the smart fuzzer v2 (type-aware payloads + semantic scoring) and the deep transport probes."""

import json
import subprocess
import tempfile
import threading

import pytest
from click.testing import CliRunner

from darco.cli import cli
from darco.models import BodyType, Cookie, NameValue, Request, Response, SessionState


# ------------------------------------------------------------------ type inference
def test_v2_infers_numeric():
    from darco.fuzz_v2 import _infer_type
    assert _infer_type("id", "5") == "numeric"
    assert _infer_type("user_id", "100") == "numeric"


def test_v2_infers_boolean():
    from darco.fuzz_v2 import _infer_type
    assert _infer_type("debug", "true") == "boolean"
    assert _infer_type("is_admin", "false") == "boolean"


def test_v2_infers_email():
    from darco.fuzz_v2 import _infer_type
    assert _infer_type("email", "a@b.com") == "email"
    assert _infer_type("username", "root@localhost") == "email"


def test_v2_infers_filename_and_path():
    from darco.fuzz_v2 import _infer_type
    assert _infer_type("file", "shell.php") == "filename"
    assert _infer_type("path", "../../etc/passwd") == "path"
    assert _infer_type("url", "http://x/") == "url"


# ------------------------------------------------------------------ build_variants is type-tailored
def test_v2_build_variants_numeric_gets_boundaries_not_xss():
    from darco.fuzz_v2 import build_variants

    req = Request(method="GET", url="http://t/u", params=[NameValue(name="id", value="5")])
    labels = [lbl for lbl, _, _ in build_variants(req)]
    assert any(lbl.startswith("boundary:id=") for lbl in labels)
    assert any(lbl.startswith("type-confuse:id=") for lbl in labels)
    # a numeric id should NOT get SQL/XSS/cmdi probes
    assert not any(lbl.startswith("sql:id") for lbl in labels)
    assert not any(lbl.startswith("xss:id") for lbl in labels)


def test_v2_build_variants_string_gets_injection_probes():
    from darco.fuzz_v2 import build_variants

    req = Request(method="GET", url="http://t/u", params=[NameValue(name="q", value="x")])
    labels = [lbl for lbl, _, _ in build_variants(req)]
    assert any(lbl.startswith("sql:q") for lbl in labels)
    assert any(lbl.startswith("xss:q") for lbl in labels)
    assert any(lbl.startswith("cmdi:q") for lbl in labels)


def test_v2_build_variants_filename_gets_upload_probes():
    from darco.fuzz_v2 import build_variants

    req = Request(
        method="POST",
        url="http://t/upload",
        body_type=BodyType.FORM,
        body_form=[NameValue(name="file", value="pic.jpg")],
    )
    labels = [lbl for lbl, _, _ in build_variants(req)]
    assert any(lbl.startswith("upload:file=") for lbl in labels)


def test_v2_variants_not_larger_than_v1():
    from darco.fuzz_v2 import build_variants
    from darco.fuzz import build_variants as build_v1

    req = Request(
        method="GET",
        url="http://t/u",
        params=[
            NameValue(name="id", value="5"),
            NameValue(name="q", value="x"),
            NameValue(name="page", value="1"),
        ],
    )
    v2 = len(build_variants(req))
    v1 = len(build_v1(req))
    # v2 is context-aware: it should not spray more variants than v1 for the
    # same request (v1 repeats SQL/XSS on every "interesting" name).
    assert v2 <= v1


# ------------------------------------------------------------------ semantic scoring
def test_v2_classify_semantic_multi_signal():
    from darco.fuzz_v2 import _classify

    base = Response(status_code=200, body="<html>ok</html>", body_len=15, url="http://t")
    resp = Response(
        status_code=500,
        body="DB Error: You have an error in your SQL syntax near 'x'",
        body_len=55,
        url="http://t",
    )
    c = _classify("sql:q", base, resp, None)
    assert c is not None
    assert "error_leak" in c["anomalies"]
    assert "sql_error" in c["anomalies"]
    assert "status_change" in c["anomalies"]
    assert c["severity"] >= 5


def test_v2_classify_reflected_payload():
    from darco.fuzz_v2 import _classify

    base = Response(status_code=200, body="normal", body_len=6, url="http://t")
    resp = Response(
        status_code=200,
        body="you sent: <script>alert(1)</script>",
        body_len=38,
        url="http://t",
    )
    c = _classify("xss:q", base, resp, None)
    assert c is not None
    assert "reflected_payload" in c["anomalies"]


def test_v2_classify_new_header_surface():
    from darco.fuzz_v2 import _classify

    base = Response(
        status_code=200,
        body="ok",
        body_len=2,
        url="http://t",
        headers=[NameValue(name="Server", value="nginx")],
    )
    resp = Response(
        status_code=200,
        body="ok",
        body_len=2,
        url="http://t",
        headers=[
            NameValue(name="Server", value="nginx"),
            NameValue(name="X-RateLimit-Remaining", value="99"),
        ],
    )
    c = _classify("boundary:id=0", base, resp, None)
    assert c is not None
    assert "new_header_surface" in c["anomalies"]


def test_v2_classify_entropy_delta_caught():
    from darco.fuzz_v2 import _classify

    base = Response(status_code=200, body="aaaaaaaaaaaaaaaaaaaa", body_len=20, url="http://t")
    resp = Response(
        status_code=200,
        body="the quick brown fox jumps over the lazy dog near the river bank",
        body_len=64,
        url="http://t",
    )
    c = _classify("boundary:id=0", base, resp, None)
    assert c is not None
    assert "body_changed" in c["anomalies"]


def test_v2_classify_identical_is_none():
    from darco.fuzz_v2 import _classify

    base = Response(status_code=200, body="same", body_len=4, url="http://t")
    resp = Response(status_code=200, body="same", body_len=4, url="http://t")
    assert _classify("flip:x", base, resp, None) is None


# ------------------------------------------------------------------ integration: fuzz command uses v2
def test_fuzz_command_uses_v2_oneshot(app, tmp_path):
    r = CliRunner().invoke(cli, ["--json", "fuzz", "-u", f"{app}/debug?enabled=true"])
    assert r.exit_code == 0, r.output
    d = json.loads(r.stdout)
    labels = [x["label"] for x in d["results"]]
    assert any(lbl.startswith("flip:enabled") for lbl in labels)
    assert all("severity" in x for x in d["results"])


# ------------------------------------------------------------------ transport: off-line pieces
def test_transport_ja3_string_format():
    from darco.transport import _ja3_string

    s = _ja3_string([0x1301, 0x1302], [0x0000, 0x000A], [0x001D], [0x00])
    parts = s.split(",")
    assert len(parts) == 4
    assert parts[0] == "1301-1302"
    assert parts[2] == "001d"


def test_transport_ja3_against_local_tls():
    import ssl
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *a):
            pass

    cert = "/tmp/hermes-ja3.pem"
    key = "/tmp/hermes-ja3.key"
    subprocess.run(
        f"openssl req -x509 -newkey rsa:2048 -nodes -keyout {key} -out {cert} "
        f"-days 1 -subj '/CN=localhost' 2>/dev/null",
        shell=True,
        check=True,
    )
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    srv = HTTPServer(("127.0.0.1", 0), H)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    from darco.transport import ja3_fingerprint

    r = ja3_fingerprint(f"https://127.0.0.1:{port}/", timeout=5)
    srv.shutdown()
    assert r["error"] in (None, "")
    assert r["ja3"]
    assert "-" in r["ja3"]
    assert r["tls_version"]


def test_transport_smuggling_no_crash():
    from darco.transport import probe_smuggling

    res = probe_smuggling("http://127.0.0.1:1/", timeout=2)
    assert isinstance(res, dict)
    assert isinstance(res.get("findings"), list)
