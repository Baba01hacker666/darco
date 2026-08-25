import json

from darco.analyze import analyze_request, analyze_response
from darco.diff import diff_responses, normalize_body
from darco.models import BodyType, NameValue, Request, Response


def _resp(status, body, headers=None):
    return Response(
        status_code=status,
        reason="OK",
        headers=headers or [NameValue(name="Content-Type", value="text/plain")],
        body=body,
        body_len=len(body.encode()),
        elapsed_ms=10,
    )


def test_diff_status_and_body():
    a = _resp(200, "hello world")
    b = _resp(429, "hello world")
    d = diff_responses(a, b)
    assert d["status"]["changed"] is True
    assert d["status"]["a"] == 200 and d["status"]["b"] == 429


def test_diff_json_structure():
    a = _resp(200, json.dumps({"a": 1, "keep": True}))
    b = _resp(200, json.dumps({"a": 2, "keep": True, "new": 3}))
    d = diff_responses(a, b)
    changes = d["body"]["json_changes"]
    assert any("a" in c and "1" in c and "2" in c for c in changes)
    assert any("new" in c for c in changes)


def test_diff_normalizes_timestamps_and_hex():
    a = _resp(200, "token=abc123def456abc123def456 ts=1712000000")
    b = _resp(200, "token=fff999ddd888fff999ddd888 ts=1712009999")
    d = diff_responses(a, b)
    assert d["body"]["changed"] is False
    assert normalize_body("x 1234567890123 y") == "x <ts> y"


def test_diff_excludes_volatile_headers():
    a = _resp(200, "x", headers=[NameValue(name="Date", value="Mon"), NameValue(name="Server", value="nginx")])
    b = _resp(200, "x", headers=[NameValue(name="Date", value="Tue"), NameValue(name="Server", value="apache")])
    d = diff_responses(a, b)
    names = [h["name"] for h in d["headers"]]
    assert "server" in names
    assert "date" not in names


def test_analyze_request_signals():
    req = Request(
        method="GET",
        url="http://t.test/admin/panel",
        params=[NameValue(name="debug", value="true"), NameValue(name="enabled", value="1"), NameValue(name="otp", value="1234")],
    )
    types = {f.type for f in analyze_request(req)}
    assert "interesting_param_name" in types
    assert "boolean_param" in types
    assert "interesting_path" in types


def test_analyze_response_error_leak():
    req = Request(method="GET", url="http://t.test/error")
    resp = _resp(500, "Traceback (most recent call last):\n  File \"/app/x.py\", line 5, in f")
    types = {f.type for f in analyze_response(req, resp)}
    assert "error_leak" in types
    assert "server_anomaly" in types


def test_analyze_response_rate_limit():
    req = Request(method="POST", url="http://t.test/otp")
    resp = _resp(429, "too many requests")
    assert any(f.type == "rate_limited" for f in analyze_response(req, resp))


def test_analyze_response_rate_limit_body_non_429():
    req = Request(method="POST", url="http://t.test/otp")
    resp = _resp(200, "Slow down! You are being rate limited. Try again later.")
    assert any(f.type == "rate_limited" for f in analyze_response(req, resp))


def test_analyze_response_captcha():
    req = Request(method="GET", url="http://t.test/captcha")
    resp = _resp(200, '<script src="https://www.google.com/recaptcha/api.js"></script>')
    assert any(f.type == "captcha" for f in analyze_response(req, resp))


def test_analyze_response_reflection_and_auth():
    req = Request(method="GET", url="http://t.test/echo", params=[NameValue(name="q", value="reflected-here")])
    resp = _resp(200, "your input: reflected-here")
    assert any(f.type == "reflection" for f in analyze_response(req, resp))
    req2 = Request(method="GET", url="http://t.test/admin")
    resp2 = _resp(403, "forbidden")
    assert any(f.type == "auth_required" for f in analyze_response(req2, resp2))


def test_analyze_response_auth_cookie():
    req = Request(method="POST", url="http://t.test/login")
    resp = Response(
        status_code=302,
        reason="Found",
        headers=[NameValue(name="Set-Cookie", value="session=abc123; Path=/")],
        body="",
        body_len=0,
        set_cookies=[],
    )
    assert any(f.type == "auth_token_cookie" for f in analyze_response(req, resp))
