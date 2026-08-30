import json
import os

import pytest
from click.testing import CliRunner

from darco.cli import cli
from darco.errors import DarcoError
from darco.ingest import parse_curl, parse_har, parse_raw_http
from darco.models import BodyType


def test_curl_basic_get():
    req = parse_curl(
        'curl -s "https://example.com/api?foo=bar" -H "X-Api-Key: secret" -A "test-agent"'
    )
    assert req.method == "GET"
    assert req.url == "https://example.com/api"
    assert [(p.name, p.value) for p in req.params] == [("foo", "bar")]
    assert any(h.name == "X-Api-Key" and h.value == "secret" for h in req.headers)
    assert any(h.name == "User-Agent" and h.value == "test-agent" for h in req.headers)


def test_cli_ingest_curl_quoted_command(tmp_path):
    runner = CliRunner()
    old_cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        res = runner.invoke(cli, ["--json", "init", "http://target.test"])
        assert res.exit_code == 0, res.output
        res = runner.invoke(
            cli,
            [
                "--json",
                "ingest",
                "curl",
                "curl -X POST http://target.test/login -d 'user=admin&pass=hunter2'",
            ],
        )
        assert res.exit_code == 0, res.output
        data = json.loads(res.stdout)
        assert data["id"] == "0001"
        req = data["request"]
        assert req["method"] == "POST"
        assert req["url"] == "http://target.test/login"
        assert req["body_type"] == "form"
    finally:
        os.chdir(old_cwd)


def test_curl_form_data_and_method():
    req = parse_curl("curl -X POST http://h/login -d username=u -d 'password=p&x=1'")
    assert req.method == "POST"
    assert req.body_type == BodyType.FORM
    pairs = {(p.name, p.value) for p in req.body_form}
    assert ("username", "u") in pairs
    assert ("password", "p") in pairs
    assert ("x", "1") in pairs


def test_curl_data_json():
    req = parse_curl("curl -X POST http://h/api --data-json '{\"a\": 1}'")
    assert req.body_type == BodyType.JSON
    assert req.body_json == {"a": 1}
    assert any(
        h.name.lower() == "content-type" and "json" in h.value for h in req.headers
    )


def test_curl_data_urlencode():
    req = parse_curl(
        "curl -X POST http://h/x --data-urlencode 'name=hello world' --data-urlencode bare"
    )
    pairs = {(p.name, p.value) for p in req.body_form}
    assert ("name", "hello world") in pairs
    assert ("bare", "bare") in pairs


def test_curl_get_mode_params():
    req = parse_curl('curl -G "http://h/search" -d "q=abc" -d "page=2"')
    assert req.url == "http://h/search"
    assert {p.name for p in req.params} == {"q", "page"}


def test_curl_cookies_and_basic_auth():
    req = parse_curl('curl http://h/ -b "sid=abc; theme=dark" -u "user:pass"')
    assert {c.name for c in req.cookies} == {"sid", "theme"}
    auth = next(h for h in req.headers if h.name == "Authorization")
    assert auth.value.startswith("Basic ")


def test_curl_quoting_and_flags():
    req = parse_curl("curl -L -k --max-time 5 'http://h/a b?x=1'")
    assert req.follow_redirects is True
    assert req.verify is False
    assert req.timeout == 5.0


def test_curl_long_options_with_equals():
    req = parse_curl('curl --request=PUT --header="X-Test: 1" http://h/x')
    assert req.method == "PUT"
    assert any(h.name == "X-Test" and h.value == "1" for h in req.headers)


def test_curl_empty_header_semicolon():
    req = parse_curl('curl http://h/ -H "X-Empty;"')
    assert any(h.name == "X-Empty" and h.value == "" for h in req.headers)


def test_curl_no_url_raises():
    with pytest.raises(DarcoError):
        parse_curl("curl -H 'X: 1'")


def test_raw_absolute_url():
    text = "GET http://example.com/path?q=1 HTTP/1.1\r\nHost: example.com\r\nX-A: b\r\n\r\n"
    req = parse_raw_http(text)
    assert req.method == "GET"
    assert req.url == "http://example.com/path"
    assert {p.name for p in req.params} == {"q"}
    assert any(h.name == "X-A" and h.value == "b" for h in req.headers)


def test_raw_relative_url_and_body():
    text = "POST /login HTTP/1.1\r\nHost: target.test\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nuser=u&pass=p"
    req = parse_raw_http(text)
    assert req.url == "http://target.test/login"
    assert req.body_type == BodyType.FORM
    assert {p.name for p in req.body_form} == {"user", "pass"}


def test_curl_implicit_post_method():
    req = parse_curl("curl http://h/login -d username=u")
    assert req.method == "POST"
    assert req.body_type == BodyType.FORM

    req_json = parse_curl("curl http://h/api --data-json '{\"k\": 1}'")
    assert req_json.method == "POST"

    req_form = parse_curl("curl http://h/upload -F file=data")
    assert req_form.method == "POST"


def test_raw_no_trailing_newline():
    text = "GET /status HTTP/1.1\r\nHost: example.com"
    req = parse_raw_http(text)
    assert req.method == "GET"
    assert req.url == "http://example.com/status"


def test_raw_multiple_cookie_headers():
    text = (
        "GET / HTTP/1.1\r\nHost: t.test\r\nCookie: sid=1\r\nCookie: theme=dark\r\n\r\n"
    )
    req = parse_raw_http(text)
    cookie_dict = {c.name: c.value for c in req.cookies}
    assert cookie_dict == {"sid": "1", "theme": "dark"}
    assert not any(h.name.lower() == "cookie" for h in req.headers)


def test_raw_cookie_header_moved():
    text = "GET / HTTP/1.1\r\nHost: t.test\r\nCookie: sid=1; a=b\r\n\r\n"
    req = parse_raw_http(text)
    assert {c.name for c in req.cookies} == {"sid", "a"}
    assert not any(h.name.lower() == "cookie" for h in req.headers)


def test_har_parsing():
    har = {
        "log": {
            "entries": [
                {
                    "request": {
                        "method": "POST",
                        "url": "https://x.test/api?q=1",
                        "headers": [
                            {"name": "Content-Type", "value": "application/json"}
                        ],
                        "queryString": [{"name": "q", "value": "1"}],
                        "cookies": [{"name": "sid", "value": "v"}],
                        "postData": {
                            "mimeType": "application/json",
                            "text": '{"k": 2}',
                        },
                    }
                }
            ]
        }
    }
    reqs = parse_har(json.dumps(har))
    assert len(reqs) == 1
    req = reqs[0]
    assert req.url == "https://x.test/api"
    assert req.method == "POST"
    assert req.body_type == BodyType.JSON
    assert req.body_json == {"k": 2}
    assert {c.name for c in req.cookies} == {"sid"}


def test_parse_curl_accepts_token_list():
    """CLI nargs -> parse_curl(list) must preserve argument boundaries."""
    req = parse_curl(
        [
            "curl",
            "-X",
            "POST",
            "http://h/stock",
            "-H",
            "Content-Type: application/xml",
            "--data-binary",
            "<storeId>1</storeId>",
        ]
    )
    assert req.method == "POST"
    assert req.body_type == BodyType.RAW
    assert req.body_raw == "<storeId>1</storeId>"
    assert (
        next(h for h in req.headers if h.name == "Content-Type").value
        == "application/xml"
    )


def test_curl_data_binary_always_raw_even_with_equals():
    """--data-binary must not be form-interpreted, even with '=' in the payload."""
    req = parse_curl(
        [
            "curl",
            "-X",
            "POST",
            "http://h/stock",
            "--data-binary",
            '<?xml version="1.0" encoding="UTF-8"?><stockCheck><storeId>1</storeId></stockCheck>',
        ]
    )
    assert req.body_type == BodyType.RAW
    assert req.body_raw == (
        '<?xml version="1.0" encoding="UTF-8"?><stockCheck><storeId>1</storeId></stockCheck>'
    )
    assert req.body_form == []


def test_har_form_urlencoded_text_fallback():
    har = {
        "log": {
            "entries": [
                {
                    "request": {
                        "method": "POST",
                        "url": "https://x.test/login",
                        "headers": [],
                        "queryString": [],
                        "postData": {
                            "mimeType": "application/x-www-form-urlencoded",
                            "text": "username=admin&password=secret%20pass&csrf=xyz",
                        },
                    }
                }
            ]
        }
    }
    reqs = parse_har(json.dumps(har))
    assert len(reqs) == 1
    req = reqs[0]
    assert req.body_type == BodyType.FORM
    pairs = {p.name: p.value for p in req.body_form}
    assert pairs == {
        "username": "admin",
        "password": "secret pass",
        "csrf": "xyz",
    }


def test_curl_autodetect_json_and_xml():
    # JSON auto-detection from raw -d
    req_json = parse_curl(
        'curl -X POST http://h/api -d \'{"user":"alice","role":"admin"}\''
    )
    assert req_json.body_type == BodyType.JSON
    assert req_json.body_json == {"user": "alice", "role": "admin"}
    assert any(
        h.name.lower() == "content-type" and "json" in h.value for h in req_json.headers
    )

    # XML auto-detection from raw -d
    req_xml = parse_curl(
        "curl -X POST http://h/soap -d '<soap:Envelope><user>1</user></soap:Envelope>'"
    )
    assert req_xml.body_type == BodyType.RAW
    assert req_xml.body_raw == "<soap:Envelope><user>1</user></soap:Envelope>"
    assert any(
        h.name.lower() == "content-type" and "xml" in h.value for h in req_xml.headers
    )


def test_curl_data_urlencode_empty_value():
    req = parse_curl("curl -X POST http://h/form --data-urlencode 'empty=' --data-urlencode 'full=1'")
    pairs = {(p.name, p.value) for p in req.body_form}
    assert ("empty", "") in pairs
    assert ("full", "1") in pairs


def test_parse_har_long_payload_string():
    long_comment = "a" * 8000
    har = {
        "log": {
            "entries": [
                {
                    "request": {
                        "method": "GET",
                        "url": "http://example.com/api",
                        "comment": long_comment,
                    }
                }
            ]
        }
    }
    reqs = parse_har(json.dumps(har))
    assert len(reqs) == 1
    assert reqs[0].url == "http://example.com/api"


def test_parse_raw_http_relative_target_without_slash():
    raw = "GET status HTTP/1.1\nHost: example.com\n\n"
    req = parse_raw_http(raw)
    assert req.url == "http://example.com/status"
