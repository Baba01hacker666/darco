import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from darco.workspace import Workspace  # noqa: E402

PASSWORD = "hunter2"


class FixtureHandler(BaseHTTPRequestHandler):
    attempts: dict = {}

    def log_message(self, *args):  # silence
        pass

    def _cookie(self):
        raw = self.headers.get("Cookie", "")
        for part in raw.split(";"):
            name, _, value = part.strip().partition("=")
            if name == "session":
                return value
        return None

    def _send(self, status, body, headers=None, ctype="text/html"):
        data = body if isinstance(body, bytes) else body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in (headers or []):
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        path = urlsplit(self.path).path
        qs = parse_qs(urlsplit(self.path).query, keep_blank_values=True)
        if path == "/":
            self._send(200, """<html><body>
<a href="/login">login</a>
<a href="/admin">admin</a>
<a href="/api/items">items</a>
<a href="/debug?enabled=true">debug on</a>
<a href="/debug?enabled=false">debug off</a>
<a href="/captcha">captcha</a>
<a href="/error">error</a>
<script src="/js/app.js"></script>
</body></html>""")
        elif path == "/login":
            self._send(200, """<form method="POST" action="/login">
<input type="hidden" name="csrf" value="abc123">
<input name="username">
<input name="password" type="password">
</form>""")
        elif path == "/admin":
            self._send(403, "forbidden")
        elif path == "/api/items":
            self._send(200, json.dumps({"items": [1, 2, 3]}), ctype="application/json")
        elif path == "/debug":
            enabled = qs.get("enabled", [""])[0]
            body = f"debug enabled={enabled}"
            if enabled.lower() in ("true", "1", "yes"):
                body += "\nSECRET=super-secret-value"
            self._send(200, body)
        elif path == "/js/app.js":
            self._send(200, """const x = fetch('/api/users');
axios.get('/internal/status');
const ws = new WebSocket('/ws/events');""", ctype="application/javascript")
        elif path == "/robots.txt":
            self._send(200, "User-agent: *\nDisallow: /admin\nDisallow: /backup\n", ctype="text/plain")
        elif path == "/captcha":
            self._send(200, '<script src="https://www.google.com/recaptcha/api.js"></script><form action="/verify"><input name="code"></form>')
        elif path == "/error":
            self._send(500, "Traceback (most recent call last):\n  File \"/app/app.py\", line 42, in index\n    raise ValueError('boom')\nInternal Server Error")
        elif path == "/backup":
            self._send(200, "backup data")
        elif path == "/csrf":
            self._send(200, "token page", headers=[("X-CSRF-Token", "tok123")], ctype="text/plain")
        elif path == "/echo":
            payload = {"method": self.command, "path": urlsplit(self.path).path, "headers": {k: v for k, v in self.headers.items()}}
            self._send(200, json.dumps(payload), ctype="application/json")
        else:
            self._send(404, "not found")

    def do_POST(self):
        path = urlsplit(self.path).path
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode("utf-8", errors="replace")
        if path == "/login":
            if PASSWORD in body:
                self._send(302, "", headers=[("Location", "/"), ("Set-Cookie", f"session=sess-{len(self.attempts)}; Path=/")])
            else:
                self._send(401, "bad creds")
        elif path == "/otp":
            bucket = self._cookie() or "anonymous"
            self.attempts[bucket] = self.attempts.get(bucket, 0) + 1
            if self.attempts[bucket] > 3:
                self._send(429, "rate limited: too many requests", headers=[("Retry-After", "60")])
                return
            code = parse_qs(body).get("otp_code", [""])[0]
            self._send(200, json.dumps({"ok": code == "123456"}), ctype="application/json")
        elif path == "/echo":
            payload = {"method": "POST", "body": body, "cookies": self._cookie() or "", "headers": {k: v for k, v in self.headers.items()}}
            self._send(200, json.dumps(payload), ctype="application/json")
        else:
            self._send(404, "not found")


@pytest.fixture()
def app():
    server = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    FixtureHandler.attempts = {}
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture()
def workspace(tmp_path):
    return Workspace.create("http://target.test", tmp_path / "t.darco")
