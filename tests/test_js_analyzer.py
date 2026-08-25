import json
import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from click.testing import CliRunner

from darco.cli import cli
from darco.discovery.js_extractor import (
    extract_detailed_js_endpoints,
)
from darco.js_analyzer import analyze_local_js, analyze_target_js


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


SAMPLE_JS = """
// Client-side API definitions
async function getUsers() {
    const res = await fetch("/api/v1/users?page=1&limit=25", { method: "GET" });
    return res.json();
}

function updateProfile(data) {
    return axios.post('/api/v2/profile/update', data);
}

function deleteItem(itemId) {
    return axios.delete(`/api/items/${itemId}`);
}

function callGraphql() {
    return fetch('/graphql', { method: 'POST', body: JSON.stringify({ query: '{ users { id name } }' }) });
}

// Webpack chunks
__webpack_require__.e("chunk-admin");

// Exposed credentials
const config = {
    apiKey: "AIzaSyD-1234567890abcdefghijklmnopqrstu",
    token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.do_not_leak_signature_here"
};
"""


def test_extract_detailed_js_endpoints():
    endpoints, secrets, chunks = extract_detailed_js_endpoints(
        SAMPLE_JS, base_url="http://example.com", source_name="app.js"
    )

    paths = {e.path for e in endpoints}
    assert "/api/v1/users?page=1&limit=25" in paths or any(
        "/api/v1/users" in p for p in paths
    )
    assert any("/api/v2/profile/update" in p for p in paths)
    assert any("/api/items/{itemId}" in p for p in paths)
    assert any("graphql" in p for p in paths)

    # Check methods
    post_eps = [e for e in endpoints if e.method == "POST"]
    assert any("/api/v2/profile/update" in e.path for e in post_eps)

    # Check params
    user_ep = next((e for e in endpoints if "/api/v1/users" in e.path), None)
    assert user_ep is not None
    assert "page" in user_ep.params
    assert "limit" in user_ep.params

    # Check secrets
    secret_types = {s.type for s in secrets}
    assert "google_api_key" in secret_types
    assert "jwt_token" in secret_types

    # Check chunks
    assert "chunk-admin" in chunks


def test_analyze_local_js(tmp_path):
    js_file = tmp_path / "bundle.js"
    js_file.write_text(SAMPLE_JS)

    report = analyze_local_js(str(js_file))
    assert report.js_files_analyzed == 1
    assert len(report.endpoints) > 0
    assert len(report.secrets) > 0
    assert len(report.findings) > 0


class JsMockHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"""
            <html>
            <head>
                <script src="/static/app.bundle.js"></script>
                <script>
                    const localApi = "/api/internal/config";
                </script>
            </head>
            <body>SPA App</body>
            </html>
            """)
        elif self.path == "/static/app.bundle.js":
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
            self.end_headers()
            self.wfile.write(SAMPLE_JS.encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass


@pytest.fixture(scope="module")
def js_server():
    server = HTTPServer(("127.0.0.1", 0), JsMockHandler)
    host, port = server.server_address
    url = f"http://{host}:{port}/"
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    yield url
    server.shutdown()


@pytest.mark.anyio
async def test_analyze_target_js(js_server):
    report = await analyze_target_js(js_server)
    assert report.target == js_server
    assert report.js_files_analyzed >= 2
    assert len(report.endpoints) > 0
    assert len(report.secrets) > 0


def test_cli_js_command(js_server, tmp_path):
    res = run(["js", js_server], tmp_path)
    assert res.returncode == 0, res.stderr
    data = json.loads(res.stdout)
    assert data["target"] == js_server
    assert len(data["endpoints"]) > 0
    assert len(data["secrets"]) > 0


def test_cli_apis_alias(js_server, tmp_path):
    res = run(["apis", js_server], tmp_path)
    assert res.returncode == 0, res.stderr
    data = json.loads(res.stdout)
    assert len(data["endpoints"]) > 0
