import json
import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from click.testing import CliRunner

from darco.cli import cli
from darco.models import Request, SessionState
from darco.upload import audit_file_upload
from darco.workspace import Workspace


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


class UploadMockHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("latin-1")

        if "darco_test" in body:
            # Emulate accepting the upload and returning a file link
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status": "uploaded", "url": "/uploads/test.svg"}')
        else:
            self.send_response(400)
            self.end_headers()

    def do_GET(self):
        if self.path.startswith("/uploads/"):
            # Serve the SVG file
            self.send_response(200)
            self.send_header("Content-Type", "image/svg+xml")
            self.end_headers()
            self.wfile.write(
                b'<svg xmlns="http://www.w3.org/2000/svg"><text>test</text></svg>'
            )
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass


@pytest.fixture(scope="module")
def upload_server():
    server = HTTPServer(("127.0.0.1", 0), UploadMockHandler)
    host, port = server.server_address
    url = f"http://{host}:{port}/api/upload"
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    yield url
    server.shutdown()


def test_audit_file_upload_svg_and_html(upload_server):
    req = Request(method="POST", url=upload_server)
    session = SessionState()

    result = audit_file_upload(req, session=session, file_field="file")
    assert result.target == upload_server
    assert result.tests_run > 0
    assert len(result.accepted_formats) > 0
    assert any(f.vulnerability_type == "svg_stored_xss" for f in result.findings)
    assert any(f.vulnerability_type == "html_stored_xss" for f in result.findings)


def test_cli_upload_command(upload_server, tmp_path):
    res = run(
        [
            "upload",
            upload_server,
            "-p",
            "file",
            "-H",
            "X-Custom: test",
            "-C",
            "session=123",
        ],
        tmp_path,
    )
    assert res.returncode == 0, res.stderr
    data = json.loads(res.stdout)
    assert data["target"] == upload_server
    assert data["tested_field"] == "file"
    assert len(data["findings"]) > 0


def test_cli_upload_save(upload_server, tmp_path):
    old_cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        ws = Workspace.create(upload_server)
        res = run(["upload", upload_server, "--save"], tmp_path)
        assert res.returncode == 0, res.stderr
        findings = ws.load_findings()
        assert len(findings) > 0
    finally:
        os.chdir(old_cwd)
