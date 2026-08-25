import socket

import httpx

from darco.proxy import ProxyServer


def test_proxy_records_http_flow(app, workspace):
    server = ProxyServer(workspace, workspace.load_session(), port=0)
    port = server.start()
    try:
        with httpx.Client(
            proxy=f"http://127.0.0.1:{port}", trust_env=False, timeout=10
        ) as client:
            resp = client.get(f"{app}/echo", headers={"X-Proxy-Test": "1"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["method"] == "GET"
        assert data["headers"]["X-Proxy-Test"] == "1"
        records = workspace.list_records()
        assert any(r.request.source == "proxy" for r in records)
    finally:
        server.stop()


def test_proxy_connect_tunnel_recorded(app, workspace):
    server = ProxyServer(workspace, workspace.load_session(), port=0)
    port = server.start()
    try:
        fixture_port = int(app.rsplit(":", 1)[1])
        s = socket.create_connection(("127.0.0.1", port), timeout=5)
        s.sendall(
            f"CONNECT 127.0.0.1:{fixture_port} HTTP/1.1\r\nHost: 127.0.0.1:{fixture_port}\r\n\r\n".encode()
        )
        data = b""
        while b"\r\n\r\n" not in data:
            data += s.recv(4096)
        assert data.startswith(b"HTTP/1.1 200")
        s.sendall(
            f"GET /echo HTTP/1.1\r\nHost: 127.0.0.1:{fixture_port}\r\nConnection: close\r\n\r\n".encode()
        )
        chunks = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            chunks += chunk
        s.close()
        assert b'"method": "GET"' in chunks
        assert any(r.error and "tunneled" in r.error for r in workspace.list_records())
    finally:
        server.stop()
