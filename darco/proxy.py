from __future__ import annotations

import asyncio
import threading
from datetime import datetime, timezone
from typing import Callable

import httpx

from .engine import execute
from .models import BodyType, HistoryRecord, NameValue, Request, Response, SessionState
from .workspace import Workspace

HOP_BY_HOP = {
    "connection",
    "keep-alive",
    "transfer-encoding",
    "proxy-connection",
    "upgrade",
    "proxy-authenticate",
    "proxy-authorization",
}


class ProxyServer:
    """Record-only forward HTTP proxy.

    Every HTTP flow is forwarded through the darco engine (so it lands in
    workspace history and updates session state) and the raw response bytes
    are returned to the client untouched. HTTPS is tunneled (CONNECT) and
    recorded as a tunnel event, not decrypted.
    """

    def __init__(
        self,
        workspace: Workspace,
        session: SessionState,
        *,
        host: str = "127.0.0.1",
        port: int = 8080,
        base_headers: list[NameValue] | None = None,
    ):
        self.workspace = workspace
        self.session = session
        self.host = host
        self.port = port
        self.base_headers = base_headers or []
        self._stop: asyncio.Event | None = None
        self._started = threading.Event()
        self._thread: threading.Thread | None = None
        self.bound_port: int | None = None

    # ------------------------------------------------------------------ lifecycle
    def start(self) -> int:
        self._thread = threading.Thread(target=self._run, daemon=True, name="darco-proxy")
        self._thread.start()
        self._started.wait(timeout=10)
        if not self._started.is_set():
            raise RuntimeError("proxy failed to start")
        return self.bound_port  # type: ignore[return-value]

    def stop(self) -> None:
        if self._stop and self._thread:
            loop = getattr(self._thread, "_loop", None)
            if loop:
                loop.call_soon_threadsafe(self._stop.set)
            self._thread.join(timeout=5)

    def _run(self) -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        self._thread._loop = loop  # type: ignore[attr-defined]
        try:
            loop.run_until_complete(self._main())
        finally:
            loop.close()

    async def _main(self) -> None:
        self._stop = asyncio.Event()
        server = await asyncio.start_server(self._on_client, self.host, self.port)
        self.bound_port = server.sockets[0].getsockname()[1]
        self._started.set()
        try:
            await self._stop.wait()
        finally:
            server.close()
            await server.wait_closed()

    # ------------------------------------------------------------------ connection handling
    async def _on_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            request_line, headers = await _read_head(reader)
            parts = request_line.split(" ")
            if len(parts) < 3:
                await _write_raw(writer, b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                return
            method, target = parts[0].upper(), parts[1]
            if method == "CONNECT":
                await self._handle_connect(reader, writer, target)
            else:
                await self._handle_http(reader, writer, method, target, headers)
        except (asyncio.IncompleteReadError, ConnectionError, asyncio.LimitOverrunError):
            pass
        finally:
            try:
                writer.close()
            except Exception:  # noqa: BLE001
                pass

    async def _handle_http(self, reader, writer, method, target, headers) -> None:
        content_length = 0
        for name, value in headers:
            if name.lower() == "content-length":
                try:
                    content_length = max(0, int(value))
                except ValueError:
                    content_length = 0
        body = await reader.readexactly(content_length) if content_length else b""

        host = next((v for k, v in headers if k.lower() == "host"), None)
        if target.startswith(("http://", "https://")):
            url = target
        elif host:
            scheme = "https" if ":443" in host or host.endswith(":443") else "http"
            url = f"{scheme}://{host}{target}"
        else:
            await _write_raw(writer, b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            return

        req = Request(
            method=method,
            url=url,
            headers=[NameValue(name=n, value=v) for n, v in headers],
            body_type=BodyType.RAW if body else BodyType.NONE,
            body_raw=body.decode("latin-1") if body else "",
            body_encoding="latin-1",
            follow_redirects=False,
            source="proxy",
        )
        try:
            raw_resp = await asyncio.to_thread(self._forward_and_record, req)
        except httpx.HTTPError as exc:
            await _write_raw(
                writer,
                f"HTTP/1.1 502 Bad Gateway\r\nContent-Length: {len(str(exc))}\r\nConnection: close\r\n\r\n{exc}".encode("utf-8"),
            )
            return
        await _write_raw(writer, _serialize(raw_resp))

    async def _handle_connect(self, reader, writer, authority: str) -> None:
        host, _, port_str = authority.partition(":")
        port = int(port_str or "443")
        try:
            upstream_r, upstream_w = await asyncio.open_connection(host, port)
        except OSError as exc:
            await _write_raw(writer, f"HTTP/1.1 502 Bad Gateway\r\nContent-Length: {len(str(exc))}\r\n\r\n".encode("utf-8"))
            return
        await _write_raw(writer, b"HTTP/1.1 200 Connection Established\r\n\r\n", close=False)
        await asyncio.to_thread(self._record_tunnel, authority)
        await _relay(reader, writer, upstream_r, upstream_w)

    # ------------------------------------------------------------------ recording
    def _forward_and_record(self, req: Request) -> httpx.Response:
        raw, model, session = execute(req, self.session, base_headers=self.base_headers)
        record = HistoryRecord(
            id=self.workspace.next_id(),
            ts=datetime.now(timezone.utc).isoformat(),
            request=req,
            response=model,
        )
        self.workspace.add_history(record)
        self.workspace.save_session(session)
        return raw

    def _record_tunnel(self, authority: str) -> None:
        req = Request(method="CONNECT", url=f"https://{authority}", source="proxy")
        record = HistoryRecord(
            id=self.workspace.next_id(),
            ts=datetime.now(timezone.utc).isoformat(),
            request=req,
            error="tunneled (CONNECT); traffic not decrypted in v1",
        )
        self.workspace.add_history(record)


# ------------------------------------------------------------------ helpers
async def _read_head(reader: asyncio.StreamReader) -> tuple[str, list[tuple[str, str]]]:
    data = await reader.readuntil(b"\r\n\r\n")
    text = data.decode("latin-1")
    lines = text.split("\r\n")
    request_line = lines[0]
    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        if not line:
            continue
        name, _, value = line.partition(":")
        headers.append((name.strip(), value.strip()))
    return request_line, headers


async def _write_raw(writer: asyncio.StreamWriter, data: bytes, *, close: bool = True) -> None:
    writer.write(data)
    await writer.drain()
    if close:
        try:
            writer.close()
        except Exception:  # noqa: BLE001
            pass


def _serialize(raw: httpx.Response) -> bytes:
    status_line = f"HTTP/1.1 {raw.status_code} {raw.reason_phrase}\r\n".encode("latin-1")
    header_lines: list[bytes] = []
    for name, value in raw.headers.items():
        if name.lower() in HOP_BY_HOP:
            continue
        header_lines.append(f"{name}: {value}\r\n".encode("latin-1"))
    body = raw.content
    header_lines.append(f"Content-Length: {len(body)}\r\n".encode("latin-1"))
    header_lines.append(b"Connection: close\r\n\r\n")
    return status_line + b"".join(header_lines) + body


async def _relay(
    client_r: asyncio.StreamReader, client_w: asyncio.StreamWriter,
    upstream_r: asyncio.StreamReader, upstream_w: asyncio.StreamWriter,
) -> None:
    async def pump(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> None:
        try:
            while True:
                chunk = await src.read(65536)
                if not chunk:
                    break
                dst.write(chunk)
                await dst.drain()
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        finally:
            try:
                dst.close()
            except Exception:  # noqa: BLE001
                pass

    t1 = asyncio.create_task(pump(client_r, upstream_w))
    t2 = asyncio.create_task(pump(upstream_r, client_w))
    await asyncio.gather(t1, t2, return_exceptions=True)
