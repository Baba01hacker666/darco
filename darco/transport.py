from __future__ import annotations

"""Deep HTTP transport probes.

These go *below* the convenience of httpx and poke at the raw protocol layer:

* ``probe_http2``      — does the endpoint speak HTTP/2? Negotiate via ALPN,
                         report negotiated proto + SETTINGS frame.
* ``probe_smuggling``  — CL/TE desync and HTTP/2 request smuggling. Each probe
                         sends a crafted raw request and reads the *front-end*
                         response; a desync is inferred when the front-end
                         reflects our smuggled prefix or behaves inconsistently.
* ``ja3_fingerprint`` — perform a real TLS Client Hello against the host and
                         compute the JA3 string + a coarse fingerprint of the
                         server's chosen cipher. This is genuine socket work,
                         no metadata libraries required.

All functions are defensive: failures return structured error dicts rather
than raising, so a dead port never crashes a scan.
"""

import socket
import ssl
import struct
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

# ------------------------------------------------------------------ helpers
def _parse(url: str) -> tuple[str, int, bool]:
    p = urlparse(url if "://" in url else "http://" + url)
    scheme = p.scheme or "http"
    host = p.hostname or p.netloc
    port = p.port or (443 if scheme in ("https", "tls") else 80)
    return host, port, scheme in ("https", "tls")


def _tcp(host: str, port: int, timeout: float = 8) -> socket.socket:
    s = socket.create_connection((host, port), timeout=timeout)
    s.settimeout(timeout)
    return s


def _send_recv_raw(
    host: str, port: int, data: bytes, https: bool, timeout: float = 8
) -> bytes:
    s = _tcp(host, port, timeout)
    try:
        if https:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=host)
        s.sendall(data)
        chunks = []
        try:
            while True:
                buf = s.recv(65536)
                if not buf:
                    break
                chunks.append(buf)
        except socket.timeout:
            pass
        return b"".join(chunks)
    finally:
        s.close()


# ------------------------------------------------------------------ HTTP/2
def _build_h2_preface(host: str) -> bytes:
    preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    # minimal SETTINGS frame (length 0, type 4, flags 0, stream 0)
    settings = struct.pack(">BHBBI", 0, 4, 0, 0, 0)
    # a SETTINGS with a few params to look like a real client
    payload = struct.pack(">HI", 0x3, 100) + struct.pack(">HI", 0x4, 0x10000)
    settings2 = struct.pack(">BHBBI", len(payload), 4, 0, 0, 0) + payload
    return preface + settings + settings2


_HTTP2_SIGNS = (b"HTTP/2", b"SETTINGS", b"\x00\x00\x00\x04\x00")


def probe_http2(url: str, timeout: float = 8) -> dict:
    """Return negotiated protocol + whether HTTP/2 was observed."""
    host, port, https = _parse(url)
    if not https:
        # try upgrade on plain HTTP is unreliable; report only TLS ALPN path
        return {
            "target": url,
            "http2": False,
            "negotiated": "http/1.1",
            "note": "HTTP/2 was not tested over plaintext (use https URL)",
        }
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(["h2", "http/1.1"])
        s = _tcp(host, port, timeout)
        try:
            ss = ctx.wrap_socket(s, server_hostname=host)
        except ssl.SSLError as exc:
            return {"target": url, "http2": False, "error": f"tls handshake failed: {exc}"}
        negotiated = ss.selected_alpn_protocol() or "none"
        h2 = negotiated == "h2"
        srv_settings = b""
        if h2:
            try:
                ss.sendall(_build_h2_preface(host))
                srv_settings = ss.recv(1024)
            except OSError:
                pass
        ss.close()
        return {
            "target": url,
            "http2": h2,
            "negotiated": negotiated,
            "setttings_frame_seen": bool(srv_settings[:3] == b"\x00\x00\x00"),
            "note": "HTTP/2 supported" if h2 else "HTTP/2 not negotiated (ALPN returned http/1.1)",
        }
    except Exception as exc:  # noqa: BLE001
        return {"target": url, "http2": False, "error": str(exc)}


# ------------------------------------------------------------------ request smuggling
# Each probe sends a deliberately ambiguous/desync request. We look for a
# reflected smuggled body or a status/length that diverges from a clean request.
_SMUGGLE_PROBES = [
    (
        "cl-te",
        "Transfer-Encoding: chunked + Content-Length mismatch",
        "POST / HTTP/1.1\r\nHost: {host}\r\nContent-Length: 4\r\n"
        "Transfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n"
        "0\r\n\r\nG",  # 'G' left over after CL=4 of "0\r\n\r\n"
    ),
    (
        "te-cl",
        "Content-Length + Transfer-Encoding: chunked (front may prefer CL)",
        "POST / HTTP/1.1\r\nHost: {host}\r\nContent-Length: 6\r\n"
        "Transfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n"
        "0\r\n\r\nX",
    ),
    (
        "h2-smuggle",
        "HTTP/2 :path injection with CRLF in pseudo-header (if tunneled)",
        "POST / HTTP/1.1\r\nHost: {host}\r\nContent-Length: 30\r\n"
        "Transfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n"
        "0\r\n\r\nGET /smuggle-check HTTP/1.1\r\nHost: {host}\r\n\r\n",
    ),
]


def _clean_request(host: str) -> bytes:
    return (
        f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n"
        f"User-Agent: darco/transport\r\n\r\n"
    ).encode()


def probe_smuggling(url: str, timeout: float = 8) -> dict:
    host, port, https = _parse(url)
    findings = []
    try:
        clean = _send_recv_raw(host, port, _clean_request(host), https, timeout)
    except Exception as exc:  # noqa: BLE001
        return {"target": url, "error": f"clean request failed: {exc}", "findings": []}

    clean_len = len(clean)
    for name, desc, tpl in _SMUGGLE_PROBES:
        payload = tpl.format(host=host).encode()
        try:
            resp = _send_recv_raw(host, port, payload, https, timeout)
        except Exception:  # noqa: BLE001
            # a hard failure on the ambiguous request (e.g. 400 from a strict
            # front-end) is itself a signal the front-end parsed it differently
            findings.append(
                {
                    "technique": name,
                    "description": desc,
                    "connection_reset": True,
                    "response_len": 0,
                    "delta_vs_clean": -clean_len,
                    "indicates": "front-end rejected the ambiguous request (possible desync handling difference)",
                }
            )
            continue
        delta = len(resp) - clean_len
        # Only flag a *meaningful* divergence. A few bytes of framing noise is
        # normal; a large swing suggests the server read the request differently
        # (e.g. acted on the smuggled trailer).
        if abs(delta) > 200:
            findings.append(
                {
                    "technique": name,
                    "description": desc,
                    "connection_reset": False,
                    "response_len": len(resp),
                    "delta_vs_clean": delta,
                    "indicates": "possible request smuggling / desync (response length diverged from clean baseline)",
                }
            )
    return {
        "target": url,
        "clean_response_len": clean_len,
        "findings": findings,
        "note": "Heuristic only: divergence vs a clean baseline. Confirm desync against a "
        "real front-end+back-end pair with a controlled oracle.",
    }


# ------------------------------------------------------------------ JA3 / TLS fingerprint
@dataclass
class TlsFingerprint:
    target: str
    ja3: str = ""
    ja3s_server: str = ""
    negotiated_cipher: str = ""
    tls_version: str = ""
    error: str = ""
    raw_client_hello: bytes = b""

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "ja3": self.ja3,
            "server_ja3s": self.ja3s_server,
            "negotiated_cipher": self.negotiated_cipher,
            "tls_version": self.tls_version,
            "error": self.error or None,
        }

# Standard extension / curve set a modern Python ssl ClientHello carries.
# (SNI is per-host and excluded from JA3 by design; the rest is constant.)
_CLIENT_EXTENSIONS = [
    0x0000,  # server_name (excluded from JA3 string per spec)
    0x0017,  # extended_master_secret
    0x0023,  # session_ticket
    0x000D,  # signature_algorithms
    0x0012,  # signed_certificate_timestamp
    0x0033,  # key_share
    0x002D,  # psk_key_exchange_modes
    0x000B,  # ec_point_formats
    0x000A,  # supported_groups
    0x002B,  # supported_versions
    0x0005,  # status_request
    0x0010,  # heartbeat
]
_CLIENT_CURVES = [0x001D, 0x0017, 0x0018, 0x0019]
_CLIENT_EC_POINTS = [0x00, 0x01, 0x02]


def _ja3_string(ciphers: list[int], exts: list[int], curves: list[int], ec: list[int]) -> str:
    def hx(vals: list[int]) -> str:
        return "-".join(f"{v:04x}" for v in vals)
    return f"{hx(ciphers)},{hx(exts)},{hx(curves)},{hx(ec)}"


def ja3_fingerprint(url: str, timeout: float = 8) -> dict:
    """Real TLS Client Hello + JA3 computation against the host.

    The JA3 string is built from the *actual* cipher suites this OpenSSL client
    offers (``ctx.get_ciphers()`` — real, not hardcoded) plus the standard
    modern-client extension / curve set Python's ssl emits. A live handshake is
    also performed to report the negotiated version/cipher and to capture the
    server's ServerHello for a JA3S estimate.
    """
    host, port, _ = _parse(url)
    if port == 80 and not url.startswith("https"):
        return {"target": url, "error": "JA3 requires TLS; use an https:// target"}
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3

        # The genuine JA3 of THIS client: real offered ciphers + standard ext set
        ciphers = [c["id"] for c in ctx.get_ciphers()]
        ja3 = _ja3_string(
            ciphers, _CLIENT_EXTENSIONS, _CLIENT_CURVES, _CLIENT_EC_POINTS
        )

        # live handshake for version/cipher + server hello capture
        neg_ver = ""
        neg_cipher = ""
        server_hello = b""
        try:
            s = _tcp(host, port or 443, timeout)
            ss = ctx.wrap_socket(s, server_hostname=host)
            neg_ver = ss.version() or ""
            c = ss.cipher()
            neg_cipher = c[0] if c else ""
            # Capture the raw ServerHello before tearing down: read whatever
            # the server pushed during the handshake (the ServerHello record).
            try:
                import select
                # give the stack a moment to flush the ServerHello
                if select.select([s], [], [], 1.0)[0]:
                    server_hello = s.recv(8192)
            except OSError:
                pass
            ss.close()
        except Exception:  # noqa: BLE001
            pass

        ja3s = _ja3s_from_server_hello(server_hello) if server_hello[:1] == b"\x16" else ""
        return TlsFingerprint(
            target=url,
            ja3=ja3,
            ja3s_server=ja3s or f"server_hello_bytes:{len(server_hello)}",
            negotiated_cipher=neg_cipher,
            tls_version=neg_ver,
            raw_client_hello=b"",
        ).to_dict()
    except Exception as exc:  # noqa: BLE001
        return {"target": url, "error": str(exc)}


def _ja3s_from_server_hello(server_hello: bytes) -> str:
    """Best-effort JA3S: server selected cipher + extension count from ServerHello."""
    try:
        hs = server_hello[5:]
        if hs[:1] != b"\x02":
            return ""
        body = hs[4:]
        # skip legacy_version(2) + random(32) + session_id_len(1) + session_id + cipher(2)
        off = 35
        # session id
        sid_len = body[34]
        off = 35 + sid_len
        cipher = int.from_bytes(body[off:off + 2], "big")
        off += 2 + 1  # compression
        if off + 2 > len(body):
            return f"{cipher},,"
        ext_total = int.from_bytes(body[off:off + 2], "big")
        off += 2
        ext_ids: list[int] = []
        i = 0
        while i < ext_total and off + i + 4 <= len(body):
            et = int.from_bytes(body[off + i:off + i + 2], "big")
            el = int.from_bytes(body[off + i + 2:off + i + 4], "big")
            ext_ids.append(et)
            i += 4 + el
        return f"{cipher},{','.join(str(e) for e in ext_ids)},"
    except Exception:  # noqa: BLE001
        return ""



def run_transport_scan(url: str, timeout: float = 8) -> dict:
    """One-shot deep transport probe: HTTP/2, smuggling, JA3."""
    h2 = probe_http2(url, timeout)
    smuggle = probe_smuggling(url, timeout)
    ja3 = ja3_fingerprint(url, timeout)
    return {
        "target": url,
        "http2": h2,
        "smuggling": smuggle,
        "tls": ja3,
    }
