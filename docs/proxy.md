# Record-Only Proxy

`darco proxy` runs a **record-only forward HTTP proxy**. Its job: capture
traffic (from a browser, agent, or curl `-x`) into the workspace history and
session — the Burp "passive capture" workflow. v1 does **not** intercept or
mutate on the fly.

Module: `darco/proxy.py`.

## Design

```
 client ──▶ ProxyServer ──▶ engine.execute() ──▶ upstream target
                │               │
                └── record into workspace history + session
```

- **`ProxyServer`** runs an `asyncio` server on its own thread with a private
  event loop (`start()` returns the bound port — `--port 0` picks an ephemeral
  port). `stop()` signals the loop via `call_soon_threadsafe`.
- **HTTP flows** are built into a `Request` (`source="proxy"`,
  `follow_redirects=False`, raw body preserved byte-for-byte through
  `body_encoding="latin-1"`) and forwarded via
  `engine.execute()` inside `asyncio.to_thread` (the engine is sync). The
  **raw** `httpx.Response` bytes are written back to the client untouched;
  the parsed model is recorded into history.
- **HTTPS (CONNECT)** is tunneled, not decrypted:
  1. reply `200 Connection Established` (without closing the socket),
  2. open a raw `asyncio` connection to the authority,
  3. `_relay()` pumps bytes in both directions until either side closes,
  4. record a history entry with `error="tunneled (CONNECT); traffic not
     decrypted in v1"`.

### Response serialization (`_serialize`)

For HTTP flows the raw response is re-serialized from the httpx response:

- status line + reason phrase,
- headers **minus hop-by-hop** (`connection`, `keep-alive`,
  `transfer-encoding`, `proxy-connection`, `upgrade`, `proxy-authenticate`,
  `proxy-authorization`),
- an explicit `Content-Length`,
- `Connection: close` (v1 is one-request-per-connection),
- raw body bytes.

### Errors

- Upstream `httpx.HTTPError` → `502 Bad Gateway` to the client.
- Malformed request line → `400 Bad Request`.
- Failed CONNECT → `502 Bad Gateway`.

## Behavior notes

- Every flow (including `favicon.ico`) is recorded with a sequential id and
  updates `session.json` (Set-Cookie + CSRF capture) — after browsing through
  the proxy, `darco send` replays are automatically authenticated.
- Because responses are forwarded byte-for-byte, binary content is preserved
  for the client even though the recorded `Response.body` is text-decoded.
- TLS interception (decrypting HTTPS) requires replacing the tunnel with a
  mitmproxy-style CA — deliberately out of scope for v1; the seam is
  `_handle_connect` / `_relay` if you want to add it.
