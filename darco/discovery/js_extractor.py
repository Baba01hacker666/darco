import re
from urllib.parse import parse_qsl, urljoin

from ..models import ApiEndpoint, JsSecret

# ------------------------------------------------------------------ Regex Rules
# 1. Direct HTTP client method calls
HTTP_CLIENT_REGEXES = [
    # fetch("/api/users", { method: "POST" })
    re.compile(
        r"""\bfetch\s*\(\s*[`'"]([^`'")\s]+)[`'"](?:\s*,\s*\{[^}]*method\s*:\s*['"]([A-Za-z]+)['"])?""",
        re.IGNORECASE,
    ),
    # axios.get('/api/users'), axios.post(...)
    re.compile(
        r"""\baxios\.(get|post|put|delete|patch|head|options)\s*\(\s*[`'"]([^`'")\s]+)[`'"]""",
        re.IGNORECASE,
    ),
    # axios({ method: 'post', url: '/api/users' })
    re.compile(
        r"""\baxios\s*\(\s*\{[^}]*url\s*:\s*[`'"]([^`'")\s]+)[`'"](?:[^}]*method\s*:\s*['"]([A-Za-z]+)['"])?""",
        re.IGNORECASE,
    ),
    # $.ajax({ url: '/api/...', type: 'POST' }) or $.get / $.post
    re.compile(
        r"""\$\.(?:ajax|get|post|getJSON)\s*\(\s*(?:[`'"]([^`'")\s]+)[`'"]|\{[^}]*url\s*:\s*[`'"]([^`'")\s]+)[`'"])""",
        re.IGNORECASE,
    ),
    # xhr.open("GET", "/api/...")
    re.compile(
        r"""\.(?:open)\s*\(\s*['"]([A-Za-z]+)['"]\s*,\s*[`'"]([^`'")\s]+)[`'"]""",
        re.IGNORECASE,
    ),
    # new WebSocket("ws://..." or "/ws")
    re.compile(r"""new\s+WebSocket\s*\(\s*[`'"]([^`'")\s]+)[`'"]""", re.IGNORECASE),
    # new EventSource("/events")
    re.compile(r"""new\s+EventSource\s*\(\s*[`'"]([^`'")\s]+)[`'"]""", re.IGNORECASE),
    # ky.get('/api/...'), superagent.get('/api/...')
    re.compile(
        r"""\b(?:ky|superagent|got|wretch)\.(get|post|put|delete|patch)\s*\(\s*[`'"]([^`'")\s]+)[`'"]""",
        re.IGNORECASE,
    ),
]

# 2. Path & Route Literal Patterns (LinkFinder style)
ROUTE_LITERAL_REGEX = re.compile(
    r"""(?:"|'|`)("""
    r"""/(?:api|v[0-9]|rest|graphql|oauth|auth|internal|admin|users?|account|payment|webhook|config|service|app|v1|v2|v3|v4)[a-zA-Z0-9_\-\./]*"""
    r"""|\bhttps?://[a-zA-Z0-9_\-\.]+/[a-zA-Z0-9_\-\./\?=&%#]*"""
    r"""|/[a-zA-Z0-9_\-\.]+\.(?:json|xml|yaml|yml|php|asp|aspx|jsp|action)"""
    r""")(?:"|'|`)""",
    re.IGNORECASE,
)

# 3. Template string routes with variables `/api/users/${id}/items` -> `/api/users/{id}/items`
TEMPLATE_ROUTE_REGEX = re.compile(
    r"""`(/api/[^`]+|https?://[^`]+)`""",
    re.IGNORECASE,
)

# 4. Webpack / Next.js / Vite chunk discovery patterns
WEBPACK_CHUNK_PATTERNS = [
    # __webpack_require__.e("chunkId") or .e(123)
    re.compile(r"""__webpack_require__\.e\s*\(\s*["']?([a-zA-Z0-9_\-]+)["']?\s*\)"""),
    # "/_next/static/chunks/..."
    re.compile(r"""['"](/_next/static/chunks/[^'"]+\.js)['"]"""),
    # "static/js/..." or "assets/..."
    re.compile(r"""['"]((?:static/js/|assets/|chunks/)[a-zA-Z0-9_\-\./]+\.js)['"]"""),
    # import("./chunk.js")
    re.compile(r"""import\s*\(\s*['"]([^'"]+\.js)['"]\s*\)"""),
]

# 5. Sensitive keys and tokens in frontend JS
SECRET_PATTERNS = [
    ("google_api_key", re.compile(r"""\b(AIza[0-9A-Za-z\-_]{35})\b""")),
    (
        "jwt_token",
        re.compile(
            r"""\b(eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]+)\b"""
        ),
    ),
    (
        "bearer_token",
        re.compile(r"""['"]Bearer\s+([A-Za-z0-9\-_\.=]{20,})['"]""", re.IGNORECASE),
    ),
    ("aws_access_key", re.compile(r"""\b(AKIA[0-9A-Z]{16})\b""")),
    ("stripe_key", re.compile(r"""\b((?:pk|sk)_(?:test|live)_[0-9a-zA-Z]{24,})\b""")),
    (
        "firebase_url",
        re.compile(r"""['"](https://[a-zA-Z0-9_-]+\.firebaseio\.com)['"]"""),
    ),
    (
        "internal_ip",
        re.compile(
            r"""\b(https?://(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})(?::\d+)?[^'"\s]*)"""
        ),
    ),
]

_EXT_EXCLUDE = re.compile(
    r"\.(css|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|otf|map|mp4|webm|webp|avif)$",
    re.IGNORECASE,
)


def _clean_path(raw: str) -> str:
    # Convert JS template `${var}` into `{var}`
    cleaned = re.sub(r"\$\{\s*([a-zA-Z0-9_]+)\s*\}", r"{\1}", raw)
    return cleaned.strip()


def _extract_params_from_query(url_or_path: str) -> list[str]:
    params = []
    if "?" in url_or_path:
        query = url_or_path.split("?", 1)[1]
        for k, _ in parse_qsl(query, keep_blank_values=True):
            if k and k not in params:
                params.append(k)
    return params


def extract_detailed_js_endpoints(
    js_text: str, base_url: str | None = None, source_name: str = "inline"
) -> tuple[list[ApiEndpoint], list[JsSecret], list[str]]:
    """Extract detailed API endpoints, GraphQL endpoints, parameters, secrets, and chunks from JS source."""
    endpoints_map: dict[str, ApiEndpoint] = {}
    secrets: list[JsSecret] = []
    chunks: list[str] = []
    seen_secrets = set()

    # 1. HTTP client calls with explicit methods
    for regex in HTTP_CLIENT_REGEXES:
        for match in regex.finditer(js_text):
            groups = match.groups()
            url_cand = None
            method = "GET"

            if len(groups) == 2:
                if groups[0] and groups[0].upper() in (
                    "GET",
                    "POST",
                    "PUT",
                    "DELETE",
                    "PATCH",
                    "HEAD",
                    "OPTIONS",
                ):
                    method = groups[0].upper()
                    url_cand = groups[1]
                else:
                    url_cand = groups[0]
                    if groups[1]:
                        method = groups[1].upper()
            elif len(groups) == 1:
                url_cand = groups[0]

            if not url_cand or _EXT_EXCLUDE.search(url_cand):
                continue

            cleaned = _clean_path(url_cand)
            if not cleaned.startswith(("/", "http://", "https://")):
                continue

            full_url = urljoin(base_url or "", cleaned) if base_url else cleaned
            params = _extract_params_from_query(cleaned)
            is_gql = "graphql" in cleaned.lower()

            key = (method, cleaned.split("?", 1)[0])
            if key not in endpoints_map:
                endpoints_map[key] = ApiEndpoint(
                    path=cleaned,
                    full_url=full_url,
                    method=method,
                    params=params,
                    source_js=source_name,
                    is_graphql=is_gql,
                    context_snippet=match.group(0)[:120],
                )

    # 2. Template string routes
    for match in TEMPLATE_ROUTE_REGEX.finditer(js_text):
        raw = match.group(1)
        cleaned = _clean_path(raw)
        if _EXT_EXCLUDE.search(cleaned):
            continue
        if cleaned.startswith(("/", "http://", "https://")):
            full_url = urljoin(base_url or "", cleaned) if base_url else cleaned
            params = _extract_params_from_query(cleaned)
            key = ("GET", cleaned.split("?", 1)[0])
            if key not in endpoints_map:
                endpoints_map[key] = ApiEndpoint(
                    path=cleaned,
                    full_url=full_url,
                    method="GET",
                    params=params,
                    source_js=source_name,
                    is_graphql="graphql" in cleaned.lower(),
                    context_snippet=match.group(0)[:120],
                )

    # 3. Route literals & REST path regex
    for match in ROUTE_LITERAL_REGEX.finditer(js_text):
        raw = match.group(1)
        if _EXT_EXCLUDE.search(raw):
            continue
        cleaned = _clean_path(raw)
        if not cleaned.startswith(("/", "http://", "https://")):
            continue
        full_url = urljoin(base_url or "", cleaned) if base_url else cleaned
        params = _extract_params_from_query(cleaned)
        key = ("GET", cleaned.split("?", 1)[0])
        if key not in endpoints_map:
            endpoints_map[key] = ApiEndpoint(
                path=cleaned,
                full_url=full_url,
                method="GET",
                params=params,
                source_js=source_name,
                is_graphql="graphql" in cleaned.lower(),
                context_snippet=match.group(0)[:120],
            )

    # 4. Webpack / Next.js chunks
    for regex in WEBPACK_CHUNK_PATTERNS:
        for match in regex.finditer(js_text):
            chunk = match.group(1)
            if chunk and chunk not in chunks:
                chunks.append(chunk)

    # 5. Secrets and sensitive tokens
    for sec_type, sec_regex in SECRET_PATTERNS:
        for match in sec_regex.finditer(js_text):
            val = match.group(1)
            if val and val not in seen_secrets:
                seen_secrets.add(val)
                secrets.append(
                    JsSecret(
                        type=sec_type,
                        value=val,
                        source_js=source_name,
                        evidence=match.group(0)[:100],
                    )
                )

    return list(endpoints_map.values()), secrets, chunks


def extract_js_endpoints(js_text: str, base_url: str | None = None) -> list[str]:
    """Backward-compatible endpoint extraction returning list of resolved string URLs."""
    endpoints, _, _ = extract_detailed_js_endpoints(js_text, base_url=base_url)
    return [ep.full_url or ep.path for ep in endpoints]
