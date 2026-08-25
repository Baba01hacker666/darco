from __future__ import annotations

import re
from urllib.parse import urljoin

JS_PATTERNS = [
    re.compile(
        r"""(?:fetch|axios\.(?:get|post|put|delete|patch|head))\s*\(\s*['"]([^'")\s]+)['"]"""
    ),
    re.compile(r"""new\s+WebSocket\s*\(\s*['"]([^'")\s]+)['"]"""),
    re.compile(r"""\.open\s*\(\s*['"][A-Za-z]+['"]\s*,\s*['"]([^'")\s]+)['"]"""),
    re.compile(r"""url\s*[:=]\s*['"]([^'")\s]+)['"]"""),
    re.compile(
        r"""['"](/(?:api|v\d|admin|internal|ws|graphql|rest)[^'"\s]*|\w+\.(?:php|asp|aspx|jsp|json))['"]"""
    ),
]

_SKIP = re.compile(
    r"^\$?\{|^data:|^javascript:|\.(css|png|jpe?g|gif|svg|ico|woff2?|ttf|map)$|^//[^/]|^blob:"
)


def extract_js_endpoints(js_text: str, base_url: str | None = None) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()
    for pattern in JS_PATTERNS:
        for match in pattern.finditer(js_text):
            raw = match.group(1) if match.lastindex else match.group(0)
            for candidate in _split_candidates(raw):
                if _SKIP.search(candidate):
                    continue
                if not candidate.startswith(("/", "http://", "https://")):
                    continue
                if candidate in seen:
                    continue
                seen.add(candidate)
                resolved = urljoin(base_url or "", candidate) if base_url else candidate
                found.append(resolved)
    return found


def _split_candidates(raw: str) -> list[str]:
    # handle template-ish or comma separated strings conservatively
    parts = re.split(r"[\s,]+", raw)
    return [p for p in parts if p]
