"""Custom matcher / extractor type registry for attack templates.

The template engine natively understands the core Nuclei-compatible types —
matchers ``word`` / ``regex`` / ``status`` / ``size`` / ``dsl`` and extractors
``regex`` / ``kval`` / ``json``. Any other type named in a template is
resolved through this registry, so authors can teach darco brand-new
matching semantics without touching the engine.

Three ways to register a custom type:

1. Python API::

       from darco.templates.custom import register_matcher_type

       @register_matcher_type("sha256")
       def match_sha256(matcher, resp, elapsed_ms=0.0):
           ...return (bool, [matched_items])

2. Scan plugins — :meth:`darco.plugins.ScanPlugin.template_matcher_types`
   and ``template_extractor_types`` are synced into these registries when a
   plugin registers (see the built-in ``timing`` plugin for the ``delay``
   matcher).

3. External plugin files — ``*.py`` files dropped in a directory passed via
   ``darco template run --plugin-dir DIR``, ``darco sql --plugin-dir DIR``,
   or the ``DARCO_PLUGIN_PATH`` environment variable.

Matcher signature: ``(matcher, resp, elapsed_ms) -> (matched, items)``.
Extractor signature: ``(extractor, resp) -> {name: [values]}``.
"""

from __future__ import annotations

import binascii
import re
import xml.etree.ElementTree as ET

import httpx

from ..errors import DarcoError
from .models import TemplateExtractor, TemplateMatcher

# --------------------------------------------------------------------- registry

_MATCHER_TYPES: dict[str, dict] = {}
_EXTRACTOR_TYPES: dict[str, dict] = {}


def register_matcher_type(name, fn=None, *, source="python", description=""):
    """Register a custom matcher type. Usable directly or as a decorator."""

    def _wrap(f):
        if callable(name):  # used as @register_matcher_type (name = fn)
            raise DarcoError(
                "register_matcher_type requires a type name: @register_matcher_type('mytype')"
            )
        _MATCHER_TYPES[name] = {
            "fn": f,
            "source": source,
            "description": description or (f.__doc__ or "").strip().split("\n")[0],
        }
        return f

    return _wrap(fn) if fn else _wrap


def register_extractor_type(name, fn=None, *, source="python", description=""):
    """Register a custom extractor type. Usable directly or as a decorator."""

    def _wrap(f):
        if callable(name):
            raise DarcoError(
                "register_extractor_type requires a type name: @register_extractor_type('mytype')"
            )
        _EXTRACTOR_TYPES[name] = {
            "fn": f,
            "source": source,
            "description": description or (f.__doc__ or "").strip().split("\n")[0],
        }
        return f

    return _wrap(fn) if fn else _wrap


def get_matcher_type(name: str):
    entry = _MATCHER_TYPES.get(name)
    return entry["fn"] if entry else None


def get_extractor_type(name: str):
    entry = _EXTRACTOR_TYPES.get(name)
    return entry["fn"] if entry else None


def registered_matcher_types() -> dict[str, dict]:
    return {k: dict(v, fn=None) for k, v in _MATCHER_TYPES.items()}


def registered_extractor_types() -> dict[str, dict]:
    return {k: dict(v, fn=None) for k, v in _EXTRACTOR_TYPES.items()}


# ------------------------------------------------------------------ xml helpers


def _xml_root(resp: httpx.Response):
    """Parse the body; returns an Element or None on malformed XML.

    The document is wrapped in a synthetic super-root so template authors can
    use natural document paths like ``/users/user`` regardless of nesting.
    """
    try:
        # Parsing response XML for xpath matching is intentional — this is the
        # template xpath matcher. Response content is attacker-controlled in a
        # scan context; no external entities are involved.
        doc = ET.fromstring(resp.text or "")  # nosec B314
    except ET.ParseError:
        return None
    wrapper = ET.Element("__darco_root__")
    wrapper.append(doc)
    return wrapper


def _findall(root, expr: str):
    return root.findall(expr.lstrip("/"))


# ------------------------------------------------------- bundled custom matchers


@register_matcher_type(
    "binary",
    source="darco",
    description="Hex-encoded byte patterns matched against the raw response",
)
def _match_binary(
    matcher: TemplateMatcher, resp: httpx.Response, elapsed_ms: float = 0.0
):
    target = matcher.part if matcher.part == "header" else ""
    raw = (
        ("\r\n".join(f"{k}: {v}" for k, v in resp.headers.items())).encode("utf-8")
        if target == "header"
        else resp.content or b""
    )
    hits = []
    for hex_pat in matcher.binary:
        try:
            needle = binascii.unhexlify(re.sub(r"\s+", "", hex_pat))
        except (binascii.Error, ValueError):
            continue
        if needle and needle in raw:
            hits.append(hex_pat)
    if matcher.condition.lower() == "and":
        ok = bool(matcher.binary) and len(hits) == len(matcher.binary)
    else:
        ok = len(hits) > 0
    return ok, hits


@register_matcher_type(
    "xpath",
    source="darco",
    description="XPath expressions evaluated against an XML response body",
)
def _match_xpath(
    matcher: TemplateMatcher, resp: httpx.Response, elapsed_ms: float = 0.0
):
    root = _xml_root(resp)
    if root is None:
        return False, []
    hits = []
    for expr in matcher.xpath:
        try:
            # ElementTree only understands relative paths.
            found = _findall(root, expr)
        except (ET.ParseError, SyntaxError):
            continue
        if found:
            hits.append(expr)
    if matcher.condition.lower() == "and":
        ok = bool(matcher.xpath) and len(hits) == len(matcher.xpath)
    else:
        ok = len(hits) > 0
    return ok, hits


@register_matcher_type(
    "json",
    source="darco",
    description="JSON key paths (dot notation); entries may pin values with path=value",
)
def _match_json(
    matcher: TemplateMatcher, resp: httpx.Response, elapsed_ms: float = 0.0
):
    try:
        data = resp.json()
    except ValueError:
        return False, []

    def walk(node, dotted):
        cur = node
        for key in dotted.split("."):
            if isinstance(cur, dict) and key in cur:
                cur = cur[key]
            elif isinstance(cur, list) and key.isdigit() and int(key) < len(cur):
                cur = cur[int(key)]
            else:
                return None
        return cur

    hits = []
    for entry in matcher.json_keys:
        if "=" in entry:
            dotted, _, expected = entry.partition("=")
            val = walk(data, dotted.strip())
            if val is not None and str(val) == expected.strip():
                hits.append(entry)
        elif walk(data, entry) is not None:
            hits.append(entry)

    if matcher.words:
        vals = [str(walk(data, e.partition("=")[0])) for e in matcher.json_keys]
        word_hits = [w for w in matcher.words if w in vals]
        hits.extend(word_hits)
    if matcher.condition.lower() == "and":
        required = len(matcher.json_keys) + len(matcher.words)
        ok = bool(required) and len(hits) == required
    else:
        ok = len(hits) > 0
    return ok, hits


# ------------------------------------------------------ bundled custom extractors


@register_extractor_type(
    "xpath",
    source="darco",
    description="Extract node text/values from an XML body via XPath",
)
def _extract_xpath(ext: TemplateExtractor, resp: httpx.Response) -> dict[str, list]:
    root = _xml_root(resp)
    out: dict[str, list] = {}
    if root is None:
        return out
    name = ext.name or "xpath"
    for expr in ext.xpath:
        try:
            for node in _findall(root, expr):
                if isinstance(node.tag, str):
                    val = node.text if node.text and node.text.strip() else node.tag
                    out.setdefault(name, []).append(val.strip())
        except (ET.ParseError, SyntaxError):
            continue
    return out


__all__ = [
    "get_extractor_type",
    "get_matcher_type",
    "register_extractor_type",
    "register_matcher_type",
    "registered_extractor_types",
    "registered_matcher_types",
]
