"""XML body detection, entity encoding, and WAF-bypass probes.

Some backends accept XML request bodies and hand element text straight to SQL.
A WAF inspects the *raw* bytes, but XML parsers expand character references
(``&#x55;&#x4e;...``) *after* the filter has already seen them — so a payload
encoded as numeric character references reaches the database decoded while the
filter only ever saw ``&#x..;`` tokens.

This module answers the question "how do we know it's XML?" with behavioral
probes, then hands the sqli engine the encoded payload channel to exploit it.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from difflib import SequenceMatcher

import httpx

from .engine import execute
from .models import BodyType, NameValue, Request, Response, SessionState

# Characters kept literal in encoded payloads. Whitespace stays readable and
# never trips a signature-based filter; everything else becomes a hex ref.
_XML_WS = set(" \t\r\n")


class XmlParam:
    """A leaf element value extracted from an XML request body."""

    __slots__ = ("name", "path", "value")

    def __init__(self, name: str, value: str, path: str):
        self.name = name
        self.value = value
        self.path = path

    def as_tuple(self) -> tuple[str, str, str]:
        return (self.name, self.value, self.path)


class XmlProbeResult:
    """Outcome of the behavioral "is this really XML?" probe battery."""

    __slots__ = ("decodes_entities", "param", "parses_xml", "probes", "requires_xml")

    def __init__(self, param: str):
        self.param = param
        self.decodes_entities = False
        self.parses_xml = False
        self.requires_xml = False
        self.probes: list[dict] = []


def content_type_of(request: Request) -> str:
    for h in request.headers:
        if h.name.lower() == "content-type":
            return h.value.lower()
    return ""


def looks_like_xml(request: Request) -> bool:
    """True when the request body is likely XML (content-type or leading tag)."""
    if "xml" in content_type_of(request):
        return True
    body = request.body_raw.lstrip()
    return body.startswith(("<?xml", "<"))


def xml_entity_encode(text: str) -> str:
    """Encode text as XML hex character references (whitespace stays literal).

    ``1 OR 1=1`` becomes ``&#x31; &#x4f;&#x52; &#x31;&#x3d;&#x31;`` — the raw
    bytes a WAF sees contain no SQL keywords, but an XML parser decodes them
    back to the original SQL before the query executes.
    """
    return "".join(ch if ch in _XML_WS else f"&#x{ord(ch):X};" for ch in text)


def _tag_pattern(tag: str) -> re.Pattern:
    return re.compile(
        rf"(<{re.escape(tag)}(?:\s[^<>]*?)?>)(.*?)(</{re.escape(tag)}>)",
        re.DOTALL,
    )


def parse_xml_params(body: str) -> list[XmlParam]:
    """Extract leaf element text values from an XML body (namespaces stripped)."""
    body = body.lstrip()
    if not body.startswith("<"):
        return []
    try:
        # Parsing user-supplied XML is intentional: this is the XML injection
        # auditor — we must parse attacker-controlled bodies to detect the
        # vulnerability. Caller controls input, not external entities.
        root = ET.fromstring(body)  # nosec B314
    except ET.ParseError:
        return []

    params: list[XmlParam] = []

    def walk(el: ET.Element, path: str) -> None:
        tag = el.tag.rsplit("}", 1)[-1] if isinstance(el.tag, str) else str(el.tag)
        cur = f"{path}/{tag}" if path else tag
        children = list(el)
        if not children and el.text and el.text.strip():
            params.append(XmlParam(name=tag, value=el.text, path=cur))
        for child in children:
            walk(child, cur)

    walk(root, "")
    return params


def replace_element_text(
    body: str, tag: str, old_value: str | None, new_value: str
) -> str:
    """Substitute the text of the first ``<tag>`` whose text equals ``old_value``.

    Pass ``old_value=None`` to replace the first occurrence regardless of the
    current text. The rest of the document is preserved byte-for-byte.
    """
    pat = _tag_pattern(tag)
    out: list[str] = []
    replaced = False
    last = 0
    for m in pat.finditer(body):
        out.append(body[last : m.start()])
        if not replaced and (old_value is None or m.group(2) == old_value):
            out.append(m.group(1) + new_value + m.group(3))
            replaced = True
        else:
            out.append(m.group(0))
        last = m.end()
    out.append(body[last:])
    return "".join(out)


def truncate_after_element_text(body: str, tag: str, value: str) -> str:
    """Cut the body right after ``<tag>value`` — an unclosed element."""
    pat = re.compile(
        rf"(<{re.escape(tag)}(?:\s[^<>]*?)?>)({re.escape(value)})", re.DOTALL
    )
    m = pat.search(body)
    if not m:
        return body
    return body[: m.end()]


def send(req: Request, session: SessionState) -> Response | None:
    """Execute a request and return the darco Response model or None on failure."""
    try:
        res = execute(req, session)
        if isinstance(res, tuple) and len(res) >= 2:
            return res[1]
        if isinstance(res, Response):
            return res
        return None
    except (httpx.HTTPError, OSError, TimeoutError, ValueError):
        return None


def _similarity(a: str, b: str) -> float:
    if a == b:
        return 1.0
    if not a or not b:
        return 0.0
    return SequenceMatcher(None, a[:2000], b[:2000]).ratio()


def probe_xml_parsing(
    request: Request,
    session: SessionState,
    param: str,
    value: str,
    baseline: Response | None = None,
) -> XmlProbeResult | None:
    """Behaviorally confirm an endpoint parses XML / expands character refs.

    Returns ``None`` when the request is not an XML body. Probes:

    * **unclosed_tag** — truncated element -> XML parse error?
    * **numeric_ref** — ``&#x31;`` decodes to ``1`` and returns baseline content?
      (the smoking gun: only an XML parser expands character references)
    * **undefined_entity** — ``&abc;`` is a hard XML parse failure?
    * **non_xml** — a form-encoded body is rejected outright?
    """
    if request.body_type != BodyType.RAW or not looks_like_xml(request):
        return None

    result = XmlProbeResult(param)
    if baseline is None:
        baseline = send(request, session)
    if baseline is None:
        return None
    base_status = baseline.status_code
    base_len = baseline.body_len

    def run(body: str, label: str) -> tuple[Response | None, str]:
        req = request.model_copy(deep=True)
        req.body_raw = body
        resp = send(req, session)
        detail = f"{label}: status {resp.status_code if resp else 'n/a'}"
        return resp, detail

    # A: unclosed element -> XML parse error?
    truncated = truncate_after_element_text(request.body_raw, param, value)
    if truncated != request.body_raw:
        resp_a, detail_a = run(truncated, "unclosed element")
    else:
        resp_a, detail_a = None, "unclosed element: no-op"
    result.probes.append(
        {
            "label": "unclosed_tag",
            "status": resp_a.status_code if resp_a else None,
            "detail": detail_a,
        }
    )

    # B: numeric character reference decodes to the original value?
    enc = xml_entity_encode(value)
    encoded_body = replace_element_text(request.body_raw, param, value, enc)
    if encoded_body != request.body_raw:
        resp_b, detail_b = run(encoded_body, "numeric char ref")
    else:
        resp_b, detail_b = None, "numeric char ref: no-op"
    sim_b = _similarity(baseline.body or "", resp_b.body or "") if resp_b else 0.0
    b_matches = (
        resp_b is not None
        and resp_b.status_code == base_status
        and sim_b >= 0.85
        and abs(resp_b.body_len - base_len) <= max(30, int(base_len * 0.15))
    )
    result.probes.append(
        {
            "label": "numeric_ref",
            "status": resp_b.status_code if resp_b else None,
            "detail": f"{detail_b}, {round(sim_b * 100)}% match with baseline",
        }
    )

    # C: undefined entity -> hard XML parse failure?
    bad_body = replace_element_text(request.body_raw, param, value, "&abc;")
    if bad_body != request.body_raw:
        resp_c, detail_c = run(bad_body, "undefined entity")
    else:
        resp_c, detail_c = None, "undefined entity: no-op"
    result.probes.append(
        {
            "label": "undefined_entity",
            "status": resp_c.status_code if resp_c else None,
            "detail": detail_c,
        }
    )

    # D: non-XML body rejected?
    req_d = request.model_copy(deep=True)
    req_d.body_raw = f"{param}={value}"
    headers = [h for h in req_d.headers if h.name.lower() != "content-type"]
    headers.append(
        NameValue(name="Content-Type", value="application/x-www-form-urlencoded")
    )
    req_d.headers = headers
    resp_d = send(req_d, session)
    result.probes.append(
        {
            "label": "non_xml",
            "status": resp_d.status_code if resp_d else None,
            "detail": f"form-encoded body: status {resp_d.status_code if resp_d else 'n/a'}",
        }
    )

    a_error = resp_a is not None and resp_a.status_code >= 400
    c_error = resp_c is not None and resp_c.status_code >= 400
    d_error = resp_d is not None and resp_d.status_code >= 400

    result.decodes_entities = b_matches
    result.parses_xml = b_matches or (a_error and c_error)
    result.requires_xml = b_matches and d_error
    return result


__all__ = [
    "XmlParam",
    "XmlProbeResult",
    "content_type_of",
    "looks_like_xml",
    "parse_xml_params",
    "probe_xml_parsing",
    "replace_element_text",
    "send",
    "truncate_after_element_text",
    "xml_entity_encode",
]
