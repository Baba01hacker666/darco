from __future__ import annotations

from ..models import Finding, Response

SECURITY_HEADER_SPECS = [
    (
        "Strict-Transport-Security",
        "missing_hsts",
        "medium",
        "Enforces HTTPS connections and prevents SSL stripping attacks.",
    ),
    (
        "Content-Security-Policy",
        "missing_csp",
        "medium",
        "Restricts resources (scripts, styles, frames) the browser is allowed to load, mitigating XSS and clickjacking.",
    ),
    (
        "X-Frame-Options",
        "missing_x_frame_options",
        "low",
        "Prevents site from being embedded in iframes, defending against clickjacking attacks.",
    ),
    (
        "X-Content-Type-Options",
        "missing_x_content_type_options",
        "low",
        "Prevents MIME-sniffing attacks (e.g. executing text/plain as JavaScript).",
    ),
    (
        "Referrer-Policy",
        "missing_referrer_policy",
        "low",
        "Controls how much referrer information is sent with navigation requests.",
    ),
    (
        "Permissions-Policy",
        "missing_permissions_policy",
        "low",
        "Controls browser features and APIs (camera, microphone, geolocation) that can be used.",
    ),
]


def audit_security_headers(
    response: Response, target_url: str = ""
) -> tuple[dict[str, str], list[str], list[Finding]]:
    """Audit HTTP response for standard security headers and missing protections."""
    headers_dict = {h.name.lower(): h.value for h in response.headers}
    present_headers: dict[str, str] = {}
    missing_headers: list[str] = []
    findings: list[Finding] = []

    loc = target_url or response.url

    for header_name, f_type, severity, purpose in SECURITY_HEADER_SPECS:
        key = header_name.lower()
        if key in headers_dict:
            present_headers[header_name] = headers_dict[key]
        else:
            missing_headers.append(header_name)
            # Only report missing HSTS for HTTPS targets
            if header_name == "Strict-Transport-Security" and not loc.startswith(
                "https://"
            ):
                continue

            findings.append(
                Finding(
                    id=f"find-hdr-{f_type}",
                    type=f_type,
                    severity=severity,
                    location=loc,
                    evidence=f"Missing security header: {header_name}",
                    suggestion=f"Configure the '{header_name}' header. {purpose}",
                )
            )

    return present_headers, missing_headers, findings
