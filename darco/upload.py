import re
import secrets
from urllib.parse import urljoin, urlsplit

import httpx

from .engine import effective_cookies, effective_headers
from .models import (
    Request,
    SessionState,
    UploadAuditResult,
    UploadFinding,
)

SVG_PAYLOAD = """<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">
  <polygon id="triangle" points="0,0 0,50 50,0" fill="#009900" stroke="#004400"/>
  <text x="50" y="50" font-size="20" fill="red">darco_xss_audit</text>
  <script type="text/javascript">
    // darco benign audit marker
  </script>
</svg>"""

HTML_PAYLOAD = """<!DOCTYPE html>
<html>
<head><title>Darco Audit</title></head>
<body>
  <h1>Darco File Upload Audit</h1>
  <p>Verifying HTML upload policy.</p>
</body>
</html>"""


def _extract_file_url(
    base_url: str, resp_text: str, location_header: str | None
) -> str | None:
    """Extract uploaded file link from Location header or response body."""
    if location_header:
        return urljoin(base_url, location_header)
    if not resp_text:
        return None

    # Search for JSON URL or path
    m = re.search(
        r'"(?:url|path|file|location|link|src)"\s*:\s*"([^"]+)"',
        resp_text,
        re.IGNORECASE,
    )
    if m:
        return urljoin(base_url, m.group(1).replace("\\/", "/"))

    # Search for <a href="...uploads/..."> or <img src="...">
    m = re.search(
        r'(?:href|src)=["\']([^"\']+\.(?:svg|html|png|jpg|jpeg)[^"\']*)["\']',
        resp_text,
        re.IGNORECASE,
    )
    if m:
        return urljoin(base_url, m.group(1))

    return None


def audit_file_upload(
    request: Request,
    session: SessionState | None = None,
    file_field: str | None = None,
    extra_fields: dict[str, str] | None = None,
) -> UploadAuditResult:
    """Audit a file upload endpoint for dangerous file types (SVG with script context, HTML) and header defenses."""
    if session is None:
        session = SessionState()

    target_url = request.url
    # Common file input field names if none provided
    candidate_fields = (
        [file_field]
        if file_field
        else ["file", "upload", "avatar", "image", "attachment", "doc"]
    )
    used_field = candidate_fields[0]

    result = UploadAuditResult(
        target=target_url,
        tested_field=used_field,
        tests_run=0,
        accepted_formats=[],
        findings=[],
    )

    cookies = httpx.Cookies()
    for c in effective_cookies(request, session):
        cookies.set(
            c.name,
            c.value,
            domain=c.domain or urlsplit(target_url).hostname or "",
            path=c.path or "/",
        )

    req_headers = {
        h.name: h.value
        for h in effective_headers(request, session)
        if h.name.lower() != "content-type"
    }

    test_cases = [
        # (format_name, filename, mime_type, content_bytes, vuln_type)
        (
            "SVG (image/svg+xml)",
            f"darco_test_{secrets.token_hex(3)}.svg",
            "image/svg+xml",
            SVG_PAYLOAD.encode("utf-8"),
            "svg_stored_xss",
        ),
        (
            "HTML (text/html)",
            f"darco_test_{secrets.token_hex(3)}.html",
            "text/html",
            HTML_PAYLOAD.encode("utf-8"),
            "html_stored_xss",
        ),
        (
            "SVG with Image MIME (image/png)",
            f"darco_test_{secrets.token_hex(3)}.svg",
            "image/png",
            SVG_PAYLOAD.encode("utf-8"),
            "mime_spoofing_bypass",
        ),
        (
            "Double Extension (test.svg.png)",
            f"darco_test_{secrets.token_hex(3)}.svg.png",
            "image/png",
            SVG_PAYLOAD.encode("utf-8"),
            "dangerous_extension_allowed",
        ),
    ]

    with httpx.Client(
        verify=request.verify, timeout=request.timeout, trust_env=False, cookies=cookies
    ) as client:
        for fmt_name, filename, mime_type, content, vuln_type in test_cases:
            result.tests_run += 1
            files = {used_field: (filename, content, mime_type)}
            data = extra_fields or {}

            try:
                resp = client.request(
                    request.method
                    if request.method in ("POST", "PUT", "PATCH")
                    else "POST",
                    target_url,
                    headers=req_headers,
                    files=files,
                    data=data,
                    follow_redirects=request.follow_redirects,
                )
            except (httpx.HTTPError, OSError, TimeoutError, ValueError):
                continue

            # Check if upload was accepted (2xx or successful 302 redirect)
            is_success = resp.status_code in (200, 201, 202, 204, 302, 303)
            # Ensure response doesn't explicitly state file rejected in text
            lower_body = (resp.text or "").lower()
            rejected = any(
                term in lower_body
                for term in (
                    "invalid file",
                    "file type not allowed",
                    "extension not allowed",
                    "unsupported media",
                )
            )

            if is_success and not rejected:
                result.accepted_formats.append(fmt_name)
                loc = resp.headers.get("location")
                file_url = _extract_file_url(target_url, resp.text, loc)

                # Inspect served file headers if file URL is found
                served_content_type = None
                has_attachment = False
                has_csp = False

                if file_url:
                    try:
                        file_resp = client.get(
                            file_url, headers=req_headers, follow_redirects=True
                        )
                        served_content_type = (
                            file_resp.headers.get("content-type", "")
                            .split(";")[0]
                            .strip()
                            .lower()
                        )
                        disposition = file_resp.headers.get(
                            "content-disposition", ""
                        ).lower()
                        has_attachment = "attachment" in disposition
                        csp = file_resp.headers.get(
                            "content-security-policy", ""
                        ).lower()
                        has_csp = bool(
                            csp
                            and (
                                "script-src 'none'" in csp
                                or "default-src 'none'" in csp
                            )
                        )
                    except (httpx.HTTPError, OSError, TimeoutError, ValueError):
                        pass

                # Classify finding
                if vuln_type == "svg_stored_xss":
                    if (
                        served_content_type == "image/svg+xml"
                        and not has_attachment
                        and not has_csp
                    ):
                        result.findings.append(
                            UploadFinding(
                                param=used_field,
                                filename=filename,
                                content_type=mime_type,
                                status_code=resp.status_code,
                                file_url=file_url,
                                vulnerability_type="svg_stored_xss",
                                confidence="confirmed" if file_url else "high",
                                evidence=f"Server accepted SVG upload '{filename}' with status {resp.status_code}. "
                                + (
                                    f"Served directly as '{served_content_type}' without Content-Disposition: attachment or restrictive CSP."
                                    if file_url
                                    else "SVG uploads are accepted by the endpoint."
                                ),
                                suggestion="Serve user-uploaded SVGs with 'Content-Disposition: attachment', sanitize SVG XML, or host uploads on an isolated non-cookie CDN domain.",
                            )
                        )
                    else:
                        result.findings.append(
                            UploadFinding(
                                param=used_field,
                                filename=filename,
                                content_type=mime_type,
                                status_code=resp.status_code,
                                file_url=file_url,
                                vulnerability_type="svg_stored_xss",
                                confidence="medium",
                                evidence=f"Server accepted SVG upload '{filename}' with status {resp.status_code}.",
                                suggestion="Verify that uploaded SVGs are sanitized and served with 'Content-Disposition: attachment'.",
                            )
                        )

                elif vuln_type == "html_stored_xss":
                    result.findings.append(
                        UploadFinding(
                            param=used_field,
                            filename=filename,
                            content_type=mime_type,
                            status_code=resp.status_code,
                            file_url=file_url,
                            vulnerability_type="html_stored_xss",
                            confidence="confirmed" if file_url else "high",
                            evidence=f"Server accepted direct HTML file upload '{filename}' (status {resp.status_code})."
                            + (f" Accessible at {file_url}." if file_url else ""),
                            suggestion="Disallow .html/.htm file extensions entirely or enforce strict Content-Disposition: attachment on an isolated domain.",
                        )
                    )

                elif vuln_type == "mime_spoofing_bypass":
                    result.findings.append(
                        UploadFinding(
                            param=used_field,
                            filename=filename,
                            content_type=mime_type,
                            status_code=resp.status_code,
                            file_url=file_url,
                            vulnerability_type="mime_spoofing_bypass",
                            confidence="high",
                            evidence=f"Server accepted SVG file '{filename}' when submitted with spoofed MIME type '{mime_type}' (status {resp.status_code}).",
                            suggestion="Validate file contents using server-side magic byte inspection rather than relying on client-supplied Content-Type.",
                        )
                    )

                elif vuln_type == "dangerous_extension_allowed":
                    result.findings.append(
                        UploadFinding(
                            param=used_field,
                            filename=filename,
                            content_type=mime_type,
                            status_code=resp.status_code,
                            file_url=file_url,
                            vulnerability_type="dangerous_extension_allowed",
                            confidence="medium",
                            evidence=f"Server accepted double-extension file '{filename}' with status {resp.status_code}.",
                            suggestion="Validate file extensions against an allowlist and rewrite filenames on disk.",
                        )
                    )

    return result


__all__ = ["audit_file_upload"]
