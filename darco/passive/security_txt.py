from __future__ import annotations

from datetime import UTC, datetime
from urllib.parse import urljoin

import httpx

from ..models import Finding, SecurityTxt


async def inspect_security_txt(
    base_url: str, client: httpx.AsyncClient | None = None
) -> tuple[SecurityTxt, list[Finding]]:
    """Check for and parse RFC 9116 security.txt."""
    sec = SecurityTxt(present=False)
    findings: list[Finding] = []
    own_client = False

    if client is None:
        client = httpx.AsyncClient(timeout=5.0, trust_env=False, follow_redirects=True)
        own_client = True

    try:
        paths = ["/.well-known/security.txt", "/security.txt"]
        for p in paths:
            target_url = urljoin(base_url, p)
            try:
                resp = await client.get(target_url)
                if resp.status_code == 200 and "contact:" in resp.text.lower():
                    sec.present = True
                    sec.url = str(resp.url)
                    sec.raw = resp.text[:4000]

                    for line in resp.text.splitlines():
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        if ":" in line:
                            field, _, val = line.partition(":")
                            field = field.strip().lower()
                            val = val.strip()
                            if field == "contact":
                                sec.contact.append(val)
                            elif field == "expires":
                                sec.expires = val
                            elif field == "encryption":
                                sec.encryption.append(val)
                            elif field == "acknowledgments":
                                sec.acknowledgments.append(val)
                            elif field == "policy":
                                sec.policy.append(val)
                            elif field == "hiring":
                                sec.hiring.append(val)

                    findings.append(
                        Finding(
                            id="find-security-txt-present",
                            type="security_txt_present",
                            severity="info",
                            location=sec.url,
                            evidence=f"Discovered security.txt with {len(sec.contact)} contact point(s)",
                            suggestion="Use documented security.txt contact channels for coordinated vulnerability disclosure.",
                        )
                    )

                    # Check expiration if specified
                    if sec.expires:
                        try:
                            # Try ISO 8601 parsing
                            exp_dt = datetime.fromisoformat(sec.expires)
                            if exp_dt < datetime.now(UTC):
                                findings.append(
                                    Finding(
                                        id="find-security-txt-expired",
                                        type="security_txt_expired",
                                        severity="low",
                                        location=sec.url,
                                        evidence=f"security.txt expired on {sec.expires}",
                                        suggestion="Update the Expires field in security.txt to maintain valid disclosure metadata.",
                                    )
                                )
                        except (ValueError, TypeError):
                            pass

                    break
            except (httpx.HTTPError, OSError):
                continue

        if not sec.present:
            findings.append(
                Finding(
                    id="find-security-txt-missing",
                    type="missing_security_txt",
                    severity="info",
                    location=base_url,
                    evidence="No security.txt found at /.well-known/security.txt or /security.txt",
                    suggestion="Add a security.txt (RFC 9116) file to define vulnerability disclosure channels.",
                )
            )

    finally:
        if own_client:
            await client.aclose()

    return sec, findings
