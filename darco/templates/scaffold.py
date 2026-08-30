"""Template generator and scaffolder for custom attack templates."""

from __future__ import annotations

import yaml


def generate_template_scaffold(
    template_id: str,
    name: str = "",
    author: str = "darco",
    severity: str = "medium",
    description: str = "",
    tags: list[str] | None = None,
    method: str = "GET",
    path: str = "{{BaseURL}}/",
    words: list[str] | None = None,
    status_codes: list[int] | None = None,
    regex_patterns: list[str] | None = None,
    remediation: str = "",
) -> str:
    """Generate formatted YAML template content."""
    data = {
        "id": template_id,
        "info": {
            "name": name or template_id.replace("-", " ").title(),
            "author": author,
            "severity": severity,
            "description": description or f"Security check for {template_id}",
            "tags": tags or [template_id.split("-")[0]],
            "remediation": remediation or "Review and restrict access to the endpoint.",
        },
        "requests": [
            {
                "method": method.upper(),
                "path": [path],
                "matchers-condition": "and"
                if (status_codes and (words or regex_patterns))
                else "or",
                "matchers": [],
            }
        ],
    }

    req_matchers = data["requests"][0]["matchers"]

    if status_codes:
        req_matchers.append(
            {
                "type": "status",
                "status": status_codes,
            }
        )
    else:
        req_matchers.append(
            {
                "type": "status",
                "status": [200],
            }
        )

    if words:
        req_matchers.append(
            {
                "type": "word",
                "part": "body",
                "words": words,
            }
        )

    if regex_patterns:
        req_matchers.append(
            {
                "type": "regex",
                "part": "body",
                "regex": regex_patterns,
            }
        )

    header_comment = """# ------------------------------------------------------------------
# Darco Security / Attack Template
# Nuclei-compatible YAML definition
# ------------------------------------------------------------------
"""
    return header_comment + yaml.dump(data, sort_keys=False, default_flow_style=False)
