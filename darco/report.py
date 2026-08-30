"""Multi-format security report generator (SARIF 2.1.0, JUnit XML, Markdown, HTML).

Provides standard CI/CD and security scanner export formats so Darco findings
can be loaded into GitHub Code Scanning, DefectDojo, GitLab CI, or Jenkins.
"""

from __future__ import annotations

import html
from datetime import UTC, datetime
from typing import Any
from xml.sax.saxutils import escape as xml_escape

from .models import Finding

SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
DARCO_VERSION = "0.1.0"


def _sarif_level(severity: str) -> str:
    sev = severity.lower()
    if sev in ("critical", "high"):
        return "error"
    if sev in ("medium", "low"):
        return "warning"
    return "note"


def export_sarif(
    findings: list[Finding], target_url: str = "", tool_name: str = "darco"
) -> dict[str, Any]:
    """Export findings as a SARIF 2.1.0 dictionary."""
    rules_map: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for f in findings:
        rule_id = f"DARCO-{f.type.upper().replace('_', '-')}"
        if rule_id not in rules_map:
            rules_map[rule_id] = {
                "id": rule_id,
                "name": f.type.replace("_", " ").title(),
                "shortDescription": {"text": f"Security finding of type {f.type}"},
                "fullDescription": {"text": f.evidence or f.type},
                "help": {
                    "text": f.suggestion or "Verify finding and apply remediation.",
                    "markdown": f"**Suggestion**: {f.suggestion or 'Review and patch.'}",
                },
                "defaultConfiguration": {"level": _sarif_level(f.severity)},
            }

        loc_uri = f.location or target_url or "target"
        res_entry: dict[str, Any] = {
            "ruleId": rule_id,
            "level": _sarif_level(f.severity),
            "message": {"text": f.evidence or f"{f.type} detected at {loc_uri}"},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": loc_uri, "uriBaseId": "%SRCROOT%"},
                        "region": {"startLine": 1, "startColumn": 1},
                    }
                }
            ],
            "properties": {
                "id": f.id,
                "darcoSeverity": f.severity,
                "suggestion": f.suggestion,
                "requestId": f.request_id,
            },
        }
        results.append(res_entry)

    sarif_doc: dict[str, Any] = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "version": DARCO_VERSION,
                        "informationUri": "https://github.com/Baba01hacker666/darco",
                        "rules": list(rules_map.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return sarif_doc


def export_junit(findings: list[Finding], suite_name: str = "darco-scan") -> str:
    """Export findings as JUnit XML format for CI pipelines."""
    failures = sum(1 for f in findings if f.severity.lower() in ("critical", "high", "medium"))
    tests_count = max(len(findings), 1)

    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        f'<testsuite name="{xml_escape(suite_name)}" tests="{tests_count}" failures="{failures}" errors="0" time="0.0">',
    ]

    if not findings:
        lines.append('  <testcase classname="darco.security" name="clean_scan" time="0.0"/>')
    else:
        for f in findings:
            cname = f"darco.{xml_escape(f.type)}"
            tname = f"{f.severity.upper()}_{f.id}"
            lines.append(f'  <testcase classname="{cname}" name="{tname}" time="0.0">')
            if f.severity.lower() in ("critical", "high", "medium", "low"):
                msg = xml_escape(f.evidence or f.type)
                sugg = xml_escape(f.suggestion or "")
                lines.append(f'    <failure message="{msg}" type="{xml_escape(f.type)}">')
                lines.append(f"Severity: {f.severity}\nLocation: {f.location}\nSuggestion: {sugg}")
                lines.append("    </failure>")
            lines.append("  </testcase>")

    lines.append("</testsuite>")
    return "\n".join(lines)


def export_html(findings: list[Finding], target_url: str = "") -> str:
    """Generate a clean, standalone HTML security report."""
    now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
    sev_counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.severity.lower()
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    rows = []
    for f in findings:
        sev = f.severity.lower()
        badge_color = {
            "critical": "#d32f2f",
            "high": "#e65100",
            "medium": "#f57c00",
            "low": "#388e3c",
            "info": "#1976d2",
        }.get(sev, "#757575")

        rows.append(
            f"<tr>"
            f"<td><span style=\"background-color: {badge_color}; color: white; padding: 3px 8px; border-radius: 4px; font-weight: bold;\">{html.escape(f.severity.upper())}</span></td>"
            f"<td><code>{html.escape(f.type)}</code></td>"
            f"<td><code>{html.escape(f.location or '-')}</code></td>"
            f"<td>{html.escape(f.evidence or '-')}</td>"
            f"<td>{html.escape(f.suggestion or '-')}</td>"
            f"</tr>"
        )

    table_body = "\n".join(rows) if rows else "<tr><td colspan='5'><em>No security findings recorded.</em></td></tr>"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Darco Security Scan Report - {html.escape(target_url or "Workspace")}</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; margin: 30px; color: #333; background-color: #fafafa; }}
    h1 {{ color: #111; margin-bottom: 5px; }}
    .meta {{ color: #666; margin-bottom: 20px; font-size: 0.9em; }}
    .summary {{ display: flex; gap: 15px; margin-bottom: 25px; }}
    .card {{ background: white; border: 1px solid #e0e0e0; border-radius: 6px; padding: 15px; flex: 1; text-align: center; box-shadow: 0 1px 3px rgba(0,0,0,0.05); }}
    .card .num {{ font-size: 24px; font-weight: bold; margin-top: 5px; }}
    table {{ width: 100%; border-collapse: collapse; background: white; border: 1px solid #e0e0e0; border-radius: 6px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.05); }}
    th, td {{ padding: 12px 15px; text-align: left; border-bottom: 1px solid #eee; }}
    th {{ background-color: #f5f5f5; font-weight: 600; color: #444; }}
    code {{ background: #f0f0f0; padding: 2px 5px; border-radius: 3px; font-size: 0.9em; }}
  </style>
</head>
<body>
  <h1>Darco Security Report</h1>
  <div class="meta">Target: <strong>{html.escape(target_url or "Local Workspace")}</strong> | Generated at: {now}</div>
  <div class="summary">
    <div class="card" style="border-top: 4px solid #d32f2f;"><div style="color:#d32f2f;">Critical</div><div class="num">{sev_counts['critical']}</div></div>
    <div class="card" style="border-top: 4px solid #e65100;"><div style="color:#e65100;">High</div><div class="num">{sev_counts['high']}</div></div>
    <div class="card" style="border-top: 4px solid #f57c00;"><div style="color:#f57c00;">Medium</div><div class="num">{sev_counts['medium']}</div></div>
    <div class="card" style="border-top: 4px solid #388e3c;"><div style="color:#388e3c;">Low</div><div class="num">{sev_counts['low']}</div></div>
    <div class="card" style="border-top: 4px solid #1976d2;"><div style="color:#1976d2;">Info</div><div class="num">{sev_counts['info']}</div></div>
  </div>
  <table>
    <thead>
      <tr>
        <th>Severity</th>
        <th>Finding Type</th>
        <th>Location</th>
        <th>Evidence</th>
        <th>Remediation Suggestion</th>
      </tr>
    </thead>
    <tbody>
      {table_body}
    </tbody>
  </table>
</body>
</html>
"""
