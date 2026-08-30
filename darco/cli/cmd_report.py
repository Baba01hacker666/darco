from __future__ import annotations

import json
from pathlib import Path

import click

from ..models import to_json
from ..render import md_report
from ..report import export_html, export_junit, export_sarif
from ._context import _find_workspace
from ._group import cli
from ._output import _emit


@cli.command("report")
@click.option(
    "--format",
    "report_format",
    type=click.Choice(["sarif", "junit", "html", "json", "markdown"], case_sensitive=False),
    default="sarif",
    help="Export format for the security report (sarif, junit, html, json, markdown)",
)
@click.option("-o", "--output", "out_file", type=click.Path(), help="Output file path")
@click.pass_context
def report_cmd(ctx, report_format, out_file):
    """Generate multi-format CI/CD and compliance reports (SARIF 2.1.0, JUnit XML, HTML, JSON)."""
    ws = _find_workspace(ctx, require=True)
    findings = ws.load_findings()
    cfg = ws.load_config()
    target_url = cfg.target if cfg else ""

    fmt = report_format.lower()
    raw_content = ""
    payload: dict | str = {}

    if fmt == "sarif":
        sarif_dict = export_sarif(findings, target_url=target_url)
        payload = sarif_dict
        raw_content = json.dumps(sarif_dict, indent=2)
    elif fmt == "junit":
        junit_xml = export_junit(findings, suite_name=f"darco-{target_url or 'scan'}")
        payload = {"junit": junit_xml}
        raw_content = junit_xml
    elif fmt == "html":
        html_str = export_html(findings, target_url=target_url)
        payload = {"html": html_str}
        raw_content = html_str
    elif fmt == "json":
        json_list = [to_json(f) for f in findings]
        payload = {"findings": json_list, "total": len(json_list)}
        raw_content = json.dumps(payload, indent=2)
    elif fmt == "markdown":
        from ..render import _md_finding
        md_lines = [f"# Security Findings Report for `{target_url}`\n"]
        for f in findings:
            md_lines.append(_md_finding(f))
        md_str = "\n".join(md_lines)
        payload = {"markdown": md_str}
        raw_content = md_str

    if out_file:
        Path(out_file).write_text(raw_content)

    if fmt == "sarif":
        _emit(ctx, payload, md_report)
    elif fmt in ("junit", "html", "markdown"):
        click.echo(raw_content)
    else:
        _emit(ctx, payload, md_report)
