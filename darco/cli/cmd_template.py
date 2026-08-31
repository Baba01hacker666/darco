"""Attack template commands: run / list / new."""

from __future__ import annotations

from pathlib import Path

import click

from ..errors import DarcoError
from ..models import to_json
from ._context import _find_workspace
from ._group import cli
from ._output import _emit


# ------------------------------------------------------------------ template / attack templates
@cli.group("template", invoke_without_command=False)
def template_group():
    """Attack and vulnerability scanning templates (Nuclei-compatible)."""


@template_group.command("run")
@click.argument("target", required=False, default=None)
@click.option("-u", "--url", default=None, help="Target URL to scan")
@click.option(
    "-t",
    "--template",
    "templates_opt",
    multiple=True,
    help="Template YAML file or directory of templates to execute",
)
@click.option(
    "--tags",
    "tags_opt",
    multiple=True,
    help="Filter templates by tag (e.g. git, config, exposure)",
)
@click.option(
    "--severity",
    "sev_opt",
    multiple=True,
    help="Filter templates by severity (info, low, medium, high, critical)",
)
@click.option(
    "--builtin/--no-builtin",
    default=True,
    help="Include built-in templates (default: True)",
)
@click.option("--workers", type=int, default=10, help="Concurrent template workers")
@click.option("--timeout", type=float, default=10.0)
@click.option("--save", is_flag=True, help="Save template findings to workspace")
@click.option("--insecure", is_flag=True, default=False)
@click.option(
    "--poc/--no-poc",
    default=True,
    help="Smart POC verification: prove real access on matched templates "
    "(exploit steps / auto-login with leaked creds). Default: enabled.",
)
@click.option(
    "--var",
    "cli_vars",
    multiple=True,
    help="Extra template variable KEY=VALUE (repeatable; usable as {{KEY}})",
)
@click.option(
    "--plugin-dir",
    "plugin_dirs",
    multiple=True,
    help="Load external plugin files (*.py) registering custom types (repeatable)",
)
@click.pass_context
def template_run_cmd(
    ctx,
    target,
    url,
    templates_opt,
    tags_opt,
    sev_opt,
    builtin,
    workers,
    timeout,
    save,
    insecure,
    poc,
    cli_vars,
    plugin_dirs,
):
    """Execute YAML/JSON attack templates against a target URL."""
    import asyncio

    from ..plugins import load_plugins_from_dir
    from ..render import md_template_report
    from ..templates import (
        load_builtin_templates,
        load_template,
        load_templates_from_dir,
        run_template_scan,
    )
    from ..templates.loader import BUILTIN_TEMPLATES_DIR

    for d in plugin_dirs:
        load_plugins_from_dir(d)

    extra_vars: dict[str, str] = {}
    for v in cli_vars:
        if "=" not in v:
            raise DarcoError(f"--var expects KEY=VALUE, got: {v}")
        k, _, val = v.partition("=")
        extra_vars[k.strip()] = val

    target_val = url or target
    if not target_val:
        cfg = (ctx.obj or {}).get("config")
        if cfg and cfg.target:
            target_val = cfg.target
        else:
            ws = _find_workspace(ctx, require=False)
            if ws:
                try:
                    target_val = ws.load_config().target
                except DarcoError:
                    pass
    if not target_val:
        raise DarcoError(
            "provide a target URL: 'darco template run <url>' or 'darco template run -u <url>'"
        )
    if not target_val.startswith(("http://", "https://")):
        target_val = "http://" + target_val

    all_templates = []
    if templates_opt:
        for t_path in templates_opt:
            p = Path(t_path)
            if p.is_dir():
                all_templates.extend(
                    load_templates_from_dir(
                        p, tags=list(tags_opt), severities=list(sev_opt)
                    )
                )
            elif p.is_file():
                all_templates.append(load_template(p))
            else:
                builtin = None
                for suffix in (".yaml", ".yml", ".json"):
                    candidate = BUILTIN_TEMPLATES_DIR / f"{t_path}{suffix}"
                    if candidate.is_file():
                        builtin = candidate
                        break
                if builtin is None:
                    raise DarcoError(f"template path not found: {t_path}")
                all_templates.append(load_template(builtin))
    elif builtin:
        all_templates.extend(
            load_builtin_templates(tags=list(tags_opt), severities=list(sev_opt))
        )

    if not all_templates:
        raise DarcoError("no attack templates loaded to execute")

    report = asyncio.run(
        run_template_scan(
            all_templates,
            target_val,
            workers=workers,
            timeout=timeout,
            verify=not insecure,
            verify_poc=poc,
            extra_variables=extra_vars or None,
        )
    )

    if save and report.findings:
        ws = _find_workspace(ctx, auto_create_target=target_val)
        ws.add_findings(report.findings)

    _emit(ctx, to_json(report), md_template_report)


@template_group.command("list")
@click.argument("dir_path", required=False, default=None)
@click.option("--tags", "tags_opt", multiple=True)
@click.option("--severity", "sev_opt", multiple=True)
@click.pass_context
def template_list_cmd(ctx, dir_path, tags_opt, sev_opt):
    """List available built-in or custom attack templates."""
    from ..templates import load_builtin_templates, load_templates_from_dir

    if dir_path:
        templates = load_templates_from_dir(
            dir_path, tags=list(tags_opt), severities=list(sev_opt)
        )
    else:
        templates = load_builtin_templates(
            tags=list(tags_opt), severities=list(sev_opt)
        )

    summary = [
        {
            "id": t.id,
            "name": t.info.name,
            "severity": t.info.severity,
            "tags": t.info.tags,
            "requests": len(t.requests),
            "file": t.raw_path,
        }
        for t in templates
    ]

    def render_list(d):
        lines = [f"# Attack Templates ({len(d.get('templates', []))})", ""]
        lines.append("| ID | Name | Severity | Tags | Requests |")
        lines.append("| --- | --- | --- | --- | --- |")
        for t in d.get("templates", []):
            tags_str = ", ".join(t.get("tags", []))
            lines.append(
                f"| `{t.get('id')}` | {t.get('name')} | **{t.get('severity', '').upper()}** | {tags_str} | {t.get('requests')} |"
            )
        return "\n".join(lines)

    _emit(ctx, {"count": len(summary), "templates": summary}, render_list)


@template_group.command("new")
@click.argument("template_id")
@click.option("-n", "--name", default="", help="Human-readable template name")
@click.option(
    "-s",
    "--severity",
    default="medium",
    type=click.Choice(
        ["info", "low", "medium", "high", "critical"], case_sensitive=False
    ),
)
@click.option("-m", "--method", default="GET", help="HTTP Method (GET, POST, etc.)")
@click.option("-p", "--path", default="{{BaseURL}}/", help="Target request path")
@click.option("-w", "--word", "words", multiple=True, help="Words to match in response")
@click.option(
    "-c",
    "--status",
    "status_codes",
    multiple=True,
    type=int,
    help="Status codes to match",
)
@click.option("-o", "--out", "out_file", default="", help="Output YAML file path")
@click.pass_context
def template_new_cmd(
    ctx,
    template_id,
    name,
    severity,
    method,
    path,
    words,
    status_codes,
    out_file,
):
    """Create / scaffold a new YAML attack template."""
    from ..templates import generate_template_scaffold

    yaml_content = generate_template_scaffold(
        template_id=template_id,
        name=name,
        severity=severity,
        method=method,
        path=path,
        words=list(words) if words else None,
        status_codes=list(status_codes) if status_codes else None,
    )

    if out_file:
        p = Path(out_file)
        p.write_text(yaml_content, encoding="utf-8")
        _emit(
            ctx,
            {"status": "created", "file": str(p), "id": template_id},
            lambda d: (
                f"# Template Created\n\n- **ID**: `{d.get('id')}`\n- **File**: `{d.get('file')}`\n"
            ),
        )
    else:
        click.echo(yaml_content)
