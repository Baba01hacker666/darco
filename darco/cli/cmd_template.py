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
@cli.command("template", context_settings={"ignore_unknown_options": True})
@click.argument("args", nargs=-1, required=False)
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
def template_cmd(
    ctx,
    args,
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
    """Attack and vulnerability scanning templates (Nuclei-compatible).
    
    Usage:
        darco template <url>                    # run ALL templates
        darco template <url> sql-error-based    # run specific template
        darco template <url> --tags exposure    # filter by tag
        darco template list                     # list available templates
        darco template new <id>                 # create new template
    """
    # Handle subcommands
    if args and args[0] == "list":
        return _list_templates(ctx, args[1] if len(args) > 1 else None, tags_opt, sev_opt)
    if args and args[0] == "new":
        if len(args) < 2:
            raise DarcoError("usage: darco template new <template_id>")
        return _new_template(ctx, args[1], args[2:], cli_vars)
    
    # Otherwise, run templates against target
    _run_templates(ctx, args, url, templates_opt, tags_opt, sev_opt, builtin, workers, timeout, save, insecure, poc, cli_vars, plugin_dirs)


def _run_templates(ctx, args, url, templates_opt, tags_opt, sev_opt, builtin, workers, timeout, save, insecure, poc, cli_vars, plugin_dirs):
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

    # Smart argument parsing:
    # - If first arg is a URL, use it as URL
    # - If first arg is not a URL, treat it as template name (URL from config/workspace)
    # - Remaining args are template names
    target_val = url
    template_names: tuple = templates_opt

    if args:
        if args[0].startswith(("http://", "https://")):
            target_val = args[0]
            template_names = template_names + args[1:]
        else:
            template_names = template_names + args
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
            "provide a target URL: 'darco template <url>' or 'darco template -u <url>'"
        )
    if not target_val.startswith(("http://", "https://")):
        target_val = "http://" + target_val

    all_templates = []
    if template_names:
        for t_path in template_names:
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
                builtin_path = None
                for suffix in (".yaml", ".yml", ".json"):
                    candidate = BUILTIN_TEMPLATES_DIR / f"{t_path}{suffix}"
                    if candidate.is_file():
                        builtin_path = candidate
                        break
                if builtin_path is None:
                    raise DarcoError(f"template not found: {t_path}")
                all_templates.append(load_template(builtin_path))
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


def _list_templates(ctx, dir_path, tags_opt, sev_opt):
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


def _new_template(ctx, template_id, args, cli_vars):
    """Create / scaffold a new YAML attack template."""
    from ..templates import generate_template_scaffold
    
    # Parse additional args
    name = ""
    severity = "medium"
    method = "GET"
    path = "{{BaseURL}}/"
    words = []
    status_codes = []
    out_file = ""
    
    i = 0
    while i < len(args):
        if args[i] == "-n" and i + 1 < len(args):
            name = args[i + 1]
            i += 2
        elif args[i] == "-s" and i + 1 < len(args):
            severity = args[i + 1]
            i += 2
        elif args[i] == "-m" and i + 1 < len(args):
            method = args[i + 1]
            i += 2
        elif args[i] == "-p" and i + 1 < len(args):
            path = args[i + 1]
            i += 2
        elif args[i] == "-w" and i + 1 < len(args):
            words.append(args[i + 1])
            i += 2
        elif args[i] == "-c" and i + 1 < len(args):
            status_codes.append(int(args[i + 1]))
            i += 2
        elif args[i] == "-o" and i + 1 < len(args):
            out_file = args[i + 1]
            i += 2
        else:
            i += 1

    yaml_content = generate_template_scaffold(
        template_id=template_id,
        name=name,
        severity=severity,
        method=method,
        path=path,
        words=words if words else None,
        status_codes=status_codes if status_codes else None,
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
