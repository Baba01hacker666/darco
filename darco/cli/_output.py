"""Output formatting: JSON emission, markdown/table rendering helpers."""

from __future__ import annotations

import json

import click

# Default output format for human-facing commands. Agents/tests pass
# `--format json` (or `-J`) to get the machine contract.
DEFAULT_FMT = "md"

# Commands that emit structured output and respect --format.
_FORMAT_CMDS = {
    "init",
    "ingest",
    "send",
    "diff",
    "analyze",
    "status",
    "session",
    "export",
    "repeat",
    "findings",
    "discover",
}


def _echo_json(data) -> None:
    click.echo(json.dumps(data, indent=2, ensure_ascii=False))


def _emit(ctx, data: dict, md_builder) -> None:
    """Print `data` as markdown (default), JSON, or table, per --format."""
    from ..guidance import build_notes, render_notes

    notes = build_notes(data) if isinstance(data, dict) else None
    if notes:
        data = {**data, "debrief": notes}
    fmt = (ctx.obj or {}).get("format", DEFAULT_FMT)
    if fmt == "json":
        _echo_json(data)
    elif fmt == "md":
        click.echo(md_builder(data))
        extra = render_notes(notes)
        if extra:
            click.echo(extra)
    else:  # table
        click.echo(_table_from_json(data))


_CELL_MAX = 60
_LINE_MAX = 200


def _cell(value: object, limit: int = _LINE_MAX) -> str:
    s = str(value)
    s = s.replace("\n", "\\n").replace("\r", "\\r").replace("\t", " ")
    if len(s) > limit:
        s = s[: limit - 3] + "..."
    return s


def _table_from_list(items: list[dict], indent: str = "") -> list[str]:
    """Render a list of dicts as an aligned table with a header row."""
    headers: list[str] = []
    for item in items:
        for key in item:
            if key not in headers:
                headers.append(key)
    rows = [[_cell(item.get(h, ""), _CELL_MAX) for h in headers] for item in items]
    widths = [max([len(h)] + [len(r[i]) for r in rows]) for i, h in enumerate(headers)]
    pad = "  "
    lines = [
        indent + pad.join(h.ljust(widths[i]) for i, h in enumerate(headers)),
        indent + pad.join("-" * w for w in widths),
    ]
    lines.extend(
        indent + pad.join(r[i].ljust(widths[i]) for i in range(len(headers)))
        for r in rows
    )
    return lines


def _render_dict_block(value: dict, indent: str = "  ") -> list[str]:
    lines: list[str] = []
    for key, item in value.items():
        if isinstance(item, dict):
            lines.append(f"{indent}{key}:")
            lines.extend(_render_dict_block(item, indent + "  "))
        elif isinstance(item, list):
            if not item:
                lines.append(f"{indent}{key}\t[]")
            elif all(isinstance(entry, dict) for entry in item):
                lines.append(f"{indent}{key}:")
                lines.extend(_table_from_list(item, indent + "  "))
            else:
                lines.append(f"{indent}{key}\t{_cell(item)}")
        else:
            lines.append(f"{indent}{key}\t{_cell(item)}")
    return lines


def _render_debrief_table(value: dict) -> list[str]:
    lines: list[str] = []
    if value.get("verdict"):
        lines.append(f"  verdict\t{_cell(value['verdict'])}")
    for section in ("highlights", "next_steps"):
        items = value.get(section) or []
        if items:
            lines.append(f"  {section}:")
            lines.extend(f"    - {_cell(item)}" for item in items)
    for key, item in value.items():
        if key in ("verdict", "highlights", "next_steps"):
            continue
        if isinstance(item, dict):
            lines.append(f"  {key}:")
            lines.extend(_render_dict_block(item, "    "))
        elif isinstance(item, list):
            if not item:
                lines.append(f"  {key}\t[]")
            elif all(isinstance(entry, dict) for entry in item):
                lines.append(f"  {key}:")
                lines.extend(_table_from_list(item, "    "))
            else:
                lines.append(f"  {key}\t{_cell(item)}")
        else:
            lines.append(f"  {key}\t{_cell(item)}")
    return lines


def _table_from_json(data: dict) -> str:
    """Render structured command output as a scannable text table."""
    lines: list[str] = []
    for key, value in data.items():
        if key == "debrief" and isinstance(value, dict):
            lines.append("debrief:")
            lines.extend(_render_debrief_table(value))
        elif isinstance(value, list):
            if not value:
                lines.append(f"{key}\t[]")
            elif all(isinstance(item, dict) for item in value):
                lines.append(f"{key}:")
                lines.extend(_table_from_list(value))
            else:
                lines.append(f"{key}\t{_cell(value)}")
        elif isinstance(value, dict):
            lines.append(f"{key}:")
            lines.extend(_render_dict_block(value))
        else:
            lines.append(f"{key}\t{_cell(value)}")
    return "\n".join(lines)
