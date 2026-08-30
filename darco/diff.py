from __future__ import annotations

import difflib
import json
import re

from .models import Response

VOLATILE_HEADERS = {"date", "set-cookie", "age"}

_TS_RE = re.compile(r"\b\d{10,13}\b")
_HEX_RE = re.compile(r"\b[0-9a-fA-F]{24,}\b")
_TOKEN_RE = re.compile(r"(?i)\b(token|csrf|xsrf|nonce)([=:]\s*)?[A-Za-z0-9._\-]{8,}")


def normalize_body(text: str) -> str:
    """Normalize volatile tokens (timestamps, long hex, csrf-ish values) for diffing."""
    if not text:
        return ""
    text = _TS_RE.sub("<ts>", text)
    text = _HEX_RE.sub("<hex>", text)
    text = _TOKEN_RE.sub(lambda m: m.group(1) + (m.group(2) or "=") + "<tok>", text)
    return text


def _json_path_diff(a, b, prefix=""):
    changes: list[str] = []
    if isinstance(a, dict) and isinstance(b, dict):
        for key in sorted(set(a) | set(b)):
            if key not in a:
                changes.append(f"{prefix}{key}: added {b[key]!r}")
            elif key not in b:
                changes.append(f"{prefix}{key}: removed {a[key]!r}")
            else:
                changes.extend(_json_path_diff(a[key], b[key], f"{prefix}{key}."))
    elif isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            changes.append(f"{prefix}[len {len(a)} -> {len(b)}]")
        min_len = min(len(a), len(b))
        for i in range(min_len):
            changes.extend(_json_path_diff(a[i], b[i], f"{prefix}[{i}]."))
        if len(a) > min_len:
            for i in range(min_len, len(a)):
                changes.append(f"{prefix}[{i}]: removed {a[i]!r}")
        elif len(b) > min_len:
            for i in range(min_len, len(b)):
                changes.append(f"{prefix}[{i}]: added {b[i]!r}")
    elif a != b:
        changes.append(f"{prefix}changed {a!r} -> {b!r}")
    return changes


def _header_map(headers) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for h in headers:
        key = h.name.lower()
        if key in VOLATILE_HEADERS:
            continue
        out.setdefault(key, []).append(h.value)
    return out


def diff_responses(a: Response, b: Response) -> dict:
    """Structured diff between two stored responses."""
    headers_a = _header_map(a.headers)
    headers_b = _header_map(b.headers)

    header_diffs: list[dict] = []
    for name in sorted(set(headers_a) | set(headers_b)):
        va, vb = headers_a.get(name), headers_b.get(name)
        if va != vb:
            header_diffs.append(
                {"name": name, "a": ", ".join(va or []), "b": ", ".join(vb or [])}
            )

    norm_a = normalize_body(a.body)
    norm_b = normalize_body(b.body)
    body_changed = norm_a != norm_b
    body_section: dict = {"changed": body_changed}
    json_changes: list[str] | None = None
    try:
        ja = json.loads(a.body)
        jb = json.loads(b.body)
        json_changes = _json_path_diff(ja, jb)
        body_section["json"] = True
    except (json.JSONDecodeError, ValueError):
        diff_lines = list(
            difflib.unified_diff(
                norm_a.splitlines(),
                norm_b.splitlines(),
                fromfile="a",
                tofile="b",
                lineterm="",
            )
        )
        added = sum(
            1 for ln in diff_lines if ln.startswith("+") and not ln.startswith("+++")
        )
        removed = sum(
            1 for ln in diff_lines if ln.startswith("-") and not ln.startswith("---")
        )
        body_section["json"] = False
        body_section["added_lines"] = added
        body_section["removed_lines"] = removed
        body_section["hunks"] = diff_lines[:40]
    body_section["json_changes"] = json_changes

    return {
        "status": {
            "a": a.status_code,
            "b": b.status_code,
            "changed": a.status_code != b.status_code,
        },
        "headers": header_diffs,
        "body": body_section,
        "elapsed_ms": {"a": a.elapsed_ms, "b": b.elapsed_ms},
        "body_len": {"a": a.body_len, "b": b.body_len},
    }
