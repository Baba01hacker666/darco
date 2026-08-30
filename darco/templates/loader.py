"""Template parser and loader for YAML and JSON attack templates."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from ..errors import DarcoError
from .models import (
    AttackTemplate,
    TemplateExtractor,
    TemplateInfo,
    TemplateMatcher,
    TemplateRequest,
)

BUILTIN_TEMPLATES_DIR = Path(__file__).parent / "builtin"


def _normalize_dict_keys(d: Any) -> Any:
    """Recursively convert hyphenated keys (matchers-condition) to underscores."""
    if isinstance(d, dict):
        out = {}
        for k, v in d.items():
            norm_k = k.replace("-", "_")
            out[norm_k] = _normalize_dict_keys(v)
        return out
    elif isinstance(d, list):
        return [_normalize_dict_keys(i) for i in d]
    return d


def load_template_from_string(content: str, path: str = "") -> AttackTemplate:
    """Parse a template string in YAML or JSON format into an AttackTemplate model."""
    try:
        raw = yaml.safe_load(content)
    except Exception as e:
        raise DarcoError(f"Failed to parse template YAML/JSON {path}: {e}") from e

    if not isinstance(raw, dict):
        raise DarcoError(f"Invalid template structure in {path}: expected a dictionary mapping")

    norm = _normalize_dict_keys(raw)

    t_id = norm.get("id") or (Path(path).stem if path else "untitled-template")
    raw_info = norm.get("info") or {}
    if not isinstance(raw_info, dict):
        raw_info = {"name": str(raw_info)}

    # Parse info block
    info = TemplateInfo(
        name=raw_info.get("name") or t_id,
        author=raw_info.get("author", "darco"),
        severity=(raw_info.get("severity") or "info").lower(),
        description=raw_info.get("description", ""),
        tags=[t.strip() for t in raw_info.get("tags", "").split(",") if t.strip()]
        if isinstance(raw_info.get("tags"), str)
        else raw_info.get("tags", []),
        reference=raw_info.get("reference")
        if isinstance(raw_info.get("reference"), list)
        else ([raw_info.get("reference")] if raw_info.get("reference") else []),
        remediation=raw_info.get("remediation", ""),
        metadata=raw_info.get("metadata", {}),
    )

    # Support both "requests" and "http" top-level sections (Nuclei compatibility)
    raw_requests = norm.get("requests") or norm.get("http") or []
    if isinstance(raw_requests, dict):
        raw_requests = [raw_requests]

    requests: list[TemplateRequest] = []
    for req_dict in raw_requests:
        if not isinstance(req_dict, dict):
            continue

        paths = req_dict.get("path") or req_dict.get("raw") or ["{{BaseURL}}"]
        if isinstance(paths, str):
            paths = [paths]

        matchers: list[TemplateMatcher] = []
        for m in req_dict.get("matchers", []):
            if not isinstance(m, dict):
                continue
            words = m.get("words") or m.get("word") or []
            if isinstance(words, str):
                words = [words]
            regex_list = m.get("regex") or []
            if isinstance(regex_list, str):
                regex_list = [regex_list]
            status_list = m.get("status") or m.get("status_code") or []
            if isinstance(status_list, int):
                status_list = [status_list]
            sizes_list = m.get("sizes") or m.get("size") or []
            if isinstance(sizes_list, int):
                sizes_list = [sizes_list]
            dsl_list = m.get("dsl") or []
            if isinstance(dsl_list, str):
                dsl_list = [dsl_list]
            binary_list = m.get("binary") or []
            if isinstance(binary_list, str):
                binary_list = [binary_list]
            xpath_list = m.get("xpath") or []
            if isinstance(xpath_list, str):
                xpath_list = [xpath_list]
            json_keys = m.get("json") or m.get("json_keys") or []
            if isinstance(json_keys, str):
                json_keys = [json_keys]

            matchers.append(
                TemplateMatcher(
                    type=m.get("type", "word"),
                    part=m.get("part", "body"),
                    condition=m.get("condition", "or"),
                    negative=bool(m.get("negative", False)),
                    words=words,
                    regex=regex_list,
                    status=status_list,
                    sizes=sizes_list,
                    dsl=dsl_list,
                    binary=binary_list,
                    xpath=xpath_list,
                    json_keys=json_keys,
                    min_ms=int(m.get("min_ms", m.get("min-ms", 0)) or 0),
                    case_sensitive=bool(m.get("case_sensitive", False)),
                )
            )

        extractors: list[TemplateExtractor] = []
        for ext in req_dict.get("extractors", []):
            if not isinstance(ext, dict):
                continue
            r_list = ext.get("regex") or []
            if isinstance(r_list, str):
                r_list = [r_list]
            k_list = ext.get("kval") or []
            if isinstance(k_list, str):
                k_list = [k_list]
            j_list = ext.get("json") or ext.get("json_keys") or []
            if isinstance(j_list, str):
                j_list = [j_list]
            x_list = ext.get("xpath") or []
            if isinstance(x_list, str):
                x_list = [x_list]

            extractors.append(
                TemplateExtractor(
                    type=ext.get("type", "regex"),
                    name=ext.get("name", ""),
                    part=ext.get("part", "body"),
                    internal=bool(ext.get("internal", False)),
                    regex=r_list,
                    group=int(ext.get("group", 1)),
                    kval=k_list,
                    json_keys=j_list,
                    xpath=x_list,
                )
            )

        requests.append(
            TemplateRequest(
                method=(req_dict.get("method") or "GET").upper(),
                path=paths,
                headers=req_dict.get("headers", {}),
                body=req_dict.get("body", ""),
                matchers_condition=req_dict.get("matchers_condition", "or"),
                matchers=matchers,
                extractors=extractors,
                redirects=bool(req_dict.get("redirects", False)),
                max_redirects=int(req_dict.get("max_redirects", 3)),
                stop_at_first_match=bool(req_dict.get("stop_at_first_match", False)),
            )
        )

    return AttackTemplate(
        id=t_id,
        info=info,
        requests=requests,
        variables=norm.get("variables", {}),
        raw_path=str(path),
    )


def load_template(path: str | Path) -> AttackTemplate:
    """Load an AttackTemplate from a file path."""
    p = Path(path)
    if not p.is_file():
        raise DarcoError(f"Template file not found: {p}")
    content = p.read_text(encoding="utf-8")
    return load_template_from_string(content, path=str(p))


def load_templates_from_dir(
    dir_path: str | Path,
    tags: list[str] | None = None,
    severities: list[str] | None = None,
    recursive: bool = True,
) -> list[AttackTemplate]:
    """Load all YAML/JSON templates from a directory with optional tag/severity filters."""
    p = Path(dir_path)
    if not p.is_dir():
        if p.is_file():
            return [load_template(p)]
        raise DarcoError(f"Template directory not found: {p}")

    patterns = ["*.yaml", "*.yml", "*.json"]
    files: list[Path] = []
    for pat in patterns:
        if recursive:
            files.extend(p.rglob(pat))
        else:
            files.extend(p.glob(pat))

    templates: list[AttackTemplate] = []
    for f in sorted(set(files)):
        try:
            t = load_template(f)
            # Tag filter
            if tags:
                lower_tags = {tag.lower() for tag in tags}
                t_tags = {tag.lower() for tag in t.info.tags}
                if not lower_tags.intersection(t_tags):
                    continue
            # Severity filter
            if severities:
                lower_sevs = {s.lower() for s in severities}
                if t.info.severity.lower() not in lower_sevs:
                    continue
            templates.append(t)
        except (DarcoError, OSError, yaml.YAMLError):
            continue

    return templates


def load_builtin_templates(
    tags: list[str] | None = None,
    severities: list[str] | None = None,
) -> list[AttackTemplate]:
    """Load built-in templates included with darco."""
    if not BUILTIN_TEMPLATES_DIR.exists():
        return []
    return load_templates_from_dir(BUILTIN_TEMPLATES_DIR, tags=tags, severities=severities)
