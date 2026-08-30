"""Path traversal auditor.

Injects traversal payloads into request parameters and looks for canonical
content signatures of the target files in the response body. Only signature
matches are reported, keeping false positives low.

Payloads cover Linux `/etc/passwd` and Windows `win.ini`, with plain,
dot-dot-stripped (`....//`) and percent-encoded variants.
"""

import httpx

from .engine import execute
from .models import (
    NameValue,
    Request,
    Response,
    SessionState,
    TraversalFinding,
    TraversalScanResult,
)
from .state_fields import is_state_field

_PASSWD_SIG = "root:x:0:0"
_WININI_SIG = "[extensions]"

# (payload, target_file_label, signatures that confirm file content)
_PROBES: list[tuple[str, str, tuple[str, ...]]] = [
    ("../../../../etc/passwd", "etc/passwd", (_PASSWD_SIG,)),
    ("....//....//....//....//etc/passwd", "etc/passwd", (_PASSWD_SIG,)),
    ("..%2f..%2f..%2f..%2fetc%2fpasswd", "etc/passwd", (_PASSWD_SIG,)),
    ("/etc/passwd", "etc/passwd", (_PASSWD_SIG,)),
    (r"..\..\..\..\windows\win.ini", "windows/win.ini", (_WININI_SIG,)),
    (
        r"....\\....\\....\\windows\win.ini",
        "windows/win.ini",
        (_WININI_SIG,),
    ),
]

_TRAVERSAL_HINTS = TRAVERSAL_PARAM_HINTS = frozenset(
    {
        "path",
        "file",
        "filename",
        "filepath",
        "file_path",
        "doc",
        "document",
        "docs",
        "folder",
        "dir",
        "directory",
        "include",
        "require",
        "tpl",
        "template",
        "page",
        "view",
        "read",
        "download",
        "dl",
        "get",
        "load",
        "open",
        "src",
        "source",
        "cat",
        "show",
        "name",
        "module",
        "attachment",
        "static",
        "asset",
        "resource",
        "lang",
        "locale",
        "layout",
        "partial",
        "config",
    }
)


def _send(req: Request, session: SessionState) -> Response | None:
    try:
        res = execute(req, session)
        if isinstance(res, tuple) and len(res) >= 2:
            return res[1]
        elif isinstance(res, Response):
            return res
        return None
    except (httpx.HTTPError, OSError, TimeoutError, ValueError):
        return None


def _clone_and_mutate_param(
    base: Request, param_type: str, param_name: str, new_val: str
) -> Request:
    req = base.model_copy(deep=True)
    if param_type == "query":
        req.params = [
            NameValue(name=p.name, value=new_val if p.name == param_name else p.value)
            for p in req.params
        ]
    elif param_type == "form":
        req.body_form = [
            NameValue(name=p.name, value=new_val if p.name == param_name else p.value)
            for p in req.body_form
        ]
    elif param_type == "json" and isinstance(req.body_json, dict):
        d = dict(req.body_json)
        d[param_name] = new_val
        req.body_json = d
    return req


def _looks_like_file_or_path(val: str) -> bool:
    if not val or len(val) > 256:
        return False
    v = val.strip()
    if "/" in v or "\\" in v:
        return True
    if "." in v and not v.startswith(".") and not v.endswith("."):
        ext = v.rsplit(".", 1)[-1].lower()
        if ext in {
            "txt",
            "pdf",
            "html",
            "htm",
            "php",
            "asp",
            "aspx",
            "jsp",
            "json",
            "xml",
            "csv",
            "log",
            "ini",
            "conf",
            "config",
            "yml",
            "yaml",
            "png",
            "jpg",
            "jpeg",
            "gif",
            "svg",
            "doc",
            "docx",
            "xls",
            "xlsx",
            "zip",
            "tar",
            "gz",
            "sql",
            "sh",
            "py",
            "rb",
            "js",
            "css",
            "env",
            "bak",
        }:
            return True
    return False


def _is_traversal_candidate(name: str) -> bool:
    normalized = name.lower().replace("-", "").replace("_", "").replace(".", "")
    return normalized in _TRAVERSAL_HINTS


def scan_traversal(
    request: Request,
    session: SessionState | None = None,
    param_filter: str | None = None,
    include_state_fields: bool = False,
) -> TraversalScanResult:
    """Audit a request's parameters for path traversal file disclosure."""
    if session is None:
        session = SessionState()

    candidates: list[tuple[str, str]] = []
    sources = (
        [("query", p.name, p.value or "") for p in request.params]
        + [("form", p.name, p.value or "") for p in request.body_form]
        + (
            [
                ("json", k, str(v) if v is not None else "")
                for k, v in request.body_json.items()
            ]
            if isinstance(request.body_json, dict)
            else []
        )
    )
    for p_type, name, val in sources:
        if param_filter:
            if name != param_filter:
                continue
        else:
            if not include_state_fields and is_state_field(name):
                continue
            if not (_is_traversal_candidate(name) or _looks_like_file_or_path(val)):
                continue
        candidates.append((p_type, name))

    result = TraversalScanResult(
        target=request.url,
        tested_params=[name for _, name in candidates],
    )

    for p_type, p_name in candidates:
        found: TraversalFinding | None = None
        for payload, target_file, signatures in _PROBES:
            probe_req = _clone_and_mutate_param(request, p_type, p_name, payload)
            resp = _send(probe_req, session)
            if not resp or not resp.body:
                continue

            matched = next((s for s in signatures if s in resp.body), None)
            if matched:
                found = TraversalFinding(
                    param=p_name,
                    param_type=p_type,
                    target_file=target_file,
                    confidence="confirmed",
                    payload=payload,
                    status_code=resp.status_code,
                    evidence=(
                        f"Response contains '{target_file}' content signature "
                        f"'{matched}' ({resp.status_code})"
                    ),
                    suggestion=(
                        f"Normalize and resolve the value of '{p_name}' against an "
                        "allowlisted base directory; reject separators and parent "
                        "references before touching the filesystem."
                    ),
                )
                break

        if found:
            result.findings.append(found)

    return result


__all__ = ["TRAVERSAL_PARAM_HINTS", "scan_traversal"]
