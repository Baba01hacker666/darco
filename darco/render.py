from __future__ import annotations

"""Markdown rendering for Darco CLI output.

Every human-facing command builds its data as a JSON-serializable dict (the
agent contract) and a markdown string (the human contract). `cli._emit` prints
one or the other based on `--format`. This module owns the markdown builders so
`cli.py` stays focused on wiring.
"""

from .models import Finding, to_json


def _kv(rows: list[tuple[str, str]]) -> str:
    return "\n".join(f"- **{k}**: {v}" for k, v in rows)


def _md_request(req: dict) -> str:
    lines = [f"- **method**: `{req.get('method', 'GET')}`", f"- **url**: {req.get('url', '')}"]
    if req.get("params"):
        params = ", ".join(f"`{p['name']}={p['value']}`" for p in req["params"])
        lines.append(f"- **params**: {params}")
    if req.get("headers"):
        headers = ", ".join(f"`{h['name']}: {h['value']}`" for h in req["headers"])
        lines.append(f"- **headers**: {headers}")
    bt = req.get("body_type")
    if bt and bt != "none":
        lines.append(f"- **body_type**: `{bt}`")
    if req.get("mutations"):
        lines.append("- **mutations**: " + " → ".join(f"`{m}`" for m in req["mutations"]))
    if req.get("parent_id"):
        lines.append(f"- **parent**: {req['parent_id']}")
    return "\n".join(lines)


def _md_finding(f: Finding) -> str:
    loc = f.location or ""
    head = f"- **[{f.severity}] `{f.type}`** — `{loc}`"
    ev = (f.evidence or "")[:300]
    out = [head, f"  - evidence: {ev}"]
    if f.suggestion:
        out.append(f"  - try: {f.suggestion}")
    return "\n".join(out)


def md_init(d: dict) -> str:
    return "# Workspace created\n\n" + _kv([
        ("status", str(d.get("status"))),
        ("workspace", str(d.get("workspace"))),
        ("target", str(d.get("target"))),
    ])


def md_store(d: dict) -> str:
    if "request" in d and "id" not in d:
        return "# Parsed request (dry-run)\n\n" + _md_request(d["request"])
    rid = d.get("id", "?")
    return f"# Stored `{rid}`\n\n" + _md_request(d["request"])


def md_send(d: dict) -> str:
    lines = [f"# Sent → `{d.get('id')}`", "", _md_request(d["request"]), ""]
    resp = d.get("response") or {}
    lines.append(f"**response**: `{resp.get('status_code')}` "
                 f"({resp.get('body_len', 0)} bytes, {resp.get('elapsed_ms', 0)} ms)")
    if d.get("diff"):
        lines.append("")
        lines.append(md_diff(d["diff"]))
    if d.get("fuzz"):
        lines.append("")
        lines.append(md_fuzz(d["fuzz"]))
    return "\n".join(lines)


def md_diff(d: dict) -> str:
    lines = ["## Diff", ""]
    st = d.get("status", {})
    lines.append(f"- **status**: `{st.get('a')}` → `{st.get('b')}`"
                 + ("  _changed_" if st.get("changed") else "  _same_"))
    hd = d.get("headers") or []
    if hd:
        lines.append("- **headers**:")
        for h in hd:
            lines.append(f"  - `{h['name']}`: `{h.get('a')}` → `{h.get('b')}`")
    body = d.get("body", {})
    lines.append(f"- **body**: {'changed' if body.get('changed') else 'unchanged'}")
    if body.get("json"):
        for c in (body.get("json_changes") or [])[:20]:
            lines.append(f"  - `{c}`")
    else:
        if body.get("added_lines"):
            lines.append(f"  - +{body['added_lines']} / -{body.get('removed_lines', 0)} lines")
    return "\n".join(lines)


def md_analyze(d: dict) -> str:
    findings = d.get("findings") or []
    lines = [f"# Analyze `{d.get('id')}`", "", f"**{len(findings)} finding(s)**", ""]
    if not findings:
        lines.append("_no findings_")
        return "\n".join(lines)
    for raw in findings:
        f = Finding.model_validate(raw) if isinstance(raw, dict) else raw
        lines.append(_md_finding(f))
    return "\n".join(lines)


def md_status(d: dict) -> str:
    cookies = ", ".join(f"`{c['name']}@{c.get('domain') or '*'}`" for c in d.get("cookies", [])) or "_none_"
    return "# Workspace status\n\n" + _kv([
        ("path", str(d.get("path"))),
        ("target", str(d.get("target"))),
        ("history", str(d.get("history_count"))),
        ("cookies", cookies),
        ("csrf hosts", ", ".join(f"`{h}`" for h in d.get("csrf_hosts", [])) or "_none_"),
        ("findings", str(d.get("findings_count"))),
        ("sitemap", "yes" if d.get("sitemap") else "no"),
    ])


def md_session(d: dict) -> str:
    cookies = d.get("cookies") or []
    lines = ["# Session", "", f"- **cookies**: {len(cookies)}"]
    for c in cookies:
        lines.append(f"  - `{c['name']}` = `{c.get('value', '')[:40]}`"
                     + (f"  (domain={c.get('domain')})" if c.get("domain") else ""))
    csrf = d.get("csrf_headers") or {}
    lines.append(f"- **csrf headers**: {len(csrf)} host(s)")
    for host, hs in csrf.items():
        vals = ", ".join(f"`{h['name']}`" for h in hs)
        lines.append(f"  - `{host}`: {vals}")
    return "\n".join(lines)


def md_repeat(d: dict) -> str:
    lines = ["# Repeat", "",
             f"- **from**: `{d.get('from')}`  **count**: `{d.get('count')}`",
             f"- **ids**: " + ", ".join(f"`{i}`" for i in d.get("ids", [])),
             f"- **statuses**: " + ", ".join(f"`{s}`" for s in d.get("statuses", [])),
             f"- **distinct**: " + ", ".join(f"`{s}`" for s in d.get("distinct_statuses", [])),
             f"- **errors**: `{d.get('errors', 0)}`"]
    return "\n".join(lines)


def md_findings_list(d: dict) -> str:
    found = d.get("findings") or []
    count = d.get("count", len(found))
    lines = [f"# Findings ({count})", ""]
    if not found:
        lines.append("_no findings_")
        return "\n".join(lines)
    for raw in found:
        f = Finding.model_validate(raw) if isinstance(raw, dict) else raw
        lines.append(_md_finding(f))
    return "\n".join(lines)


def md_discover(sitemap: dict) -> str:
    stats = sitemap.get("stats", {})
    lines = ["# Discovery report", "",
             "**stats**", _kv([
                 ("visited", str(stats.get("visited", 0))),
                 ("endpoints", str(stats.get("endpoints", 0))),
                 ("forms", str(stats.get("forms", 0))),
                 ("js_files", str(stats.get("js_files", 0))),
                 ("signals", str(stats.get("signals", 0))),
                 ("errors", str(stats.get("errors", 0))),
                 ("max_urls_reached", str(stats.get("max_urls_reached", False))),
             ]), ""]
    endpoints = sitemap.get("endpoints") or []
    if endpoints:
        lines.append(f"## Endpoints ({len(endpoints)})")
        lines.append("")
        lines.append("| Method | Path | Status | Source | Auth |")
        lines.append("| --- | --- | --- | --- | --- |")
        for e in endpoints[:50]:
            methods = ",".join(e.get("methods", [])) or "GET"
            auth = "yes" if e.get("auth_required") else "—"
            lines.append(f"| {methods} | `{e.get('url')}` | {e.get('status') or '?'} "
                         f"| {e.get('source')} | {auth} |")
        lines.append("")
    signals = sitemap.get("signals") or []
    if signals:
        lines.append(f"## Signals ({len(signals)})")
        lines.append("")
        for raw in signals[:30]:
            f = Finding.model_validate(raw) if isinstance(raw, dict) else raw
            lines.append(_md_finding(f))
    return "\n".join(lines)


def md_record(record: dict) -> str:
    req = record.get("request", {})
    lines = [f"# Record `{record.get('id')}`", "", _md_request(req)]
    if record.get("response"):
        resp = record["response"]
        lines.append("")
        lines.append(f"**response**: `{resp.get('status_code')}` "
                     f"({resp.get('body_len', 0)} bytes)")
    elif record.get("error"):
        lines.append("")
        lines.append(f"**error**: `{record['error']}`")
    return "\n".join(lines)


def md_fuzz(d: dict) -> str:
    lines = [
        "# Fuzz run",
        "",
        f"- **variants fired**: `{d.get('total_variants')}`",
        f"- **anomalies found**: `{d.get('anomalies')}`",
        f"- **baseline status**: `{d.get('baseline_status')}`",
        "",
    ]
    results = d.get("results") or []
    if not results:
        lines.append("_no anomalies vs baseline — everything behaved the same_")
        return "\n".join(lines)
    lines.append("## Interesting")
    lines.append("")
    for r in results:
        label = r.get("label")
        anomaly = r.get("anomaly")
        detail = r.get("detail") or ""
        status = r.get("status")
        muts = ", ".join(f"`{m}`" for m in r.get("mutations", [])) or "—"
        lines.append(f"- **{label}** → `{anomaly}`")
        if status is not None:
            lines.append(f"  - status: `{status}`")
        lines.append(f"  - what happened: {detail}")
        lines.append(f"  - did: {muts}")
    return "\n".join(lines)
