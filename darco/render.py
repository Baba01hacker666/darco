from __future__ import annotations

"""Markdown rendering for Darco CLI output.

Every human-facing command builds its data as a JSON-serializable dict (the
agent contract) and a markdown string (the human contract). `cli._emit` prints
one or the other based on `--format`. This module owns the markdown builders so
`cli.py` stays focused on wiring.
"""

from .models import Finding


def _kv(rows: list[tuple[str, str]]) -> str:
    return "\n".join(f"- **{k}**: {v}" for k, v in rows)


def _md_request(req: dict) -> str:
    lines = [
        f"- **method**: `{req.get('method', 'GET')}`",
        f"- **url**: {req.get('url', '')}",
    ]
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
        lines.append(
            "- **mutations**: " + " → ".join(f"`{m}`" for m in req["mutations"])
        )
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
    return "# Workspace created\n\n" + _kv(
        [
            ("status", str(d.get("status"))),
            ("workspace", str(d.get("workspace"))),
            ("target", str(d.get("target"))),
        ]
    )


def md_store(d: dict) -> str:
    if "request" in d and "id" not in d:
        return "# Parsed request (dry-run)\n\n" + _md_request(d["request"])
    rid = d.get("id", "?")
    return f"# Stored `{rid}`\n\n" + _md_request(d["request"])


def md_send(d: dict) -> str:
    rid = d.get("id")
    resp = d.get("response") or {}
    req = d.get("request") or {}
    status_code = resp.get("status_code", "")
    reason = resp.get("reason", "")

    if rid:
        header = f"# Sent → `{rid}`"
    else:
        header = "# Sent"

    lines = [header, "", _md_request(req), ""]
    if resp:
        body_len = resp.get("body_len", 0)
        elapsed_ms = resp.get("elapsed_ms", 0)
        status_str = (
            f"`{status_code} {reason}`".strip() if reason else f"`{status_code}`"
        )
        lines.append(f"**response**: {status_str} ({body_len} bytes, {elapsed_ms} ms)")
        resp_headers = resp.get("headers") or []
        notable = [
            h
            for h in resp_headers
            if h.get("name", "").lower()
            in {
                "content-type",
                "server",
                "set-cookie",
                "location",
                "retry-after",
                "www-authenticate",
            }
        ]
        if notable:
            lines.append(
                "- **response headers**: "
                + ", ".join(f"`{h['name']}: {h['value']}`" for h in notable)
            )
        if d.get("wafs"):
            waf_list = d["wafs"]
            waf_strs = []
            for w in waf_list:
                w_name = w.get("name") if isinstance(w, dict) else getattr(w, "name", "")
                w_blk = " (BLOCKED)" if (w.get("blocked") if isinstance(w, dict) else getattr(w, "blocked", False)) else ""
                waf_strs.append(f"`{w_name}{w_blk}`")
            lines.append("- **WAF / Shield**: " + ", ".join(waf_strs))

        if d.get("technologies"):
            tech_list = d["technologies"]
            tech_strs = []
            for t in tech_list:
                t_name = t.get("name") if isinstance(t, dict) else getattr(t, "name", "")
                t_ver = t.get("version") if isinstance(t, dict) else getattr(t, "version", None)
                t_cat = t.get("category") if isinstance(t, dict) else getattr(t, "category", "")
                v_str = f" {t_ver}" if t_ver else ""
                tech_strs.append(f"`{t_name}{v_str}` ({t_cat})")
            lines.append("- **Technologies**: " + ", ".join(tech_strs))

        body = resp.get("body", "")
        if body:
            body_lines = body.splitlines()
            preview = "\n".join(body_lines[:15])
            if len(body_lines) > 15:
                preview += f"\n... [{len(body_lines) - 15} more lines]"
            lines.append("")
            lines.append("```")
            lines.append(preview)
            lines.append("```")
    elif d.get("error"):
        lines.append(f"**error**: `{d.get('error')}`")

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
    lines.append(
        f"- **status**: `{st.get('a')}` → `{st.get('b')}`"
        + ("  _changed_" if st.get("changed") else "  _same_")
    )
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
            lines.append(
                f"  - +{body['added_lines']} / -{body.get('removed_lines', 0)} lines"
            )
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
    cookies = (
        ", ".join(
            f"`{c['name']}@{c.get('domain') or '*'}`" for c in d.get("cookies", [])
        )
        or "_none_"
    )
    return "# Workspace status\n\n" + _kv(
        [
            ("path", str(d.get("path"))),
            ("target", str(d.get("target"))),
            ("history", str(d.get("history_count"))),
            ("cookies", cookies),
            (
                "csrf hosts",
                ", ".join(f"`{h}`" for h in d.get("csrf_hosts", [])) or "_none_",
            ),
            ("findings", str(d.get("findings_count"))),
            ("sitemap", "yes" if d.get("sitemap") else "no"),
        ]
    )


def md_session(d: dict) -> str:
    cookies = d.get("cookies") or []
    lines = ["# Session", "", f"- **cookies**: {len(cookies)}"]
    for c in cookies:
        lines.append(
            f"  - `{c['name']}` = `{c.get('value', '')[:40]}`"
            + (f"  (domain={c.get('domain')})" if c.get("domain") else "")
        )
    csrf = d.get("csrf_headers") or {}
    lines.append(f"- **csrf headers**: {len(csrf)} host(s)")
    for host, hs in csrf.items():
        vals = ", ".join(f"`{h['name']}`" for h in hs)
        lines.append(f"  - `{host}`: {vals}")
    return "\n".join(lines)


def md_repeat(d: dict) -> str:
    lines = [
        "# Repeat",
        "",
        f"- **from**: `{d.get('from')}`  **count**: `{d.get('count')}`",
        "- **ids**: " + ", ".join(f"`{i}`" for i in d.get("ids", [])),
        "- **statuses**: " + ", ".join(f"`{s}`" for s in d.get("statuses", [])),
        "- **distinct**: "
        + ", ".join(f"`{s}`" for s in d.get("distinct_statuses", [])),
        f"- **errors**: `{d.get('errors', 0)}`",
    ]
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
    lines = [
        "# Discovery report",
        "",
        "**stats**",
        _kv(
            [
                ("visited", str(stats.get("visited", 0))),
                ("endpoints", str(stats.get("endpoints", 0))),
                ("forms", str(stats.get("forms", 0))),
                ("js_files", str(stats.get("js_files", 0))),
                ("signals", str(stats.get("signals", 0))),
                ("errors", str(stats.get("errors", 0))),
                ("max_urls_reached", str(stats.get("max_urls_reached", False))),
            ]
        ),
        "",
    ]
    endpoints = sitemap.get("endpoints") or []
    if endpoints:
        lines.append(f"## Endpoints ({len(endpoints)})")
        lines.append("")
        lines.append("| Method | Path | Status | Source | Auth |")
        lines.append("| --- | --- | --- | --- | --- |")
        for e in endpoints[:50]:
            methods = ",".join(e.get("methods", [])) or "GET"
            auth = "yes" if e.get("auth_required") else "—"
            lines.append(
                f"| {methods} | `{e.get('url')}` | {e.get('status') or '?'} "
                f"| {e.get('source')} | {auth} |"
            )
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
        lines.append(
            f"**response**: `{resp.get('status_code')}` "
            f"({resp.get('body_len', 0)} bytes)"
        )
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


def md_detect(d: dict) -> str:
    target = d.get("target") or d.get("url") or ""
    lines = [f"# Detection report: `{target}`" if target else "# Detection report", ""]
    wafs = d.get("wafs") or []
    if wafs:
        lines.append(f"## WAF & Shields ({len(wafs)})")
        lines.append("")
        for w in wafs:
            name = w.get("name") if isinstance(w, dict) else getattr(w, "name", "")
            vendor = w.get("vendor") if isinstance(w, dict) else getattr(w, "vendor", "")
            conf = w.get("confidence") if isinstance(w, dict) else getattr(w, "confidence", "high")
            evid = w.get("evidence") if isinstance(w, dict) else getattr(w, "evidence", "")
            blocked = w.get("blocked") if isinstance(w, dict) else getattr(w, "blocked", False)
            block_tag = " `[BLOCKED REQUEST]`" if blocked else ""
            vendor_str = f" ({vendor})" if vendor else ""
            lines.append(f"- **{name}**{vendor_str} — `{conf}` confidence{block_tag}")
            if evid:
                lines.append(f"  - Evidence: `{evid}`")
        lines.append("")
    else:
        lines.append("## WAF & Shields")
        lines.append("")
        lines.append("_No active WAF / CDN shields identified._")
        lines.append("")

    techs = d.get("technologies") or []
    if techs:
        lines.append(f"## Technologies ({len(techs)})")
        lines.append("")
        lines.append("| Technology | Category | Version | Confidence | Evidence |")
        lines.append("| --- | --- | --- | --- | --- |")
        for t in techs:
            name = t.get("name") if isinstance(t, dict) else getattr(t, "name", "")
            cat = t.get("category") if isinstance(t, dict) else getattr(t, "category", "")
            ver = (t.get("version") if isinstance(t, dict) else getattr(t, "version", None)) or "—"
            conf = t.get("confidence") if isinstance(t, dict) else getattr(t, "confidence", "high")
            evid = (t.get("evidence") if isinstance(t, dict) else getattr(t, "evidence", "")) or "—"
            lines.append(f"| **{name}** | `{cat}` | {ver} | {conf} | `{evid}` |")
    else:
        lines.append("## Technologies")
        lines.append("")
        lines.append("_No specific technology signatures matched._")

    return "\n".join(lines)


def md_passive(d: dict) -> str:
    domain = d.get("domain") or d.get("target") or ""
    lines = [f"# Passive Reconnaissance: `{domain}`", ""]

    # Target & IPs
    ips = d.get("ip_addresses") or []
    if ips:
        lines.append(f"**IP Addresses**: {', '.join(f'`{ip}`' for ip in ips)}")
        lines.append("")

    # WAF & Technologies
    wafs = d.get("wafs") or []
    if wafs:
        waf_strs = []
        for w in wafs:
            w_name = w.get("name") if isinstance(w, dict) else getattr(w, "name", "")
            w_blk = " (BLOCKED)" if (w.get("blocked") if isinstance(w, dict) else getattr(w, "blocked", False)) else ""
            waf_strs.append(f"`{w_name}{w_blk}`")
        lines.append(f"**WAF / Shield**: {', '.join(waf_strs)}")

    techs = d.get("technologies") or []
    if techs:
        tech_strs = []
        for t in techs:
            t_name = t.get("name") if isinstance(t, dict) else getattr(t, "name", "")
            t_ver = t.get("version") if isinstance(t, dict) else getattr(t, "version", None)
            t_cat = t.get("category") if isinstance(t, dict) else getattr(t, "category", "")
            v_str = f" {t_ver}" if t_ver else ""
            tech_strs.append(f"`{t_name}{v_str}` ({t_cat})")
        lines.append(f"**Technologies**: {', '.join(tech_strs)}")

    if wafs or techs:
        lines.append("")

    # DNS Records
    dns_recs = d.get("dns_records") or []
    if dns_recs:
        lines.append(f"## DNS Records ({len(dns_recs)})")
        lines.append("")
        lines.append("| Type | Name | Value | TTL |")
        lines.append("| --- | --- | --- | --- |")
        for r in dns_recs:
            rtype = r.get("record_type") if isinstance(r, dict) else getattr(r, "record_type", "")
            name = r.get("name") if isinstance(r, dict) else getattr(r, "name", "")
            val = r.get("value") if isinstance(r, dict) else getattr(r, "value", "")
            ttl = (r.get("ttl") if isinstance(r, dict) else getattr(r, "ttl", None)) or "—"
            lines.append(f"| `{rtype}` | `{name}` | `{val}` | {ttl} |")
        lines.append("")

    # Subdomains (CT logs)
    subdomains = d.get("subdomains") or []
    if subdomains:
        lines.append(f"## Subdomains ({len(subdomains)}) — Certificate Transparency")
        lines.append("")
        for sub in subdomains[:100]:
            lines.append(f"- `{sub}`")
        if len(subdomains) > 100:
            lines.append(f"- _...and {len(subdomains) - 100} more subdomains_")
        lines.append("")

    # Security Headers
    present_hdrs = d.get("security_headers") or {}
    missing_hdrs = d.get("missing_security_headers") or []
    if present_hdrs or missing_hdrs:
        lines.append("## Security Headers")
        lines.append("")
        for h, v in present_hdrs.items():
            lines.append(f"- ✅ **{h}**: `{v[:80]}`")
        for h in missing_hdrs:
            lines.append(f"- ❌ **{h}**: _missing_")
        lines.append("")

    # Security.txt
    sec_txt = d.get("security_txt") or {}
    if sec_txt and (sec_txt.get("present") if isinstance(sec_txt, dict) else getattr(sec_txt, "present", False)):
        contacts = (sec_txt.get("contact") if isinstance(sec_txt, dict) else getattr(sec_txt, "contact", [])) or []
        expires = sec_txt.get("expires") if isinstance(sec_txt, dict) else getattr(sec_txt, "expires", None)
        lines.append("## security.txt (RFC 9116)")
        lines.append("")
        lines.append(f"- **URL**: `{sec_txt.get('url')}`")
        if contacts:
            lines.append(f"- **Contact**: {', '.join(f'`{c}`' for c in contacts)}")
        if expires:
            lines.append(f"- **Expires**: `{expires}`")
        lines.append("")

    # Findings
    findings = d.get("findings") or []
    if findings:
        lines.append(f"## Security Posture & Signals ({len(findings)})")
        lines.append("")
        for raw in findings:
            f = Finding.model_validate(raw) if isinstance(raw, dict) else raw
            lines.append(_md_finding(f))

    return "\n".join(lines)
