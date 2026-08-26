"""Human-friendly debrief notes for Darco's structured output.

The JSON/structured output stays the machine contract; this module attaches a
``notes`` block that reads like a teammate's debrief: what was found, how sure
we are, and exactly how to verify it manually before reporting it.
"""

from __future__ import annotations

from urllib.parse import quote

_CONF_ORDER = {"confirmed": 0, "high": 1, "medium": 2, "low": 3, "potential": 4}


def _curl_for(target: str, param: str, param_type: str, payload: str) -> str:
    """Build a copy-paste curl command that reproduces a finding."""
    enc = quote(payload, safe="")
    if param_type == "form":
        return f"curl -i -X POST '{target}' -d '{param}={enc}'"
    return f"curl -i '{target}?{param}={enc}'"


def _worst_conf(vulns: list[dict]) -> str:
    confs = [str(v.get("confidence") or "potential").lower() for v in vulns]
    return min(confs, key=lambda c: _CONF_ORDER.get(c, 9))


# ------------------------------------------------------------------ SQLi
def sqli_notes(data: dict) -> dict:
    vulns = data.get("vulnerabilities") or []
    target = data.get("target") or ""
    tested = data.get("tested_params") or []

    if not vulns:
        return {
            "verdict": f"No SQL injection signals on `{target}` — clean, but only as good as the parameters we probed.",
            "highlights": [
                f"Tested {len(tested)} parameter(s): "
                + (", ".join(f"`{p}`" for p in tested) or "_none_")
                + "."
            ],
            "next_steps": [
                "Probe hidden parameters (IDs, sort, filter, debug flags) and re-run `darco sql` on them.",
                "If the app has login/forms, test those fields too — quote-balancing in auth flows is a favorite.",
            ],
        }

    worst = _worst_conf(vulns)
    verdict = (
        f"Found {len(vulns)} potential SQL injection point(s) on `{target}` "
        f"(worst confidence: **{worst}**). Treat them as **suspected until you "
        f"verify manually** — then they're solid findings to report."
    )

    highlights = []
    for v in vulns[:6]:
        conf = str(v.get("confidence") or "potential").upper()
        param = v.get("param") or "?"
        itype = v.get("injection_type") or "unknown"
        payload = v.get("payload") or ""
        line = f"`{conf}` — `{param}` looks injectable via `{itype}`"
        if payload:
            line += f" (probe `{payload}`)"
        highlights.append(line)
    if len(vulns) > 6:
        highlights.append(f"…and {len(vulns) - 6} more signal(s).")

    xml_vulns = [
        v
        for v in vulns
        if v.get("injection_type") in ("xml_entity_decoding", "xml_encoded_sqli")
    ]
    if xml_vulns:
        highlights.append(
            "XML channel confirmed — the endpoint parses XML and expands `&#x..;` "
            "character references, so SQL keywords can be smuggled past "
            "signature-based WAFs. Replay the `Verify manually` curl to confirm."
        )

    next_steps = [
        "Replay the probe payloads in a browser/curl and look for the DB error, empty page, or extra rows.",
    ]
    top = vulns[0]
    if any(v.get("param_type") == "xml" for v in vulns):
        top_curl = next((v.get("curl") for v in vulns if v.get("curl")), "")
        if top_curl:
            next_steps.append(f"Fastest manual check (XML channel): `{top_curl}`")
        else:
            next_steps.append(
                "This is an XML-body endpoint: replay the entity-encoded payload with "
                "`-H 'Content-Type: application/xml' --data-binary '<storeId>&#x..;</storeId>'`."
            )
    else:
        curl = _curl_for(
            target,
            top.get("param") or "",
            top.get("param_type") or "query",
            top.get("payload") or "",
        )
        next_steps.append(f"Fastest manual check: `{curl}`")
    if any(v.get("injection_type") == "sql_logic" for v in vulns):
        next_steps.append(
            "The OR-logic finding means hidden/unreleased rows may be retrievable — "
            "compare the payload response against the baseline product count."
        )
    next_steps.append(
        "Fix: parameterized queries / prepared statements, and report the evidence + payload."
    )
    return {"verdict": verdict, "highlights": highlights, "next_steps": next_steps}


# ------------------------------------------------------------------ XSS
def xss_notes(data: dict) -> dict:
    refls = data.get("reflections") or []
    target = data.get("target") or ""
    tested = data.get("tested_params") or []

    if not refls:
        return {
            "verdict": f"No reflection signals on `{target}` — this is a reflection-only audit, so don't rule XSS out entirely.",
            "highlights": [
                f"Tested {len(tested)} parameter(s): "
                + (", ".join(f"`{p}`" for p in tested) or "_none_")
                + "."
            ],
            "next_steps": [
                "Stored XSS (comments, profiles, uploads) won't show up here — test those flows manually.",
                "Try DOM sinks (location, innerHTML, eval) and JS files with `darco js`.",
            ],
        }

    worst = _worst_conf(refls)
    verdict = (
        f"Found {len(refls)} reflection point(s) on `{target}` "
        f"(worst confidence: **{worst}**). Reflected input is the raw material "
        f"for XSS — verify whether it actually executes in a browser."
    )

    highlights = []
    for r in refls[:6]:
        conf = str(r.get("confidence") or "potential").upper()
        param = r.get("param") or "?"
        ctx = r.get("context") or "unknown"
        un = r.get("unencoded_chars") or []
        enc = r.get("encoded_chars") or []
        line = f"`{conf}` — `{param}` reflects in `{ctx}`"
        if un:
            line += f" with **unencoded** {', '.join(un)} (execution potential!)"
        elif enc:
            line += f" — only encoded output {', '.join(enc)} (lower risk)"
        highlights.append(line)
    if len(refls) > 6:
        highlights.append(f"…and {len(refls) - 6} more.")

    next_steps = [
        "Paste `'><script>alert(document.domain)</script>` into the reflected field in a browser.",
        "Unencoded `<>` in a raw HTML context is likely exploitable; encoded output needs a decoding sink (JSON, URL, JS template).",
        "Fix: context-aware output encoding + a strict Content-Security-Policy.",
    ]
    return {"verdict": verdict, "highlights": highlights, "next_steps": next_steps}


# ------------------------------------------------------------------ Fuzz
def fuzz_notes(data: dict) -> dict:
    total = data.get("total_variants") or 0
    results = data.get("results") or []
    target = data.get("target") or ""
    verdict = (
        f"Fuzzed {total} variant(s) and {len(results)} behaved differently on "
        f"`{target}`. Anomalies are a checklist, not proof — chase the loud ones."
    )
    highlights = []
    for r in results[:8]:
        label = r.get("label") or "?"
        anomaly = r.get("anomaly") or "?"
        detail = r.get("detail") or ""
        line = f"`{label}` → **{anomaly}**"
        if detail:
            line += f" — {detail}"
        highlights.append(line)
    if len(results) > 8:
        highlights.append(f"…and {len(results) - 8} more.")

    next_steps = []
    if any(r.get("anomaly") == "status_change" for r in results):
        next_steps.append(
            "Status changes (200→500, 403→200…) — replay the variant manually and decide if it's auth bypass or an error."
        )
    if any(r.get("anomaly") == "new_auth_cookie" for r in results):
        next_steps.append(
            "A fresh session cookie after `strip-session` = server-side sessions; check session fixation and logout behavior."
        )
    if any(r.get("anomaly") == "error_leak" for r in results):
        next_steps.append(
            "Error leaks can expose paths/db internals — capture the trace and check what it reveals."
        )
    if not next_steps:
        next_steps.append(
            "Mostly content-diff anomalies — compare the flagged variant responses side by side."
        )
    next_steps.append("Re-run targeted checks with `darco sql` / `darco xss` on the flagged params.")
    return {"verdict": verdict, "highlights": highlights, "next_steps": next_steps}


# ------------------------------------------------------------------ Scan
def scan_notes(data: dict) -> dict:
    target = data.get("target") or ""
    sqli = data.get("sqli_vulnerabilities") or []
    xss = data.get("xss_reflections") or []
    up = data.get("upload_findings") or []
    login = data.get("login_bypasses") or []
    findings = data.get("findings") or []
    eps = data.get("crawled_endpoints")
    forms = data.get("crawled_forms")

    high_med = [f for f in findings if f.get("severity") in ("high", "medium")]
    verdict = (
        f"Scan of `{target}` done — crawled {eps} endpoint(s) / {forms} form(s), "
        f"surfaced {len(sqli)} SQLi, {len(xss)} XSS reflection, "
        f"{len(up)} upload finding(s), {len(login)} login-bypass candidate(s). "
        f"{len(high_med)} high/medium signals are "
        f"worth a manual look; the rest is mostly fingerprint noise."
    )

    highlights = []
    for f in high_med[:6]:
        sev = f.get("severity", "").upper()
        ftype = f.get("type") or "?"
        loc = f.get("location") or "?"
        highlights.append(f"`{sev}` — `{ftype}` at {loc}")
    if len(high_med) > 6:
        highlights.append(f"…and {len(high_med) - 6} more high/medium signal(s).")
    if not highlights:
        highlights.append("No high/medium signals — mostly informational findings (headers, tech fingerprints).")

    next_steps = [
        "Manually verify each high/medium finding before writing it up.",
        "Re-run `darco sql <url>` / `darco xss <url>` on the flagged params for the full evidence.",
    ]
    if any(f.get("type") == "auth_token_cookie" for f in findings):
        next_steps.append(
            "Session cookies without Secure/HttpOnly flags are a quick win to report."
        )
    if login:
        next_steps.append(
            "Login-bypass candidates are high value — replay the payload in a browser "
            "and confirm you reach the authenticated area."
        )
    return {"verdict": verdict, "highlights": highlights, "next_steps": next_steps}


# ------------------------------------------------------------------ Detect / passive / discover / generic findings
def detect_notes(data: dict) -> dict:
    target = data.get("target") or ""
    techs = data.get("technologies") or []
    wafs = data.get("wafs") or []
    tech_str = ", ".join(
        f"{t.get('name')} {t.get('version') or ''}".strip() for t in techs
    ) or "_unknown_"
    waf_str = ", ".join(w.get("name") for w in wafs) or "_none detected_"
    verdict = (
        f"Fingerprinted `{target}`: {tech_str}. WAF/CDN: {waf_str}. "
        f"Use the versions to hunt known CVEs — old ASP.NET/IIS stacks are a "
        f"favorite for public exploits."
    )
    highlights = [
        f"`{t.get('name')} {t.get('version') or ''}` ({t.get('confidence')} confidence, {t.get('category')})"
        for t in techs
    ] or ["Nothing recognizable — check headers/HTML manually."]
    next_steps = [
        "Look up the detected versions for known CVEs.",
        "No WAF means payloads won't be filtered — but stay in scope.",
        "Dig for verbose errors and backup files on the detected stack.",
    ]
    return {"verdict": verdict, "highlights": highlights, "next_steps": next_steps}


def passive_notes(data: dict) -> dict:
    domain = data.get("domain") or data.get("target") or "?"
    dns = data.get("dns_records") or []
    subs = data.get("subdomains") or []
    sec = data.get("security_txt") or {}
    missing_headers = data.get("missing_security_headers") or []
    findings = data.get("findings") or []
    verdict = (
        f"Passive recon on `{domain}`: {len(dns)} DNS record(s), {len(subs)} "
        f"subdomain(s), security.txt {'present' if sec.get('present') else 'missing'}, "
        f"{len(missing_headers)} security header(s) missing. "
        f"{len(findings)} posture finding(s) logged."
    )
    highlights = [
        f"`{f.get('type')}` — {str(f.get('evidence'))[:90]}"
        for f in findings[:6]
    ] or ["No notable posture findings."]
    next_steps = [
        "Missing HSTS/CSP/X-Frame-Options → harden response headers.",
        "Missing SPF/DMARC → email-spoofing risk; DMARC p=none should progress to quarantine/reject.",
        "Check the discovered subdomains for exposed admin panels or stale services.",
    ]
    return {"verdict": verdict, "highlights": highlights, "next_steps": next_steps}


def discover_notes(data: dict) -> dict:
    target = data.get("target") or ""
    stats = data.get("stats") or {}
    verdict = (
        f"Mapped `{target}`: {stats.get('visited', 0)} page(s), "
        f"{stats.get('endpoints', 0)} endpoint(s), {stats.get('forms', 0)} form(s), "
        f"{stats.get('js_files', 0)} JS file(s), {stats.get('signals', 0)} signal(s). "
        f"Good surface area to attack next."
    )
    highlights = []
    eps = data.get("endpoints") or []
    with_params = [
        e for e in eps if e.get("params")
    ][:5]
    for e in with_params:
        highlights.append(
            f"`{e.get('url')}` takes parameters: "
            + ", ".join(f"`{p.get('name')}`" for p in e.get("params", [])[:6])
        )
    if not highlights:
        highlights.append("No parameterized endpoints discovered.")
    next_steps = [
        "Run `darco scan <url>` to auto-audit everything found here.",
        "Hit the parameterized endpoints with `darco sql` / `darco xss` first — they're the highest value.",
        "Forms without CSRF tokens are worth a closer look (CSRF testing).",
    ]
    return {"verdict": verdict, "highlights": highlights, "next_steps": next_steps}


def findings_notes(data: dict) -> dict:
    findings = data.get("findings") or []
    high = [f for f in findings if f.get("severity") == "high"]
    med = [f for f in findings if f.get("severity") == "medium"]
    verdict = (
        f"{len(findings)} finding(s) logged — {len(high)} high, {len(med)} medium. "
        f"Review the high/medium ones; the info/low ones are mostly hygiene."
    )
    highlights = [
        f"`{f.get('severity', '').upper()}` — `{f.get('type')}` at {f.get('location')}"
        for f in (high + med)[:6]
    ] or ["All findings are informational — nothing urgent."]
    next_steps = [
        "Open the highest-severity finding and confirm its evidence manually.",
        "Save to the workspace with `--save` so the history records it.",
    ]
    return {"verdict": verdict, "highlights": highlights, "next_steps": next_steps}


def login_notes(data: dict) -> dict:
    target = data.get("target") or ""
    forms = data.get("forms_found") or []
    tested = data.get("tested_forms") or 0
    bypasses = data.get("bypasses") or []

    if not forms:
        return {
            "verdict": f"No login forms found on `{target}` (checked common auth paths too).",
            "highlights": ["Nothing to probe — the attack surface is elsewhere."],
            "next_steps": [
                "Look for JS-rendered SPAs with `darco js`, or app-specific auth routes.",
                "Don't forget subdomains and API-only auth endpoints.",
            ],
        }

    if not bypasses:
        return {
            "verdict": f"Checked {len(forms)} login form(s) on `{target}` ({tested} tested) — no SQL auth-bypass signals.",
            "highlights": [
                f"Form at `{f.get('action')}` (user=`{f.get('username_field') or '?'}`, "
                f"pass=`{f.get('password_field') or '?'}`, csrf="
                f"{'yes' if f.get('csrf_field') else 'no'})"
                for f in forms
            ],
            "next_steps": [
                "Payloads behaved like normal failed logins — try default/weak credentials.",
                "Check password-reset and account-recovery flows for their own injection points.",
                "No CSRF on the login form is a finding worth reporting on its own.",
            ],
        }

    verdict = (
        f"Found {len(bypasses)} SQL login-bypass candidate(s) across {len(forms)} "
        f"login form(s) on `{target}`. A payload logged you in without valid "
        f"credentials — verify manually, then report it as critical."
    )
    highlights = []
    for b in bypasses[:6]:
        conf = str(b.get("confidence") or "medium").upper()
        highlights.append(
            f"`{conf}` — `{b.get('payload')}` in `{b.get('param')}` "
            f"→ `{b.get('success_indicator')}`"
        )
    if len(bypasses) > 6:
        highlights.append(f"…and {len(bypasses) - 6} more.")
    next_steps = [
        "Replay the payload in a browser: log in with the payload as the username and any password.",
        "If it lands on an account page, the auth query is injectable — capture the redirect as evidence.",
        "Fix: parameterized queries + strict input validation on authentication flows.",
    ]
    return {"verdict": verdict, "highlights": highlights, "next_steps": next_steps}


# ------------------------------------------------------------------ dispatcher
def build_notes(data: dict) -> dict | None:
    """Attach a human-friendly debrief block when the data is recognizable."""
    if not isinstance(data, dict):
        return None
    if "vulnerabilities" in data and "tested_params" in data:
        return sqli_notes(data)
    if "forms_found" in data and "bypasses" in data:
        return login_notes(data)
    if "reflections" in data and "tested_params" in data:
        return xss_notes(data)
    if "total_variants" in data or ("results" in data and "anomalies" in data):
        return fuzz_notes(data)
    if any(
        k in data
        for k in ("sqli_vulnerabilities", "xss_reflections", "upload_findings")
    ):
        return scan_notes(data)
    if "dns_records" in data and "security_headers" in data:
        return passive_notes(data)
    if "technologies" in data and "wafs" in data and "status_code" in data:
        return detect_notes(data)
    if "endpoints" in data and "stats" in data:
        return discover_notes(data)
    if isinstance(data.get("findings"), list) and "id" in data:
        return findings_notes(data)
    return None


def render_notes(notes: dict | None) -> str:
    """Render the debrief block as markdown for the default CLI output."""
    if not notes:
        return ""
    lines = ["---", "", "## What Darco thinks", "", notes.get("verdict", "")]
    highlights = notes.get("highlights") or []
    if highlights:
        lines += ["", "**Highlights**", ""] + [f"- {h}" for h in highlights]
    next_steps = notes.get("next_steps") or []
    if next_steps:
        lines += ["", "**Do this next**", ""] + [f"- {n}" for n in next_steps]
    return "\n".join(lines)


__all__ = ["build_notes", "render_notes"]
