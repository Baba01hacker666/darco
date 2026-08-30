"""Stored XSS auditor.

Reflected-XSS scans can't see payloads that only render on a *later* page view.
This module closes that gap: it submits unique canary payloads through storable
forms (comments, profiles, reviews, ...), then re-fetches the pages where the
data is rendered and checks whether the payload survives unencoded.

Flow per form:
1. Re-fetch the page the form was discovered on to refresh CSRF/hidden tokens.
2. Submit one canary per injectable text field (``dstor<hex>'"><darcostore<hex>>``).
3. Verify on the redirect target, the source page, and the action URL:
   a raw ``<darcostore...>`` tag means attacker HTML is stored and rendered.
"""

import secrets

import httpx
from bs4 import BeautifulSoup

from .discovery.parsers import extract_forms
from .models import Form, StoredXssAuditResult, StoredXssFinding

USER_AGENT = "darco/0.1 (stored-xss auditor)"

_INJECTABLE_TYPES = frozenset({"text", "textarea", "search", "url", "email", "tel"})
_SKIP_TYPES = frozenset({"password", "file", "submit", "button", "image", "reset"})


def _default_client(timeout: float, verify: bool) -> httpx.Client:
    # follow_redirects=True: storable endpoints typically 302 to the render
    # page, which is exactly where we need to verify storage.
    return httpx.Client(
        timeout=timeout, verify=verify, follow_redirects=True, trust_env=False
    )


def _refresh_hidden(client: httpx.Client, form: Form) -> dict[str, str]:
    """Pull hidden input values (CSRF tokens) fresh from the source page."""
    if not form.url:
        return {}
    try:
        resp = client.get(form.url, headers={"User-Agent": USER_AGENT})
        if resp.status_code >= 400:
            return {}
        soup = BeautifulSoup(resp.text, "html.parser")
        for f in extract_forms(soup, form.url):
            if f.action == form.action and f.method.upper() == form.method.upper():
                fresh = {
                    i.name: i.default or "" for i in f.inputs if i.hidden and i.name
                }
                if fresh:
                    return fresh
    except (httpx.HTTPError, OSError):
        pass
    return {}


def _build_data(
    form: Form, hidden: dict[str, str], field: str, payload: str
) -> dict[str, str]:
    """Assemble a submission body with exactly one field carrying the payload."""
    data: dict[str, str] = {}
    for inp in form.inputs:
        if not inp.name or inp.type in _SKIP_TYPES or inp.type == "file":
            continue
        if inp.hidden:
            data[inp.name] = hidden.get(inp.name, inp.default or "")
        elif inp.type == "select":
            data[inp.name] = inp.default or ""
        elif inp.name == field:
            data[inp.name] = payload
        else:
            data[inp.name] = inp.default or "darco"
    data.setdefault(field, payload)
    return data


def _determine_context(body: str, match_pos: int) -> str:
    script_open = body.rfind("<script", 0, match_pos)
    script_close = body.rfind("</script>", 0, match_pos)
    if script_open != -1 and (script_close == -1 or script_close < script_open):
        return "script_context"
    comment_open = body.rfind("<!--", 0, match_pos)
    comment_close = body.rfind("-->", 0, match_pos)
    if comment_open != -1 and (comment_close == -1 or comment_close < comment_open):
        return "html_comment"
    tag_open = body.rfind("<", 0, match_pos)
    tag_close = body.rfind(">", 0, match_pos)
    if tag_open != -1 and (tag_close == -1 or tag_close < tag_open):
        return "html_attribute"
    return "html_body"


def _snippet(body: str, pos: int, length: int) -> str:
    start = max(0, pos - 40)
    end = min(len(body), pos + length + 40)
    snippet = body[start:end].replace("\r", "").replace("\n", " ")
    if start > 0:
        snippet = f"...{snippet}"
    if end < len(body):
        snippet = f"{snippet}..."
    return snippet.strip()


def audit_stored_xss(
    forms: list[Form],
    *,
    target: str = "",
    timeout: float = 10.0,
    verify: bool = True,
    max_fields_per_form: int = 4,
    max_submissions: int = 12,
    client_factory=_default_client,
) -> StoredXssAuditResult:
    """Submit canaries through storable forms and verify raw rendering later."""
    client = client_factory(timeout, verify)
    result = StoredXssAuditResult(target=target)
    submissions_left = max_submissions

    try:
        for form in forms:
            if submissions_left <= 0:
                result.notes.append("submission budget exhausted; remaining forms skipped")
                break
            if form.captcha:
                result.notes.append(f"skipped captcha-protected form {form.action}")
                continue

            injectable = [
                i for i in form.inputs if i.type in _INJECTABLE_TYPES and i.name
            ]
            if not injectable:
                continue

            tested_form_keys: set[str] = set()
            for inp in injectable[:max_fields_per_form]:
                key = f"{form.method.upper()} {form.action}#{inp.name}"
                if key in tested_form_keys:
                    continue
                tested_form_keys.add(key)

                hex_id = secrets.token_hex(4)
                text_canary = f"dstor{hex_id}"
                tag = f"darcostore{hex_id}"
                payload = f"{text_canary}'\"><{tag}>"

                hidden = _refresh_hidden(client, form)
                data = _build_data(form, hidden, inp.name, payload)
                try:
                    if form.method.upper() == "GET":
                        resp = client.get(
                            form.action, params=data, headers={"User-Agent": USER_AGENT}
                        )
                    else:
                        resp = client.post(
                            form.action, data=data, headers={"User-Agent": USER_AGENT}
                        )
                except (httpx.HTTPError, OSError):
                    continue
                result.submissions += 1
                submissions_left -= 1
                result.tested_fields.append(inp.name)

                # Candidate render pages: post-submit redirect target, the page
                # the form lives on, and the action endpoint itself.
                candidates = [str(resp.url)]
                if form.url:
                    candidates.append(form.url)
                candidates.append(form.action)

                finding, render_url = _verify(client, candidates, text_canary, tag)
                if not finding:
                    continue
                finding.param = inp.name
                finding.form_action = form.action
                finding.method = form.method.upper()
                finding.render_url = render_url
                result.findings.append(finding)
                break  # one confirmed injection per form is enough
            result.tested_forms += 1
    finally:
        client.close()

    return result


def _verify(
    client: httpx.Client,
    urls: list[str],
    text_canary: str,
    tag: str,
) -> tuple[StoredXssFinding | None, str]:
    """Check render candidates for the stored canary. Returns (finding, render_url)."""
    seen: set[str] = set()
    status = 0
    for url in urls:
        if not url or url in seen:
            continue
        seen.add(url)
        try:
            resp = client.get(url, headers={"User-Agent": USER_AGENT})
        except (httpx.HTTPError, OSError):
            continue
        status = resp.status_code
        body = resp.text or ""
        low = body.lower()

        # Search for "<tag" — the literal bracket must survive encoding.
        # A bare-name search would also match escaped output (&lt;darcostore...).
        bracketed = f"<{tag.lower()}"
        pos = low.find(bracketed)
        if pos != -1:
            context = _determine_context(body, pos)
            window = body[max(0, pos - 120) : pos]
            quotes_raw = '"' in window or "'" in window
            evidence = (
                f"Stored payload renders unencoded on a later view "
                f"(raw <{tag}> present, context '{context}'"
                + (", raw quotes adjacent" if quotes_raw else "")
                + f"): {_snippet(body, pos, len(tag))}"
            )
            return (
                StoredXssFinding(
                    param="",
                    form_action="",
                    render_url=url,
                    context=context,
                    confidence="confirmed",
                    payload=f"{text_canary}'\"><{tag}>",
                    status_code=resp.status_code,
                    evidence=evidence,
                    suggestion=(
                        "Contextually encode stored user input on render "
                        "(HTML entity encoding) and consider a strict CSP."
                    ),
                ),
                url,
            )

        # Canary text survived but the tag was stripped/encoded — storage works.
        # Only report as potential if the payload's quotes also render raw
        # (immediately after the canary), i.e. encoding is partial.
        cpos = low.find(text_canary.lower())
        if cpos != -1 and body[cpos + len(text_canary) : cpos + len(text_canary) + 3].startswith(
            ("'", '"')
        ):
            return (
                StoredXssFinding(
                    param="",
                    form_action="",
                    render_url=url,
                    context=_determine_context(body, cpos),
                    confidence="potential",
                    payload=f"{text_canary}'\"><{tag}>",
                    status_code=resp.status_code,
                    evidence=(
                        f"Stored canary '{text_canary}' renders back with partial "
                        f"markup: {_snippet(body, cpos, len(text_canary))}"
                    ),
                    suggestion=(
                        "Storage path reached rendering with partial markup — "
                        "review encoding of this field."
                    ),
                ),
                url,
            )
    return None, ""


__all__ = ["audit_stored_xss"]
