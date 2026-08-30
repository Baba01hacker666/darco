import secrets

import httpx

from .engine import execute
from .models import (
    NameValue,
    Request,
    Response,
    SessionState,
    XssReflection,
    XssScanResult,
)
from .state_fields import is_state_field


def _send(req: Request, session: SessionState) -> Response | None:
    """Execute a request and return the darco Response model or None on failure."""
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
    """Clone request and substitute parameter value."""
    req = base.model_copy(deep=True)
    if param_type == "query":
        new_params = []
        for p in req.params:
            if p.name == param_name:
                new_params.append(NameValue(name=p.name, value=new_val))
            else:
                new_params.append(p)
        req.params = new_params
    elif param_type == "form":
        new_form = []
        for p in req.body_form:
            if p.name == param_name:
                new_form.append(NameValue(name=p.name, value=new_val))
            else:
                new_form.append(p)
        req.body_form = new_form
    elif param_type == "json" and isinstance(req.body_json, dict):
        d = dict(req.body_json)
        d[param_name] = new_val
        req.body_json = d
    return req


def _determine_context(body: str, match_pos: int) -> str:
    """Determine the HTML reflection context (html_body, html_attribute, script_context, comment)."""
    # Check if inside <script>...</script>
    script_open = body.rfind("<script", 0, match_pos)
    script_close = body.rfind("</script>", 0, match_pos)
    if script_open != -1 and (script_close == -1 or script_close < script_open):
        return "script_context"

    # Check if inside <!-- ... -->
    comment_open = body.rfind("<!--", 0, match_pos)
    comment_close = body.rfind("-->", 0, match_pos)
    if comment_open != -1 and (comment_close == -1 or comment_close < comment_open):
        return "html_comment"

    # Check if inside an HTML tag attribute <tag attr="...here...">
    tag_open = body.rfind("<", 0, match_pos)
    tag_close = body.rfind(">", 0, match_pos)
    if tag_open != -1 and (tag_close == -1 or tag_close < tag_open):
        return "html_attribute"

    return "html_body"


def _extract_snippet(body: str, match_pos: int, length: int) -> str:
    """Extract a surrounding snippet around the matched position."""
    start = max(0, match_pos - 35)
    end = min(len(body), match_pos + length + 35)
    snippet = body[start:end].replace("\r", "").replace("\n", " ")
    if start > 0:
        snippet = f"...{snippet}"
    if end < len(body):
        snippet = f"{snippet}..."
    return snippet.strip()


def scan_xss(
    request: Request,
    session: SessionState | None = None,
    param_filter: str | None = None,
    include_state_fields: bool = False,
) -> XssScanResult:
    """Audit a request for parameter reflection and XSS character encoding."""
    if session is None:
        session = SessionState()

    # Extract testable parameters
    params_to_test: list[
        tuple[str, str, str]
    ] = []  # (param_type, param_name, original_val)

    for p in request.params:
        if (param_filter is None or p.name == param_filter) and (
            include_state_fields or not is_state_field(p.name)
        ):
            params_to_test.append(("query", p.name, p.value or ""))

    for p in request.body_form:
        if (param_filter is None or p.name == param_filter) and (
            include_state_fields or not is_state_field(p.name)
        ):
            params_to_test.append(("form", p.name, p.value or ""))

    if isinstance(request.body_json, dict):
        for k, v in request.body_json.items():
            if (param_filter is None or k == param_filter) and (
                include_state_fields or not is_state_field(k)
            ):
                params_to_test.append(("json", k, str(v) if v is not None else ""))

    result = XssScanResult(
        target=request.url,
        tested_params=[p[1] for p in params_to_test],
    )

    for p_type, p_name, _ in params_to_test:
        token_id = secrets.token_hex(4)
        canary = f"dxss{token_id}"
        probe_payload = f"{canary}'\"><darcotag>"

        req_probe = _clone_and_mutate_param(request, p_type, p_name, probe_payload)
        resp_probe = _send(req_probe, session)

        if not resp_probe:
            continue

        body = resp_probe.body or ""
        body_lower = body.lower()

        # 1. Check body reflection
        pos = body_lower.find(canary.lower())
        if pos != -1:
            context = _determine_context(body, pos)
            snippet = _extract_snippet(body, pos, len(probe_payload))

            # Inspect which characters in the injected probe were reflected raw vs encoded
            unencoded: list[str] = []
            encoded: list[str] = []

            canary_end = pos + len(canary)
            # Reflected segment immediately after canary (tail of probe)
            reflected_segment = body[canary_end : canary_end + 120]

            # Check tag reflection
            tag_pos = reflected_segment.lower().find("<darcotag>")
            tag_encoded = False
            if tag_pos != -1:
                unencoded.extend(["<", ">", "<darcotag>"])
            else:
                for enc_tag in ("&lt;darcotag&gt;", "%3cdarcotag%3e"):
                    enc_pos = reflected_segment.lower().find(enc_tag)
                    if enc_pos != -1:
                        tag_pos = enc_pos
                        tag_encoded = True
                        encoded.extend(["&lt;", "&gt;"])
                        break

            # The characters before the tag are the injected quotes & brackets ('">)
            prefix_window = (
                reflected_segment[:tag_pos] if tag_pos != -1 else reflected_segment[:30]
            )
            prefix_lower = prefix_window.lower()

            if tag_pos == -1 and not tag_encoded:
                # If the tag was completely stripped, inspect the immediate prefix window
                if "<" in prefix_window:
                    unencoded.append("<")
                elif "&lt;" in prefix_lower or "%3c" in prefix_lower:
                    encoded.append("&lt;")
                if ">" in prefix_window:
                    unencoded.append(">")
                elif "&gt;" in prefix_lower or "%3e" in prefix_lower:
                    encoded.append("&gt;")

            if '"' in prefix_window:
                unencoded.append('"')
            elif "&quot;" in prefix_lower or "%22" in prefix_lower:
                encoded.append("&quot;")

            if "'" in prefix_window:
                unencoded.append("'")
            elif (
                "&#39;" in prefix_lower
                or "&#x27;" in prefix_lower
                or "&apos;" in prefix_lower
                or "%27" in prefix_lower
            ):
                encoded.append("&#39;")

            # Assess confidence based on context and unencoded chars
            confidence = "low"
            if context == "html_body":
                if "<" in unencoded and ">" in unencoded:
                    confidence = "confirmed"
                elif "<" in unencoded:
                    confidence = "high"
                elif not unencoded:
                    confidence = "low"
                else:
                    confidence = "medium"
            elif context == "html_attribute":
                if (
                    '"' in unencoded
                    or "'" in unencoded
                    or "<" in unencoded
                    and ">" in unencoded
                ):
                    confidence = "high"
                elif not unencoded:
                    confidence = "low"
                else:
                    confidence = "medium"
            elif context == "script_context":
                if '"' in unencoded or "'" in unencoded or "<" in unencoded:
                    confidence = "confirmed"
                else:
                    confidence = "medium"
            else:
                if unencoded:
                    confidence = "medium"

            # Suggestion based on context
            if confidence in ("confirmed", "high"):
                if context == "html_body":
                    sugg = f"HTML-entity encode user input before rendering in HTML body (e.g. htmlspecialchars / escapeHtml) for '{p_name}'."
                elif context == "html_attribute":
                    sugg = f"Attribute-encode quotes and special characters for '{p_name}' to prevent escaping attribute boundaries."
                elif context == "script_context":
                    sugg = f"Avoid embedding unsanitized input '{p_name}' directly in JavaScript contexts. Use JSON serialization or data attributes."
                else:
                    sugg = f"Sanitize and contextually encode '{p_name}'."
            else:
                sugg = f"Input '{p_name}' is reflected with encoding. Ensure defense-in-depth sanitization."

            ev_parts = []
            if unencoded:
                ev_parts.append(f"Unencoded chars: [{', '.join(unencoded)}]")
            if encoded:
                ev_parts.append(f"Encoded chars: [{', '.join(encoded)}]")
            ev_str = f"Reflected in context '{context}'. " + " ".join(ev_parts)

            result.reflections.append(
                XssReflection(
                    param=p_name,
                    param_type=p_type,
                    context=context,
                    confidence=confidence,
                    payload=probe_payload,
                    unencoded_chars=unencoded,
                    encoded_chars=encoded,
                    snippet=snippet,
                    evidence=ev_str,
                    suggestion=sugg,
                )
            )

        # 2. Check header reflections
        for h in resp_probe.headers:
            if canary.lower() in h.value.lower():
                result.reflections.append(
                    XssReflection(
                        param=p_name,
                        param_type=p_type,
                        context="header",
                        confidence="medium",
                        payload=probe_payload,
                        unencoded_chars=[],
                        encoded_chars=[],
                        snippet=f"{h.name}: {h.value}",
                        evidence=f"Reflected in response header '{h.name}'. Potential HTTP response splitting or header injection.",
                        suggestion=f"Sanitize CRLF and header control characters in '{p_name}'.",
                    )
                )

    return result


__all__ = ["scan_xss"]
