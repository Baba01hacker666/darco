"""Template execution and response matcher engine."""

from __future__ import annotations

import asyncio
import random
import re
import string
import time
from urllib.parse import urlsplit

import httpx

from ..models import Finding
from .custom import get_extractor_type, get_matcher_type
from .dsl import evaluate_dsl
from .models import (
    AttackTemplate,
    TemplateExtractor,
    TemplateMatcher,
    TemplateMatchResult,
    TemplateScanReport,
)

USER_AGENT = "darco/0.1 (security template runner)"


def _extract_url_components(target: str) -> dict[str, str]:
    raw = target.strip()
    if not raw.startswith(("http://", "https://")):
        raw = "http://" + raw
    split = urlsplit(raw)

    scheme = split.scheme or "http"
    host = split.hostname or "localhost"
    port = str(split.port) if split.port else ("443" if scheme == "https" else "80")
    hostname = f"{host}:{port}" if split.port and split.port not in (80, 443) else host
    root_url = f"{scheme}://{hostname}"
    base_url = raw.rstrip("/")

    return {
        "BaseURL": base_url,
        "RootURL": root_url,
        "Hostname": hostname,
        "Host": host,
        "Port": port,
        "Scheme": scheme,
        "Path": split.path or "",
    }


def _substitute_variables(text: str, variables: dict[str, str]) -> str:
    res = text
    for k, v in variables.items():
        res = res.replace(f"{{{{{k}}}}}", v)
    if "{{randstr}}" in res:
        res = res.replace(
            "{{randstr}}", "".join(random.choices(string.ascii_lowercase, k=8))
        )
    if "{{rand_int}}" in res:
        res = res.replace("{{rand_int}}", str(random.randint(100000, 999999)))
    return res


def _get_target_part(resp: httpx.Response, part: str) -> str:
    part_clean = part.lower()
    if part_clean in ("header", "headers"):
        return "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
    elif part_clean == "status":
        return str(resp.status_code)
    elif part_clean in ("all", "response"):
        headers_str = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
        return (
            f"HTTP/{resp.http_version} {resp.status_code}\n{headers_str}\n\n{resp.text}"
        )
    return resp.text or ""


def _evaluate_matcher(
    matcher: TemplateMatcher, resp: httpx.Response, elapsed_ms: float = 0.0
) -> tuple[bool, list[str]]:
    target_text = _get_target_part(resp, matcher.part)
    matched_items: list[str] = []
    matched = False

    if matcher.type == "status":
        if matcher.status:
            matched = resp.status_code in matcher.status
            if matched:
                matched_items.append(str(resp.status_code))
        else:
            matched = True

    elif matcher.type == "word":
        if not matcher.words:
            matched = True
        else:
            check_text = target_text if matcher.case_sensitive else target_text.lower()
            word_matches = []
            for w in matcher.words:
                check_w = w if matcher.case_sensitive else w.lower()
                if check_w in check_text:
                    word_matches.append(w)

            if matcher.condition.lower() == "and":
                matched = len(word_matches) == len(matcher.words)
            else:
                matched = len(word_matches) > 0
            matched_items = word_matches

    elif matcher.type == "regex":
        if not matcher.regex:
            matched = True
        else:
            regex_matches = []
            for r_str in matcher.regex:
                flags = 0 if matcher.case_sensitive else re.IGNORECASE
                try:
                    if re.search(r_str, target_text, flags=flags):
                        regex_matches.append(r_str)
                except re.error:
                    pass

            if matcher.condition.lower() == "and":
                matched = len(regex_matches) == len(matcher.regex)
            else:
                matched = len(regex_matches) > 0
            matched_items = regex_matches

    elif matcher.type == "size":
        body_len = len(resp.content)
        sizes = matcher.sizes or matcher.status  # status fallback: legacy templates
        if sizes and body_len in sizes:
            matched = True
            matched_items.append(str(body_len))

    elif matcher.type == "dsl":
        try:
            req_url_val = str(resp.request.url)
        except (RuntimeError, AttributeError):
            req_url_val = ""
        dsl_vars = {
            "status_code": resp.status_code,
            "content_length": len(resp.content),
            "body": resp.text or "",
            "header": "\n".join(f"{k}: {v}" for k, v in resp.headers.items()),
            "all": _get_target_part(resp, "all"),
            "url": req_url_val,
            "elapsed_ms": round(elapsed_ms),
        }
        for expr in matcher.dsl:
            if evaluate_dsl(expr, dsl_vars):
                matched = True
                matched_items.append(expr)

    else:
        fn = get_matcher_type(matcher.type)
        if fn is None:
            matched = False
        else:
            try:
                result = fn(matcher, resp, elapsed_ms)
            except Exception:  # noqa: BLE001
                result = (False, [])
            if isinstance(result, tuple) and len(result) == 2:
                matched, matched_items = bool(result[0]), list(result[1])
            else:
                matched, matched_items = bool(result), []

    if matcher.negative:
        matched = not matched

    return matched, matched_items


def _json_walk(data, dotted: str):
    """Resolve a dot-notation path (a.b.0.c) inside parsed JSON."""
    cur = data
    for key in dotted.split("."):
        if isinstance(cur, dict) and key in cur:
            cur = cur[key]
        elif isinstance(cur, list) and key.isdigit() and int(key) < len(cur):
            cur = cur[int(key)]
        else:
            return None
    return cur


def _evaluate_extractor(
    ext: TemplateExtractor, resp: httpx.Response
) -> dict[str, list[str]]:
    target_text = _get_target_part(resp, ext.part)
    name = ext.name or ext.type

    if ext.type == "regex":
        extracted: dict[str, list[str]] = {}
        for r_pat in ext.regex:
            try:
                matches = re.findall(r_pat, target_text, re.IGNORECASE)
                for m in matches:
                    val = (
                        m[ext.group - 1]
                        if isinstance(m, tuple) and len(m) >= ext.group
                        else (m if isinstance(m, str) else str(m))
                    )
                    extracted.setdefault(name, []).append(str(val))
            except (re.error, IndexError):
                pass
        return extracted

    if ext.type == "kval":
        out = {}
        for k in ext.kval:
            v = resp.headers.get(k)
            if v:
                out.setdefault(name, []).append(v)
        return out

    if ext.type == "json":
        out = {}
        try:
            data = resp.json()
            for j_key in ext.json_keys:
                val = _json_walk(data, j_key)
                if val is not None:
                    out.setdefault(name, []).append(str(val))
        except (ValueError, TypeError):
            pass
        return out

    fn = get_extractor_type(ext.type)
    if fn is None:
        return {}
    try:
        result = fn(ext, resp)
    except Exception:  # noqa: BLE001
        return {}
    return result if isinstance(result, dict) else {}


def _evaluate_extractors(
    extractors: list[TemplateExtractor], resp: httpx.Response
) -> tuple[dict[str, list[str]], set[str]]:
    """Run all extractors; returns (values_by_name, internal_names)."""
    extracted: dict[str, list[str]] = {}
    internal_names: set[str] = set()
    for ext in extractors:
        vals = _evaluate_extractor(ext, resp)
        for k, v in vals.items():
            if ext.internal:
                internal_names.add(k)
            extracted.setdefault(k, [])
            for item in v:
                if item not in extracted[k]:
                    extracted[k].append(item)
    return extracted, internal_names


async def execute_template_on_target(
    template: AttackTemplate,
    target: str,
    *,
    client: httpx.AsyncClient | None = None,
    timeout: float = 10.0,
    verify: bool = True,
    extra_variables: dict[str, str] | None = None,
) -> tuple[list[TemplateMatchResult], list[Finding], int]:
    results: list[TemplateMatchResult] = []
    findings: list[Finding] = []
    requests_count = 0

    # Mutable so extractor values can chain into subsequent requests.
    vars_dict = _extract_url_components(target)
    vars_dict.update(template.variables)
    if extra_variables:
        vars_dict.update({k: str(v) for k, v in extra_variables.items()})

    managed_client = client is None
    async_client = client or httpx.AsyncClient(
        timeout=timeout,
        verify=verify,
        follow_redirects=False,
        trust_env=False,
    )

    try:
        stop = False
        for req in template.requests:
            if stop:
                break
            for raw_path in req.path:
                req_url = _substitute_variables(raw_path, vars_dict)
                req_body = (
                    _substitute_variables(req.body, vars_dict) if req.body else None
                )
                req_headers = {
                    k: _substitute_variables(v, vars_dict)
                    for k, v in req.headers.items()
                }
                if "User-Agent" not in req_headers:
                    req_headers["User-Agent"] = USER_AGENT

                requests_count += 1
                started = time.perf_counter()
                try:
                    resp = await async_client.request(
                        req.method,
                        req_url,
                        headers=req_headers,
                        content=req_body.encode("utf-8") if req_body else None,
                        follow_redirects=req.redirects,
                    )
                except (httpx.HTTPError, OSError, TimeoutError):
                    continue
                elapsed_ms = (time.perf_counter() - started) * 1000.0

                all_matched_words: list[str] = []
                matcher_evals: list[bool] = []

                for m in req.matchers:
                    m_ok, m_words = _evaluate_matcher(m, resp, elapsed_ms)
                    matcher_evals.append(m_ok)
                    if m_ok:
                        all_matched_words.extend(m_words)

                is_matched = False
                if req.matchers:
                    if req.matchers_condition.lower() == "and":
                        is_matched = all(matcher_evals)
                    else:
                        is_matched = any(matcher_evals)
                else:
                    is_matched = resp.status_code == 200

                # Extracted values always become variables for later requests
                # in this template (multi-step attack chains).
                extracted, internal_names = _evaluate_extractors(req.extractors, resp)
                for k, vals in extracted.items():
                    if vals:
                        vars_dict.setdefault(k, vals[0])

                if is_matched:
                    public_extracted = {
                        k: v for k, v in extracted.items() if k not in internal_names
                    }
                    evidence = f"Matched {template.info.name} at {req_url} (HTTP {resp.status_code})"
                    if all_matched_words:
                        matched_words_str = ", ".join(all_matched_words[:5])
                        evidence += f" [Matched: {matched_words_str}]"
                    if public_extracted:
                        ext_str = ", ".join(
                            f"{k}={v}" for k, v in public_extracted.items()
                        )
                        evidence += f" [Extracted: {ext_str}]"

                    curl_cmd = f'curl -k -i -X {req.method} "{req_url}"'

                    match_res = TemplateMatchResult(
                        template_id=template.id,
                        template_name=template.info.name,
                        severity=template.info.severity,
                        matched_url=req_url,
                        matcher_type=req.matchers[0].type if req.matchers else "status",
                        matched_words=all_matched_words,
                        extracted_data=public_extracted,
                        curl=curl_cmd,
                        evidence=evidence,
                        remediation=template.info.remediation,
                    )
                    results.append(match_res)

                    norm_tid = template.id.replace("-", "_")
                    findings.append(
                        Finding(
                            id=f"template-{template.id}-{hash(req_url) & 0xFFFF:04x}",
                            type=f"template_{norm_tid}",
                            severity=template.info.severity,
                            location=req_url,
                            evidence=evidence,
                            suggestion=template.info.remediation
                            or "Review the exposed asset or endpoint and apply security controls.",
                        )
                    )

                    if req.stop_at_first_match:
                        stop = True
                        break

    finally:
        if managed_client:
            await async_client.aclose()

    return results, findings, requests_count


async def run_template_scan(
    templates: list[AttackTemplate],
    targets: list[str] | str,
    *,
    workers: int = 10,
    timeout: float = 10.0,
    verify: bool = True,
    extra_variables: dict[str, str] | None = None,
) -> TemplateScanReport:
    target_list = [targets] if isinstance(targets, str) else targets
    primary_target = target_list[0] if target_list else ""

    all_matched: list[TemplateMatchResult] = []
    all_findings: list[Finding] = []
    total_requests = 0

    async with httpx.AsyncClient(
        timeout=timeout,
        verify=verify,
        follow_redirects=False,
        trust_env=False,
    ) as client:
        sem = asyncio.Semaphore(max(1, workers))

        async def run_one(tmpl: AttackTemplate, tgt: str):
            nonlocal total_requests
            async with sem:
                res_list, f_list, reqs = await execute_template_on_target(
                    tmpl,
                    tgt,
                    client=client,
                    timeout=timeout,
                    verify=verify,
                    extra_variables=extra_variables,
                )
                total_requests += reqs
                all_matched.extend(res_list)
                all_findings.extend(f_list)

        tasks = [
            asyncio.create_task(run_one(t, tgt))
            for t in templates
            for tgt in target_list
        ]
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    return TemplateScanReport(
        target=primary_target,
        templates_loaded=len(templates),
        templates_executed=len(templates) * len(target_list),
        requests_sent=total_requests,
        matched_results=all_matched,
        findings=all_findings,
    )
