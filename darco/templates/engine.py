"""Template execution and response matcher engine."""

from __future__ import annotations

import asyncio
import random
import re
import string
from urllib.parse import urlsplit

import httpx

from ..models import Finding
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
        res = res.replace("{{randstr}}", "".join(random.choices(string.ascii_lowercase, k=8)))
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
        return f"HTTP/{resp.http_version} {resp.status_code}\n{headers_str}\n\n{resp.text}"
    return resp.text or ""


def _evaluate_matcher(matcher: TemplateMatcher, resp: httpx.Response) -> tuple[bool, list[str]]:
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
        if matcher.status and body_len in matcher.status:
            matched = True
            matched_items.append(str(body_len))

    else:
        matched = False

    if matcher.negative:
        matched = not matched

    return matched, matched_items


def _evaluate_extractors(extractors: list[TemplateExtractor], resp: httpx.Response) -> dict[str, list[str]]:
    extracted: dict[str, list[str]] = {}
    for ext in extractors:
        target_text = _get_target_part(resp, ext.part)
        name = ext.name or ext.type

        if ext.type == "regex":
            for r_pat in ext.regex:
                try:
                    matches = re.findall(r_pat, target_text, re.IGNORECASE)
                    for m in matches:
                        val = m[ext.group - 1] if isinstance(m, tuple) and len(m) >= ext.group else (m if isinstance(m, str) else str(m))
                        extracted.setdefault(name, []).append(str(val))
                except (re.error, IndexError):
                    pass

        elif ext.type == "kval":
            for k in ext.kval:
                v = resp.headers.get(k)
                if v:
                    extracted.setdefault(name, []).append(v)

        elif ext.type == "json":
            try:
                data = resp.json()
                for j_key in ext.json_keys:
                    if isinstance(data, dict) and j_key in data:
                        extracted.setdefault(name, []).append(str(data[j_key]))
            except (ValueError, TypeError, KeyError):
                pass

    return extracted


async def execute_template_on_target(
    template: AttackTemplate,
    target: str,
    *,
    client: httpx.AsyncClient | None = None,
    timeout: float = 10.0,
    verify: bool = True,
) -> tuple[list[TemplateMatchResult], list[Finding], int]:
    results: list[TemplateMatchResult] = []
    findings: list[Finding] = []
    requests_count = 0

    vars_dict = _extract_url_components(target)
    vars_dict.update(template.variables)

    managed_client = client is None
    async_client = client or httpx.AsyncClient(
        timeout=timeout,
        verify=verify,
        follow_redirects=False,
        trust_env=False,
    )

    try:
        for req in template.requests:
            for raw_path in req.path:
                req_url = _substitute_variables(raw_path, vars_dict)
                req_body = _substitute_variables(req.body, vars_dict) if req.body else None
                req_headers = {
                    k: _substitute_variables(v, vars_dict)
                    for k, v in req.headers.items()
                }
                if "User-Agent" not in req_headers:
                    req_headers["User-Agent"] = USER_AGENT

                requests_count += 1
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

                all_matched_words: list[str] = []
                matcher_evals: list[bool] = []

                for m in req.matchers:
                    m_ok, m_words = _evaluate_matcher(m, resp)
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

                if is_matched:
                    extracted = _evaluate_extractors(req.extractors, resp)
                    evidence = f"Matched {template.info.name} at {req_url} (HTTP {resp.status_code})"
                    if all_matched_words:
                        matched_words_str = ", ".join(all_matched_words[:5])
                        evidence += f" [Matched: {matched_words_str}]"
                    if extracted:
                        ext_str = ", ".join(f"{k}={v}" for k, v in extracted.items())
                        evidence += f" [Extracted: {ext_str}]"

                    curl_cmd = f'curl -k -i -X {req.method} "{req_url}"'

                    match_res = TemplateMatchResult(
                        template_id=template.id,
                        template_name=template.info.name,
                        severity=template.info.severity,
                        matched_url=req_url,
                        matcher_type=req.matchers[0].type if req.matchers else "status",
                        matched_words=all_matched_words,
                        extracted_data=extracted,
                        curl=curl_cmd,
                        evidence=evidence,
                        remediation=template.info.remediation,
                    )
                    results.append(match_res)

                    norm_tid = template.id.replace("-", "_")
                    findings.append(
                        Finding(
                            id=f"template-{template.id}-{hash(req_url) & 0xffff:04x}",
                            type=f"template_{norm_tid}",
                            severity=template.info.severity,
                            location=req_url,
                            evidence=evidence,
                            suggestion=template.info.remediation or "Review the exposed asset or endpoint and apply security controls.",
                        )
                    )

                    if req.stop_at_first_match:
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
                    tmpl, tgt, client=client, timeout=timeout, verify=verify
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
