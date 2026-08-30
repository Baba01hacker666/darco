from __future__ import annotations

from typing import Any

from pydantic import Field

from ..models import DarcoModel, Finding


class TemplateInfo(DarcoModel):
    name: str
    author: str = "darco"
    severity: str = "info"  # "info", "low", "medium", "high", "critical"
    description: str = ""
    tags: list[str] = Field(default_factory=list)
    reference: list[str] = Field(default_factory=list)
    remediation: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class TemplateMatcher(DarcoModel):
    type: str = "word"  # native: word, regex, status, size, dsl; more via custom registry
    part: str = "body"  # "body", "header", "all", "status", "response"
    condition: str = "or"  # "or", "and"
    negative: bool = False
    words: list[str] = Field(default_factory=list)
    regex: list[str] = Field(default_factory=list)
    status: list[int] = Field(default_factory=list)
    sizes: list[int] = Field(default_factory=list)
    dsl: list[str] = Field(default_factory=list)
    binary: list[str] = Field(default_factory=list)  # hex-encoded patterns (custom)
    xpath: list[str] = Field(default_factory=list)  # custom xpath matcher
    json_keys: list[str] = Field(
        default_factory=list, alias="json"
    )  # custom json matcher
    min_ms: int = 0  # custom delay matcher threshold
    case_sensitive: bool = False


class TemplateExtractor(DarcoModel):
    type: str = "regex"  # native: regex, kval, json; more via custom registry
    name: str = ""
    part: str = "body"  # "body", "header", "all"
    internal: bool = False  # feed value to subsequent requests, hide from output
    regex: list[str] = Field(default_factory=list)
    group: int = 1
    kval: list[str] = Field(default_factory=list)
    json_keys: list[str] = Field(default_factory=list, alias="json")
    xpath: list[str] = Field(default_factory=list)  # custom xpath extractor


class TemplateRequest(DarcoModel):
    method: str = "GET"
    path: list[str] = Field(default_factory=list)
    headers: dict[str, str] = Field(default_factory=dict)
    body: str = ""
    matchers_condition: str = "or"  # "or", "and"
    matchers: list[TemplateMatcher] = Field(default_factory=list)
    extractors: list[TemplateExtractor] = Field(default_factory=list)
    redirects: bool = False
    max_redirects: int = 3
    stop_at_first_match: bool = False


class AttackTemplate(DarcoModel):
    id: str
    info: TemplateInfo
    requests: list[TemplateRequest] = Field(default_factory=list)
    variables: dict[str, str] = Field(default_factory=dict)
    raw_path: str = ""


class TemplateMatchResult(DarcoModel):
    template_id: str
    template_name: str
    severity: str
    matched_url: str
    matcher_type: str = ""
    matched_words: list[str] = Field(default_factory=list)
    extracted_data: dict[str, list[str]] = Field(default_factory=dict)
    curl: str = ""
    evidence: str = ""
    remediation: str = ""


class TemplateScanReport(DarcoModel):
    target: str
    templates_loaded: int = 0
    templates_executed: int = 0
    requests_sent: int = 0
    matched_results: list[TemplateMatchResult] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
