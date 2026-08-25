from __future__ import annotations

import enum
from typing import Any

from pydantic import BaseModel, Field


class BodyType(str, enum.Enum):
    NONE = "none"
    JSON = "json"
    FORM = "form"
    RAW = "raw"


class DarcoModel(BaseModel):
    """Base class providing cross-version compatibility for Pydantic v1 and v2."""

    def model_copy(
        self, *, deep: bool = False, update: dict[str, Any] | None = None
    ) -> Any:
        if hasattr(BaseModel, "model_copy"):
            return super().model_copy(deep=deep, update=update)
        return self.copy(deep=deep, update=update)

    def model_dump(self, *, mode: str = "python", **kwargs: Any) -> dict[str, Any]:
        if hasattr(BaseModel, "model_dump"):
            return super().model_dump(mode=mode, **kwargs)
        import json

        return json.loads(self.json(**kwargs))

    def model_dump_json(self, **kwargs: Any) -> str:
        if hasattr(BaseModel, "model_dump_json"):
            return super().model_dump_json(**kwargs)
        return self.json(**kwargs)

    @classmethod
    def model_validate(cls, obj: Any, **kwargs: Any) -> Any:
        if hasattr(BaseModel, "model_validate"):
            return super().model_validate(obj, **kwargs)
        if isinstance(obj, str):
            return cls.parse_raw(obj)
        return cls.parse_obj(obj)

    @classmethod
    def model_validate_json(cls, json_data: str | bytes, **kwargs: Any) -> Any:
        if hasattr(BaseModel, "model_validate_json"):
            return super().model_validate_json(json_data, **kwargs)
        return cls.parse_raw(json_data)


class NameValue(DarcoModel):
    name: str
    value: str = ""


class Cookie(DarcoModel):
    name: str
    value: str = ""
    domain: str | None = None
    path: str | None = None


class Request(DarcoModel):
    method: str = "GET"
    url: str
    headers: list[NameValue] = Field(default_factory=list)
    cookies: list[Cookie] = Field(default_factory=list)
    params: list[NameValue] = Field(default_factory=list)
    body_type: BodyType = BodyType.NONE
    body_json: Any = None
    body_form: list[NameValue] = Field(default_factory=list)
    body_raw: str = ""
    body_encoding: str = "utf-8"
    follow_redirects: bool = True
    timeout: float = 10.0
    verify: bool = True
    source: str = "manual"
    parent_id: str | None = None
    mutations: list[str] = Field(default_factory=list)
    session_stripped: bool = False


class Response(DarcoModel):
    status_code: int
    reason: str = ""
    headers: list[NameValue] = Field(default_factory=list)
    body: str = ""
    body_len: int = 0
    body_file: str | None = None
    url: str = ""
    elapsed_ms: int = 0
    redirects: list[str] = Field(default_factory=list)
    set_cookies: list[Cookie] = Field(default_factory=list)


class HistoryRecord(DarcoModel):
    id: str
    ts: str
    request: Request
    response: Response | None = None
    error: str | None = None


class WorkspaceConfig(DarcoModel):
    version: int = 1
    target: str
    created_at: str
    base_headers: list[NameValue] = Field(default_factory=list)
    follow_redirects: bool = True
    timeout: float = 10.0
    insecure: bool = False


class SessionState(DarcoModel):
    cookies: list[Cookie] = Field(default_factory=list)
    csrf_headers: dict[str, list[NameValue]] = Field(default_factory=dict)
    updated_at: str = ""


class Finding(DarcoModel):
    id: str
    type: str
    severity: str = "info"
    location: str = ""
    evidence: str = ""
    suggestion: str = ""
    request_id: str | None = None


class Endpoint(DarcoModel):
    url: str
    methods: list[str] = Field(default_factory=list)
    params: list[NameValue] = Field(default_factory=list)
    status: int | None = None
    content_type: str | None = None
    auth_required: bool = False
    source: str = "link"
    notes: list[str] = Field(default_factory=list)


class FormInput(DarcoModel):
    name: str
    type: str = "text"
    hidden: bool = False
    default: str | None = None
    interesting: bool = False


class Form(DarcoModel):
    action: str
    method: str = "GET"
    inputs: list[FormInput] = Field(default_factory=list)
    captcha: bool = False


class JsFile(DarcoModel):
    url: str
    endpoints: list[str] = Field(default_factory=list)


class TechDetection(DarcoModel):
    name: str
    category: str  # "server", "language", "framework", "cms", "frontend", "cdn"
    version: str | None = None
    confidence: str = "high"  # "high", "medium", "low"
    evidence: str = ""


class WafDetection(DarcoModel):
    name: str
    vendor: str = ""
    confidence: str = "high"  # "high", "medium", "low"
    evidence: str = ""
    blocked: bool = False


class SiteMap(DarcoModel):
    target: str = ""
    crawled_at: str = ""
    stats: dict[str, int] = Field(default_factory=dict)
    endpoints: list[Endpoint] = Field(default_factory=list)
    forms: list[Form] = Field(default_factory=list)
    js_files: list[JsFile] = Field(default_factory=list)
    signals: list[Finding] = Field(default_factory=list)
    robots: list[str] = Field(default_factory=list)
    technologies: list[TechDetection] = Field(default_factory=list)
    wafs: list[WafDetection] = Field(default_factory=list)


class DnsRecord(DarcoModel):
    record_type: str  # "A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "CAA"
    name: str
    value: str
    ttl: int | None = None


class SecurityTxt(DarcoModel):
    present: bool = False
    url: str = ""
    contact: list[str] = Field(default_factory=list)
    expires: str | None = None
    encryption: list[str] = Field(default_factory=list)
    acknowledgments: list[str] = Field(default_factory=list)
    policy: list[str] = Field(default_factory=list)
    hiring: list[str] = Field(default_factory=list)
    raw: str = ""


class PassiveReport(DarcoModel):
    target: str
    domain: str
    timestamp: str = ""
    ip_addresses: list[str] = Field(default_factory=list)
    dns_records: list[DnsRecord] = Field(default_factory=list)
    subdomains: list[str] = Field(default_factory=list)
    security_headers: dict[str, str] = Field(default_factory=dict)
    missing_security_headers: list[str] = Field(default_factory=list)
    security_txt: SecurityTxt | None = None
    technologies: list[TechDetection] = Field(default_factory=list)
    wafs: list[WafDetection] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)


class SqliFinding(DarcoModel):
    param: str
    param_type: str  # "query", "form", "json"
    injection_type: str  # "error_based", "quote_balancing", "arithmetic_evaluation", "boolean_differential", "status_anomaly"
    db_engine: str | None = None
    confidence: str  # "confirmed", "high", "medium", "potential"
    payload: str
    baseline_status: int
    payload_status: int
    evidence: str
    suggestion: str


class SqliScanResult(DarcoModel):
    target: str
    tested_params: list[str] = Field(default_factory=list)
    vulnerabilities: list[SqliFinding] = Field(default_factory=list)


class XssReflection(DarcoModel):
    param: str
    param_type: str  # "query", "form", "json", "header"
    context: str  # "html_body", "html_attribute", "script_context", "header", "unknown"
    confidence: str  # "confirmed", "high", "medium", "low"
    payload: str
    unencoded_chars: list[str] = Field(default_factory=list)
    encoded_chars: list[str] = Field(default_factory=list)
    snippet: str = ""
    evidence: str = ""
    suggestion: str = ""


class XssScanResult(DarcoModel):
    target: str
    tested_params: list[str] = Field(default_factory=list)
    reflections: list[XssReflection] = Field(default_factory=list)


class AutoScanReport(DarcoModel):
    target: str
    crawled_endpoints: int = 0
    crawled_forms: int = 0
    fuzzed_requests: int = 0
    anomalies: list[dict[str, Any]] = Field(default_factory=list)
    sqli_vulnerabilities: list[SqliFinding] = Field(default_factory=list)
    xss_reflections: list[XssReflection] = Field(default_factory=list)
    technologies: list[TechDetection] = Field(default_factory=list)
    wafs: list[WafDetection] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)


def to_json(model: BaseModel) -> dict[str, Any]:
    if hasattr(model, "model_dump"):
        return model.model_dump(mode="json")
    import json

    return json.loads(model.json())
