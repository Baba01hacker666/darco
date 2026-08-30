from __future__ import annotations

import enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class BodyType(str, enum.Enum):
    NONE = "none"
    JSON = "json"
    FORM = "form"
    RAW = "raw"


class DarcoModel(BaseModel):
    """Base class providing cross-version compatibility for Pydantic v1 and v2."""

    model_config = ConfigDict(populate_by_name=True)

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
    url: str = ""  # page where the form was discovered (used to refresh CSRF tokens)


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
    emails: list[str] = Field(default_factory=list)
    admin_panels: list[AdminPanel] = Field(default_factory=list)


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
    emails: list[str] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)


class SqliFinding(DarcoModel):
    param: str
    param_type: str  # "query", "form", "json", "xml"
    injection_type: str  # "error_based", "quote_balancing", "arithmetic_evaluation", "boolean_differential", "status_anomaly", "sql_logic", "xml_entity_decoding", "xml_encoded_sqli"
    db_engine: str | None = None
    confidence: str  # "confirmed", "high", "medium", "potential"
    payload: str
    baseline_status: int
    payload_status: int
    evidence: str
    suggestion: str
    curl: str = ""  # copy-paste replay command for manual verification


class SqliScanResult(DarcoModel):
    target: str
    tested_params: list[str] = Field(default_factory=list)
    vulnerabilities: list[SqliFinding] = Field(default_factory=list)


class LoginForm(DarcoModel):
    url: str = ""
    action: str
    method: str = "POST"
    username_field: str | None = None
    password_field: str | None = None
    csrf_field: str | None = None
    captcha: bool = False


class LoginBypassFinding(DarcoModel):
    param: str
    payload: str
    confidence: str  # "confirmed", "high", "medium", "low"
    success_indicator: str
    evidence: str
    suggestion: str


class LoginAuditResult(DarcoModel):
    target: str
    forms_found: list[LoginForm] = Field(default_factory=list)
    tested_forms: int = 0
    bypasses: list[LoginBypassFinding] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


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


class AdminPanel(DarcoModel):
    path: str
    url: str
    status_code: int
    title: str = ""
    auth_type: str = "unknown"  # "login_form", "basic_auth", "forbidden", "redirect", "exposed_dashboard", "api"
    redirect_url: str | None = None
    login_form: LoginForm | None = None
    server: str = ""
    confidence: str = "high"  # "confirmed", "high", "medium", "low"
    evidence: str = ""


class AdminPanelReport(DarcoModel):
    target: str
    scanned_paths: int = 0
    panels_found: list[AdminPanel] = Field(default_factory=list)
    tested_creds: int = 0
    bypasses: list[LoginBypassFinding] = Field(default_factory=list)
    emails_used: list[str] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)


class AutoScanReport(DarcoModel):
    target: str
    crawled_endpoints: int = 0
    crawled_forms: int = 0
    fuzzed_requests: int = 0
    anomalies: list[dict[str, Any]] = Field(default_factory=list)
    sqli_vulnerabilities: list[SqliFinding] = Field(default_factory=list)
    xss_reflections: list[XssReflection] = Field(default_factory=list)
    upload_findings: list[UploadFinding] = Field(default_factory=list)
    redirect_findings: list[RedirectFinding] = Field(default_factory=list)
    traversal_findings: list[TraversalFinding] = Field(default_factory=list)
    stored_xss_findings: list[StoredXssFinding] = Field(default_factory=list)
    login_bypasses: list[LoginBypassFinding] = Field(default_factory=list)
    admin_panels: list[AdminPanel] = Field(default_factory=list)
    technologies: list[TechDetection] = Field(default_factory=list)
    wafs: list[WafDetection] = Field(default_factory=list)
    emails: list[str] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)


class UploadFinding(DarcoModel):
    param: str
    filename: str
    content_type: str
    status_code: int
    file_url: str | None = None
    vulnerability_type: str  # "svg_stored_xss", "html_stored_xss", "mime_spoofing_bypass", "missing_content_disposition", "dangerous_extension_allowed"
    confidence: str = "high"  # "confirmed", "high", "medium", "low"
    evidence: str = ""
    suggestion: str = ""


class UploadAuditResult(DarcoModel):
    target: str
    tested_field: str = "file"
    tests_run: int = 0
    accepted_formats: list[str] = Field(default_factory=list)
    findings: list[UploadFinding] = Field(default_factory=list)


class RedirectFinding(DarcoModel):
    param: str
    param_type: str  # "query", "form", "json"
    redirect_type: str  # "location_header", "meta_refresh", "js_location"
    confidence: str  # "confirmed", "high", "medium"
    payload: str
    redirect_to: str = ""
    status_code: int = 0
    evidence: str = ""
    suggestion: str = ""


class RedirectScanResult(DarcoModel):
    target: str
    tested_params: list[str] = Field(default_factory=list)
    findings: list[RedirectFinding] = Field(default_factory=list)


class TraversalFinding(DarcoModel):
    param: str
    param_type: str  # "query", "form", "json"
    target_file: str  # "etc/passwd", "windows/win.ini"
    confidence: str  # "confirmed"
    payload: str
    status_code: int = 0
    evidence: str = ""
    suggestion: str = ""


class TraversalScanResult(DarcoModel):
    target: str
    tested_params: list[str] = Field(default_factory=list)
    findings: list[TraversalFinding] = Field(default_factory=list)


class StoredXssFinding(DarcoModel):
    param: str
    form_action: str
    method: str = "POST"
    render_url: str = ""
    context: str  # "html_body", "html_attribute", "script_context", "html_comment"
    confidence: str  # "confirmed", "potential"
    payload: str
    status_code: int = 0
    evidence: str = ""
    suggestion: str = ""


class StoredXssAuditResult(DarcoModel):
    target: str
    tested_forms: int = 0
    tested_fields: list[str] = Field(default_factory=list)
    submissions: int = 0
    findings: list[StoredXssFinding] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class ApiEndpoint(DarcoModel):
    path: str
    full_url: str = ""
    method: str = "GET"  # "GET", "POST", "PUT", "DELETE", "PATCH", "ALL", "UNKNOWN"
    params: list[str] = Field(default_factory=list)
    source_js: str = ""
    is_graphql: bool = False
    context_snippet: str = ""


class JsSecret(DarcoModel):
    type: str  # "api_key", "jwt_token", "bearer_token", "firebase", "aws_key", "internal_url"
    value: str
    source_js: str = ""
    evidence: str = ""


class JsAnalysisReport(DarcoModel):
    target: str
    js_files_analyzed: int = 0
    endpoints: list[ApiEndpoint] = Field(default_factory=list)
    graphql_endpoints: list[str] = Field(default_factory=list)
    secrets: list[JsSecret] = Field(default_factory=list)
    chunks_discovered: list[str] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)


def to_json(model: BaseModel) -> dict[str, Any]:
    if hasattr(model, "model_dump"):
        return model.model_dump(mode="json")
    import json

    return json.loads(model.json())
