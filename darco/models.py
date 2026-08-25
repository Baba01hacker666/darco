from __future__ import annotations

import enum
from typing import Any

from pydantic import BaseModel, Field


class BodyType(str, enum.Enum):
    NONE = "none"
    JSON = "json"
    FORM = "form"
    RAW = "raw"


class NameValue(BaseModel):
    name: str
    value: str = ""


class Cookie(BaseModel):
    name: str
    value: str = ""
    domain: str | None = None
    path: str | None = None


class Request(BaseModel):
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


class Response(BaseModel):
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


class HistoryRecord(BaseModel):
    id: str
    ts: str
    request: Request
    response: Response | None = None
    error: str | None = None


class WorkspaceConfig(BaseModel):
    version: int = 1
    target: str
    created_at: str
    base_headers: list[NameValue] = Field(default_factory=list)
    follow_redirects: bool = True
    timeout: float = 10.0
    insecure: bool = False


class SessionState(BaseModel):
    cookies: list[Cookie] = Field(default_factory=list)
    csrf_headers: dict[str, list[NameValue]] = Field(default_factory=dict)
    updated_at: str = ""


class Finding(BaseModel):
    id: str
    type: str
    severity: str = "info"
    location: str = ""
    evidence: str = ""
    suggestion: str = ""
    request_id: str | None = None


class Endpoint(BaseModel):
    url: str
    methods: list[str] = Field(default_factory=list)
    params: list[NameValue] = Field(default_factory=list)
    status: int | None = None
    content_type: str | None = None
    auth_required: bool = False
    source: str = "link"
    notes: list[str] = Field(default_factory=list)


class FormInput(BaseModel):
    name: str
    type: str = "text"
    hidden: bool = False
    default: str | None = None
    interesting: bool = False


class Form(BaseModel):
    action: str
    method: str = "GET"
    inputs: list[FormInput] = Field(default_factory=list)
    captcha: bool = False


class JsFile(BaseModel):
    url: str
    endpoints: list[str] = Field(default_factory=list)


class SiteMap(BaseModel):
    target: str = ""
    crawled_at: str = ""
    stats: dict[str, int] = Field(default_factory=dict)
    endpoints: list[Endpoint] = Field(default_factory=list)
    forms: list[Form] = Field(default_factory=list)
    js_files: list[JsFile] = Field(default_factory=list)
    signals: list[Finding] = Field(default_factory=list)
    robots: list[str] = Field(default_factory=list)


def to_json(model: BaseModel) -> dict[str, Any]:
    return model.model_dump(mode="json")
