from __future__ import annotations

import re
from urllib.parse import urljoin

from bs4 import BeautifulSoup

from ..models import Form, FormInput

SKIP_SCHEMES = {"javascript:", "mailto:", "tel:", "data:", "about:", "file:", "ftp:"}


def _is_captcha(text: str) -> bool:
    return bool(re.search(r"recaptcha|g-recaptcha|hcaptcha|turnstile|geetest|cloudflare-challenge", text, re.IGNORECASE))


def extract_links(soup: BeautifulSoup, base_url: str) -> list[str]:
    urls: list[str] = []
    for tag in soup.find_all(["a", "area"]):
        href = tag.get("href")
        if href:
            urls.append(href)
    for tag in soup.find_all(["iframe", "frame"]):
        src = tag.get("src")
        if src:
            urls.append(src)
    return [urljoin(base_url, u) for u in urls]


def extract_meta_refresh(soup: BeautifulSoup, base_url: str) -> list[str]:
    urls: list[str] = []
    for meta in soup.find_all("meta", attrs={"http-equiv": True}):
        if meta.get("http-equiv", "").lower() == "refresh":
            content = meta.get("content", "")
            m = re.search(r"url\s*=\s*(.+?)\s*;?\s*$", content, re.IGNORECASE)
            if m:
                urls.append(urljoin(base_url, m.group(1).strip().strip("'\"")))
    return urls


def extract_scripts(soup: BeautifulSoup, base_url: str) -> list[str]:
    return [
        urljoin(base_url, s.get("src"))
        for s in soup.find_all("script")
        if s.get("src")
    ]


def extract_forms(soup: BeautifulSoup, base_url: str) -> list[Form]:
    forms: list[Form] = []
    for form in soup.find_all("form"):
        action = form.get("action") or ""
        if not action:
            action = base_url
        action = urljoin(base_url, action)
        method = (form.get("method") or "GET").upper()
        inputs: list[FormInput] = []
        for inp in form.find_all("input"):
            name = inp.get("name")
            if not name:
                continue
            inputs.append(
                FormInput(
                    name=name,
                    type=(inp.get("type") or "text").lower(),
                    hidden=(inp.get("type") or "").lower() == "hidden",
                    default=inp.get("value"),
                )
            )
        for sel in form.find_all("select"):
            name = sel.get("name")
            if not name:
                continue
            inputs.append(FormInput(name=name, type="select", default=sel.find("option", selected=True).get("value") if sel.find("option", selected=True) else None))
        for ta in form.find_all("textarea"):
            name = ta.get("name")
            if name:
                inputs.append(FormInput(name=name, type="textarea", default=ta.get_text()))
        captcha = _is_captcha(str(form))
        forms.append(Form(action=action, method=method, inputs=inputs, captcha=captcha))
    return forms


def is_html(content_type: str | None, body: str) -> bool:
    if content_type:
        return "html" in content_type.lower()
    return body.lstrip().startswith("<!doctype") or body.lstrip().startswith("<html")
