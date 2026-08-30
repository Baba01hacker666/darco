from __future__ import annotations

import re
from urllib.parse import urljoin

from bs4 import BeautifulSoup

from ..models import Form, FormInput

SKIP_SCHEMES = {"javascript:", "mailto:", "tel:", "data:", "about:", "file:", "ftp:"}


def _is_captcha(text: str) -> bool:
    return bool(
        re.search(
            r"recaptcha|g-recaptcha|hcaptcha|turnstile|geetest|cloudflare-challenge",
            text,
            re.IGNORECASE,
        )
    )


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
        urljoin(base_url, s.get("src")) for s in soup.find_all("script") if s.get("src")
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
            selected_opt = sel.find("option", selected=True)
            default_val = None
            if selected_opt:
                default_val = selected_opt.get("value") or selected_opt.get_text()
            inputs.append(
                FormInput(
                    name=name,
                    type="select",
                    default=default_val,
                )
            )
        for ta in form.find_all("textarea"):
            name = ta.get("name")
            if name:
                inputs.append(
                    FormInput(name=name, type="textarea", default=ta.get_text())
                )
        captcha = _is_captcha(str(form))
        forms.append(
            Form(
                action=action,
                method=method,
                inputs=inputs,
                captcha=captcha,
                url=base_url,
            )
        )
    return forms


def is_html(content_type: str | None, body: str) -> bool:
    if content_type:
        return "html" in content_type.lower()
    return body.lstrip().startswith("<!doctype") or body.lstrip().startswith("<html")


_EMAIL_REGEX = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_IGNORED_EMAIL_EXTENSIONS = {
    "png",
    "jpg",
    "jpeg",
    "gif",
    "svg",
    "webp",
    "css",
    "js",
    "woff",
    "woff2",
    "ttf",
    "eot",
    "ico",
    "map",
    "mp4",
    "mp3",
    "pdf",
    "zip",
    "tar",
    "gz",
}
_IGNORED_EMAIL_DOMAINS = {
    "example.com",
    "example.org",
    "example.net",
    "domain.com",
    "yourcompany.com",
    "company.com",
    "email.com",
    "sample.com",
    "w3.org",
    "schema.org",
    "sentry.io",
}


def extract_emails(text_or_soup: str | BeautifulSoup) -> list[str]:
    """Extract valid, clean email addresses from HTML text or mailto: links."""
    emails: set[str] = set()
    raw_text = ""
    if isinstance(text_or_soup, BeautifulSoup):
        # 1. mailto: links
        for tag in text_or_soup.find_all(["a", "area"]):
            href = tag.get("href") or ""
            if href.lower().startswith("mailto:"):
                email_cand = href[7:].split("?")[0].split("#")[0].strip()
                if email_cand:
                    emails.add(email_cand)
        raw_text = text_or_soup.get_text() + " " + str(text_or_soup)
    else:
        raw_text = str(text_or_soup)

    # 2. Text regex
    for m in _EMAIL_REGEX.finditer(raw_text):
        emails.add(m.group(0))

    valid: list[str] = []
    seen: set[str] = set()
    for em in sorted(emails):
        em_clean = (
            em.strip().rstrip(".,;:!?)'\"<>[]{}").lstrip(".,;:!?'\"<([]{}").lower()
        )
        if not (5 <= len(em_clean) <= 100):
            continue
        if "@" not in em_clean or em_clean.count("@") != 1:
            continue
        user, domain = em_clean.split("@", 1)
        if not user or not domain or "." not in domain:
            continue
        ext = domain.rsplit(".", 1)[-1]
        if (
            ext in _IGNORED_EMAIL_EXTENSIONS
            or user.rsplit(".", 1)[-1] in _IGNORED_EMAIL_EXTENSIONS
        ):
            continue
        if domain in _IGNORED_EMAIL_DOMAINS:
            continue
        if any(domain.endswith("." + d) for d in _IGNORED_EMAIL_DOMAINS):
            continue
        if em_clean not in seen:
            seen.add(em_clean)
            valid.append(em_clean)
    return valid
