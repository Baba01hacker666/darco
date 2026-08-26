from __future__ import annotations

import re
from urllib.parse import urlsplit

from ..models import Request, Response, TechDetection

# Regex patterns for server headers
SERVER_RULES: list[tuple[str, str, re.Pattern]] = [
    ("nginx", "server", re.compile(r"nginx(?:/([\d.]+))?", re.IGNORECASE)),
    ("Apache", "server", re.compile(r"Apache(?:/([\d.]+))?", re.IGNORECASE)),
    (
        "Microsoft-IIS",
        "server",
        re.compile(r"Microsoft-IIS(?:/([\d.]+))?", re.IGNORECASE),
    ),
    ("LiteSpeed", "server", re.compile(r"LiteSpeed(?:/([\d.]+))?", re.IGNORECASE)),
    ("Caddy", "server", re.compile(r"Caddy(?:/([\d.]+))?", re.IGNORECASE)),
    ("Gunicorn", "server", re.compile(r"gunicorn(?:/([\d.]+))?", re.IGNORECASE)),
    ("Werkzeug", "server", re.compile(r"Werkzeug(?:/([\d.]+))?", re.IGNORECASE)),
    ("uWSGI", "server", re.compile(r"uWSGI", re.IGNORECASE)),
    ("Kestrel", "server", re.compile(r"Kestrel", re.IGNORECASE)),
    ("OpenResty", "server", re.compile(r"openresty(?:/([\d.]+))?", re.IGNORECASE)),
    ("Envoy", "server", re.compile(r"envoy", re.IGNORECASE)),
    ("Traefik", "server", re.compile(r"traefik", re.IGNORECASE)),
    (
        "Apache Tomcat",
        "server",
        re.compile(r"(?:Apache-Coyote|Tomcat)(?:/([\d.]+))?", re.IGNORECASE),
    ),
    ("Cloudflare", "cdn", re.compile(r"cloudflare", re.IGNORECASE)),
    ("CloudFront", "cdn", re.compile(r"cloudfront", re.IGNORECASE)),
    ("Varnish", "cache", re.compile(r"varnish(?:/([\d.]+))?", re.IGNORECASE)),
]

# Regex patterns for X-Powered-By / X-Generator / framework headers
HEADER_RULES: list[tuple[str, str, str, re.Pattern]] = [
    (
        "x-powered-by",
        "PHP",
        "language",
        re.compile(r"PHP(?:/([\d.]+))?", re.IGNORECASE),
    ),
    ("x-powered-by", "ASP.NET", "framework", re.compile(r"ASP\.NET", re.IGNORECASE)),
    ("x-powered-by", "Express", "framework", re.compile(r"Express", re.IGNORECASE)),
    ("x-powered-by", "Next.js", "framework", re.compile(r"Next\.js", re.IGNORECASE)),
    ("x-powered-by", "Nuxt", "framework", re.compile(r"Nuxt", re.IGNORECASE)),
    (
        "x-powered-by",
        "Servlet",
        "language",
        re.compile(r"Servlet(?:/([\d.]+))?", re.IGNORECASE),
    ),
    (
        "x-powered-by",
        "Phusion Passenger",
        "server",
        re.compile(r"Phusion Passenger(?:/([\d.]+))?", re.IGNORECASE),
    ),
    ("x-aspnet-version", "ASP.NET", "framework", re.compile(r"([\d.]+)")),
    ("x-aspnetmvc-version", "ASP.NET MVC", "framework", re.compile(r"([\d.]+)")),
    ("x-generator", "Drupal", "cms", re.compile(r"Drupal\s*([\d.]*)", re.IGNORECASE)),
    (
        "x-generator",
        "WordPress",
        "cms",
        re.compile(r"WordPress\s*([\d.]*)", re.IGNORECASE),
    ),
    ("x-generator", "Joomla", "cms", re.compile(r"Joomla!?\s*([\d.]*)", re.IGNORECASE)),
    ("x-drupal-cache", "Drupal", "cms", re.compile(r".+")),
    ("x-shopify-stage", "Shopify", "cms", re.compile(r".+")),
    ("x-ghost-cache-date", "Ghost", "cms", re.compile(r".+")),
    ("x-magento-tags", "Magento", "cms", re.compile(r".+")),
    ("x-debug-token", "Symfony", "framework", re.compile(r".+")),
    ("x-application-context", "Spring Boot", "framework", re.compile(r".+")),
    ("via", "Varnish", "cache", re.compile(r"varnish", re.IGNORECASE)),
    ("via", "Squid", "proxy", re.compile(r"squid", re.IGNORECASE)),
    ("via", "CloudFront", "cdn", re.compile(r"cloudfront", re.IGNORECASE)),
    ("via", "Kong", "api-gateway", re.compile(r"kong", re.IGNORECASE)),
]

# Cookie signatures mapping to tech
COOKIE_RULES: list[tuple[str, str, str, re.Pattern]] = [
    ("PHPSESSID", "PHP", "language", re.compile(r"^PHPSESSID$", re.IGNORECASE)),
    ("JSESSIONID", "Java", "language", re.compile(r"^JSESSIONID$", re.IGNORECASE)),
    (
        "ASP.NET_SessionId",
        "ASP.NET",
        "framework",
        re.compile(r"^(?:ASP\.NET_SessionId|ASPSESSIONID\w+)$", re.IGNORECASE),
    ),
    (
        ".AspNetCore.Session",
        "ASP.NET Core",
        "framework",
        re.compile(r"^\.AspNetCore\.", re.IGNORECASE),
    ),
    ("csrftoken", "Django", "framework", re.compile(r"^csrftoken$", re.IGNORECASE)),
    (
        "laravel_session",
        "Laravel",
        "framework",
        re.compile(r"^laravel_session$", re.IGNORECASE),
    ),
    (
        "XSRF-TOKEN",
        "Laravel / Angular",
        "framework",
        re.compile(r"^XSRF-TOKEN$", re.IGNORECASE),
    ),
    (
        "connect.sid",
        "Express / Node.js",
        "framework",
        re.compile(r"^connect\.sid$", re.IGNORECASE),
    ),
    (
        "rack.session",
        "Ruby on Rails",
        "framework",
        re.compile(r"^(?:rack\.session|_rails_session)$", re.IGNORECASE),
    ),
    (
        "wordpress_logged_in",
        "WordPress",
        "cms",
        re.compile(r"^wordpress(?:_logged_in|_sec|_test_cookie)", re.IGNORECASE),
    ),
    ("wp-settings", "WordPress", "cms", re.compile(r"^wp-settings-", re.IGNORECASE)),
    (
        "ci_session",
        "CodeIgniter",
        "framework",
        re.compile(r"^ci_session$", re.IGNORECASE),
    ),
    ("cakephp", "CakePHP", "framework", re.compile(r"^cakephp", re.IGNORECASE)),
    (
        "sf_redirect",
        "Symfony",
        "framework",
        re.compile(r"^sf_redirect$", re.IGNORECASE),
    ),
    ("AWSALB", "AWS ALB", "infrastructure", re.compile(r"^AWSALB", re.IGNORECASE)),
]

# Body signatures mapping to tech
BODY_RULES: list[tuple[str, str, re.Pattern, str | None]] = [
    (
        "ASP.NET",
        "framework",
        re.compile(
            r"id=[\"']__VIEWSTATE[\"']|name=[\"']__VIEWSTATE[\"']", re.IGNORECASE
        ),
        None,
    ),
    (
        "ASP.NET",
        "framework",
        re.compile(r"id=[\"']__EVENTVALIDATION[\"']", re.IGNORECASE),
        None,
    ),
    (
        "WordPress",
        "cms",
        re.compile(r"/wp-(?:content|includes|json)/", re.IGNORECASE),
        None,
    ),
    (
        "WordPress",
        "cms",
        re.compile(
            r"<meta\s+name=[\"']generator[\"']\s+content=[\"']WordPress\s*([\d.]*)[\"']",
            re.IGNORECASE,
        ),
        "\\1",
    ),
    (
        "Drupal",
        "cms",
        re.compile(
            r"<meta\s+name=[\"']generator[\"']\s+content=[\"']Drupal\s*([\d.]*)[\"']",
            re.IGNORECASE,
        ),
        "\\1",
    ),
    (
        "Drupal",
        "cms",
        re.compile(r"sites/default/files/|Drupal\.settings", re.IGNORECASE),
        None,
    ),
    (
        "Joomla",
        "cms",
        re.compile(
            r"<meta\s+name=[\"']generator[\"']\s+content=[\"']Joomla!?\s*([\d.]*)[\"']",
            re.IGNORECASE,
        ),
        "\\1",
    ),
    (
        "Ghost",
        "cms",
        re.compile(
            r"<meta\s+name=[\"']generator[\"']\s+content=[\"']Ghost\s*([\d.]*)[\"']",
            re.IGNORECASE,
        ),
        "\\1",
    ),
    (
        "Hugo",
        "cms",
        re.compile(
            r"<meta\s+name=[\"']generator[\"']\s+content=[\"']Hugo\s*([\d.]*)[\"']",
            re.IGNORECASE,
        ),
        "\\1",
    ),
    (
        "Gatsby",
        "frontend",
        re.compile(
            r"<meta\s+name=[\"']generator[\"']\s+content=[\"']Gatsby\s*([\d.]*)[\"']",
            re.IGNORECASE,
        ),
        "\\1",
    ),
    (
        "Next.js",
        "framework",
        re.compile(
            r"id=[\"'](?:__NEXT_DATA__|__next)[\"']|/_next/static/", re.IGNORECASE
        ),
        None,
    ),
    (
        "Nuxt.js",
        "framework",
        re.compile(r"id=[\"']__NUXT__[\"']|/_nuxt/", re.IGNORECASE),
        None,
    ),
    (
        "React",
        "frontend",
        re.compile(
            r"data-reactroot|react\.production\.min\.js|react\.development\.js",
            re.IGNORECASE,
        ),
        None,
    ),
    (
        "Vue.js",
        "frontend",
        re.compile(r"data-v-[a-f0-9]+|vue(?:\.runtime)?(?:\.min)?\.js", re.IGNORECASE),
        None,
    ),
    (
        "Angular",
        "frontend",
        re.compile(r"ng-version=[\"']([^\"']+)[\"']|ng-app=[\"']", re.IGNORECASE),
        "\\1",
    ),
    (
        "jQuery",
        "frontend",
        re.compile(
            r"jquery(?:-([\d.]+))?(?:\.min)?\.js|jQuery\s*v([\d.]+)", re.IGNORECASE
        ),
        "\\1",
    ),
    (
        "Bootstrap",
        "frontend",
        re.compile(r"bootstrap(?:-([\d.]+))?(?:\.min)?\.(?:css|js)", re.IGNORECASE),
        "\\1",
    ),
    (
        "Tailwind CSS",
        "frontend",
        re.compile(
            r"tailwindcss(?:\.min)?\.css|class=[\"'][^\"']*(?:grid-cols-|flex-col|space-y-|bg-opacity-)[^\"']*[\"']",
            re.IGNORECASE,
        ),
        None,
    ),
    (
        "HTMX",
        "frontend",
        re.compile(r"htmx(?:\.min)?\.js|hx-get=|hx-post=|hx-target=", re.IGNORECASE),
        None,
    ),
    (
        "Alpine.js",
        "frontend",
        re.compile(r"alpine(?:\.min)?\.js|x-data=|x-bind=|x-show=", re.IGNORECASE),
        None,
    ),
    (
        "Livewire",
        "frontend",
        re.compile(r"wire:initial-data|wire:id=", re.IGNORECASE),
        None,
    ),
    (
        "Django",
        "framework",
        re.compile(r"name=[\"']csrfmiddlewaretoken[\"']|django-admin", re.IGNORECASE),
        None,
    ),
    (
        "Spring Boot",
        "framework",
        re.compile(r"Whitelabel Error Page", re.IGNORECASE),
        None,
    ),
    (
        "Swagger / OpenAPI",
        "documentation",
        re.compile(
            r"swagger-ui(?:-bundle)?\.js|id=[\"']swagger-ui[\"']", re.IGNORECASE
        ),
        None,
    ),
]


def detect_technologies(
    response: Response, request: Request | None = None
) -> list[TechDetection]:
    """Inspect response headers, cookies, and body to identify web technologies."""
    detected: dict[str, TechDetection] = {}

    def _add(
        name: str,
        category: str,
        version: str | None = None,
        confidence: str = "high",
        evidence: str = "",
    ) -> None:
        key = name.lower()
        if key in detected:
            cur = detected[key]
            if not cur.version and version:
                cur.version = version
            if evidence and evidence not in cur.evidence:
                cur.evidence = (
                    f"{cur.evidence}, {evidence}" if cur.evidence else evidence
                )
            return
        detected[key] = TechDetection(
            name=name,
            category=category,
            version=version,
            confidence=confidence,
            evidence=evidence,
        )

    # 1. Inspect Server header
    for h in response.headers:
        if h.name.lower() == "server" and h.value:
            for s_name, cat, pat in SERVER_RULES:
                m = pat.search(h.value)
                if m:
                    ver = m.group(1) if m.groups() and m.group(1) else None
                    _add(
                        s_name,
                        cat,
                        version=ver,
                        confidence="high",
                        evidence=f"Server: {h.value}",
                    )

    # 2. Inspect Other Headers
    for h in response.headers:
        h_name_lower = h.name.lower()
        for target_hdr, tech_name, cat, pat in HEADER_RULES:
            if h_name_lower == target_hdr and h.value:
                m = pat.search(h.value)
                if m:
                    ver = m.group(1) if m.groups() and m.group(1) else None
                    _add(
                        tech_name,
                        cat,
                        version=ver,
                        confidence="high",
                        evidence=f"{h.name}: {h.value}",
                    )

    # 3. Inspect Cookies
    cookie_names = [c.name for c in response.set_cookies]
    for h in response.headers:
        if h.name.lower() == "set-cookie":
            cname = h.value.split(";", 1)[0].split("=", 1)[0].strip()
            if cname and cname not in cookie_names:
                cookie_names.append(cname)

    for cname in cookie_names:
        for target_cookie, tech_name, cat, pat in COOKIE_RULES:
            if pat.search(cname):
                _add(tech_name, cat, confidence="high", evidence=f"Cookie: {cname}")

    # 4. Inspect Body Signatures
    body = response.body or ""
    if body:
        for tech_name, cat, pat, ver_group in BODY_RULES:
            m = pat.search(body)
            if m:
                ver = None
                if ver_group and m.groups():
                    ver = next((g for g in m.groups() if g), None)
                snippet = m.group(0)[:60].replace("\n", " ").strip()
                _add(
                    tech_name,
                    cat,
                    version=ver,
                    confidence="high",
                    evidence=f"Body: {snippet}",
                )

    # 5. Check request/response URL extensions if available
    target_url = response.url or (request.url if request else "")
    if target_url:
        path = urlsplit(target_url).path.lower()
        if path.endswith((".aspx", ".ashx", ".asmx")):
            _add(
                "ASP.NET", "framework", confidence="high", evidence=f"URL path: {path}"
            )
        elif path.endswith(".php"):
            _add("PHP", "language", confidence="high", evidence=f"URL path: {path}")
        elif path.endswith((".jsp", ".do")):
            _add("Java", "language", confidence="high", evidence=f"URL path: {path}")

    return sorted(detected.values(), key=lambda t: (t.category, t.name))
