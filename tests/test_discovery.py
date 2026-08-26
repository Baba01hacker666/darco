import asyncio

from darco.discovery.crawler import discover


def test_discover_builds_sitemap(app, workspace):
    sitemap = asyncio.run(discover(workspace, app))
    urls = {e.url for e in sitemap.endpoints}
    assert f"{app}/" in urls
    assert f"{app}/login" in urls
    assert f"{app}/admin" in urls
    assert f"{app}/api/items" in urls
    assert f"{app}/debug" in urls
    assert f"{app}/captcha" in urls
    assert f"{app}/error" in urls

    login_form = next(f for f in sitemap.forms if f.action == f"{app}/login")
    assert login_form.method == "POST"
    assert {i.name for i in login_form.inputs} >= {"csrf", "username", "password"}
    assert next(i for i in login_form.inputs if i.name == "csrf").hidden is True

    js = {j.url: j.endpoints for j in sitemap.js_files}
    assert f"{app}/js/app.js" in js
    assert f"{app}/api/users" in js[f"{app}/js/app.js"]
    assert f"{app}/internal/status" in js[f"{app}/js/app.js"]
    assert f"{app}/ws/events" in js[f"{app}/js/app.js"]

    signal_types = {s.type for s in sitemap.signals}
    assert "interesting_path" in signal_types  # /admin
    assert "captcha" in signal_types
    assert "error_leak" in signal_types
    assert "auth_required" in signal_types  # /admin 403

    assert set(sitemap.robots) == {"/admin", "/backup"}
    assert any(
        e.url == f"{app}/backup" and e.source == "robots" for e in sitemap.endpoints
    )

    admin = next(e for e in sitemap.endpoints if e.url == f"{app}/admin")
    assert admin.auth_required is True
    assert admin.status == 403

    debug = next(e for e in sitemap.endpoints if e.url == f"{app}/debug")
    assert {p.name for p in debug.params} == {"enabled"}

    assert workspace.sitemap_file.exists()
    assert workspace.load_findings()


def test_extract_js_endpoints_xhr():
    from darco.discovery.js_extractor import extract_js_endpoints

    js_code = """
    var xhr = new XMLHttpRequest();
    xhr.open("POST", "/api/v2/submit", true);
    xhr.send();
    """
    endpoints = extract_js_endpoints(js_code, "http://target.test")
    assert "http://target.test/api/v2/submit" in endpoints


def test_extract_forms_select_option_fallback():
    from bs4 import BeautifulSoup
    from darco.discovery.parsers import extract_forms

    html = """
    <form action="/submit" method="POST">
        <select name="role">
            <option>User</option>
            <option selected>Admin</option>
        </select>
        <select name="tier">
            <option value="free">Free</option>
            <option value="pro" selected>Pro</option>
        </select>
    </form>
    """
    soup = BeautifulSoup(html, "html.parser")
    forms = extract_forms(soup, "http://example.com")
    assert len(forms) == 1
    f = forms[0]
    role_inp = next(i for i in f.inputs if i.name == "role")
    assert role_inp.default == "Admin"
    tier_inp = next(i for i in f.inputs if i.name == "tier")
    assert tier_inp.default == "pro"


def test_extract_emails_from_html():
    from bs4 import BeautifulSoup
    from darco.discovery.parsers import extract_emails

    html = """
    <html><body>
        <p>Contact our team at <a href="mailto:security@mycompany.org?subject=Bug">Email Us</a></p>
        <p>Support: support.team@mycompany.org or dev_ops+alert@infra.mycompany.org</p>
        <!-- False positive tests below: -->
        <img src="avatar@2x.png">
        <span>test@example.com</span>
        <span>user@schema.org</span>
    </body></html>
    """
    soup = BeautifulSoup(html, "html.parser")
    emails = extract_emails(soup)
    assert "security@mycompany.org" in emails
    assert "support.team@mycompany.org" in emails
    assert "dev_ops+alert@infra.mycompany.org" in emails
    assert not any("2x.png" in e for e in emails)
    assert not any("example.com" in e for e in emails)
    assert not any("schema.org" in e for e in emails)
