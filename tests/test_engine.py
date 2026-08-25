from darco.engine import send_and_record
from darco.models import BodyType, NameValue, Request


def _form(path, app, fields):
    return Request(
        method="POST",
        url=f"{app}{path}",
        body_type=BodyType.FORM,
        body_form=[NameValue(name=k, value=v) for k, v in fields],
        follow_redirects=False,
    )


def test_basic_get_recorded(app, workspace):
    session = workspace.load_session()
    rec, session = send_and_record(workspace, Request(method="GET", url=f"{app}/"), session)
    assert rec.id == "0001"
    assert rec.response.status_code == 200
    assert "login" in rec.response.body
    assert workspace.list_records()[0].id == "0001"


def test_login_captures_session_cookie(app, workspace):
    session = workspace.load_session()
    req = _form("/login", app, [("username", "u"), ("password", "hunter2")])
    rec, session = send_and_record(workspace, req, session)
    assert rec.response.status_code == 302
    assert any(c.name == "session" for c in session.cookies)
    persisted = workspace.load_session()
    assert any(c.name == "session" for c in persisted.cookies)


def test_csrf_header_capture_and_replay(app, workspace):
    session = workspace.load_session()
    rec, session = send_and_record(workspace, Request(method="GET", url=f"{app}/csrf"), session)
    assert session.csrf_headers.get("127.0.0.1", [])
    rec2, session = send_and_record(workspace, Request(method="GET", url=f"{app}/echo"), session)
    body = rec2.response.body
    assert "tok123" in body
    assert "csrf" in body.lower()


def test_otp_rate_limit_and_strip_session_bypass(app, workspace):
    session = workspace.load_session()
    login = _form("/login", app, [("username", "u"), ("password", "hunter2")])
    rec, session = send_and_record(workspace, login, session)
    assert rec.response.status_code == 302

    otp = _form("/otp", app, [("otp_code", "000000")])
    for _ in range(3):
        rec, session = send_and_record(workspace, otp, session)
        assert rec.response.status_code == 200
    rec, session = send_and_record(workspace, otp, session)
    assert rec.response.status_code == 429
    assert any(h.name.lower() == "retry-after" for h in rec.response.headers)

    stripped = otp.model_copy(deep=True)
    stripped.session_stripped = True
    rec2, session = send_and_record(workspace, stripped, session)
    assert rec2.response.status_code == 200
    assert "strip session" in rec2.request.mutations or rec2.request.session_stripped


def test_headers_preserved_and_form_body(app, workspace):
    session = workspace.load_session()
    req = Request(
        method="POST",
        url=f"{app}/echo",
        headers=[NameValue(name="X-Custom", value="yes")],
        body_type=BodyType.FORM,
        body_form=[NameValue(name="a", value="1")],
        follow_redirects=False,
    )
    rec, _ = send_and_record(workspace, req, session)
    body = rec.response.body
    assert "yes" in body
    assert "x-custom" in body.lower()
    assert '"body": "a=1"' in body


def test_query_params_rebuilt(app, workspace):
    session = workspace.load_session()
    req = Request(method="GET", url=f"{app}/debug", params=[NameValue(name="enabled", value="true")])
    rec, _ = send_and_record(workspace, req, session)
    assert "SECRET=super-secret-value" in rec.response.body
