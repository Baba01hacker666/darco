import pytest

from darco.errors import DarcoError
from darco.models import (
    Cookie,
    Finding,
    HistoryRecord,
    NameValue,
    Request,
    Response,
    SessionState,
)
from darco.workspace import Workspace, default_workspace_name, merge_cookies


def test_default_workspace_name():
    assert default_workspace_name("http://example.com:8080/x") == "example.com.darco"
    assert default_workspace_name("https://sub.host.test") == "sub.host.test.darco"


def test_create_open_and_ids(tmp_path):
    ws = Workspace.create("http://t.test", tmp_path / "w.darco")
    assert (tmp_path / "w.darco" / "workspace.json").exists()
    assert (tmp_path / "w.darco" / "history.jsonl").exists()
    assert ws.next_id() == "0001"
    assert ws.next_id() == "0002"
    reopened = Workspace.open(tmp_path / "w.darco")
    assert reopened.next_id() == "0001"


def test_duplicate_create_raises(tmp_path):
    Workspace.create("http://t.test", tmp_path / "w.darco")
    with pytest.raises(DarcoError):
        Workspace.create("http://t.test", tmp_path / "w.darco")


def test_non_empty_dir_create_raises(tmp_path):
    non_empty = tmp_path / "existing_dir"
    non_empty.mkdir()
    (non_empty / "my_code.py").write_text("print('hello')")
    with pytest.raises(DarcoError, match="not empty"):
        Workspace.create("http://t.test", non_empty)
    assert (non_empty / "my_code.py").exists()  # file preserved, not wiped


def test_add_and_get_record(tmp_path):
    ws = Workspace.create("http://t.test", tmp_path / "w.darco")
    req = Request(method="GET", url="http://t.test/")
    resp = Response(status_code=200, reason="OK", body="hi", body_len=2)
    rec = HistoryRecord(id=ws.next_id(), ts="t", request=req, response=resp)
    ws.add_history(rec)
    got = ws.get_record("0001")
    assert got.response.body == "hi"
    with pytest.raises(DarcoError):
        ws.get_record("9999")


def test_session_roundtrip(tmp_path):
    ws = Workspace.create("http://t.test", tmp_path / "w.darco")
    session = SessionState(
        cookies=[Cookie(name="sid", value="v", domain="t.test")],
        csrf_headers={"t.test": [NameValue(name="X-CSRF-Token", value="tok")]},
    )
    ws.save_session(session)
    loaded = ws.load_session()
    assert loaded.cookies[0].name == "sid"
    assert loaded.csrf_headers["t.test"][0].value == "tok"


def test_findings_dedupe(tmp_path):
    ws = Workspace.create("http://t.test", tmp_path / "w.darco")
    f1 = Finding(id="x", type="boom", location="L", evidence="E")
    f2 = Finding(id="y", type="boom", location="L", evidence="E")
    f3 = Finding(id="z", type="other", location="L", evidence="E")
    assert ws.add_findings([f1, f2, f3]) == 2
    assert ws.add_findings([f1]) == 0
    assert len(ws.load_findings()) == 2


def test_merge_cookies():
    base = [Cookie(name="a", value="1", domain="h")]
    incoming = [Cookie(name="a", value="2", domain="h"), Cookie(name="b", value="3")]
    merged = merge_cookies(base, incoming, "h")
    assert len(merged) == 2
    assert next(c for c in merged if c.name == "a").value == "2"
