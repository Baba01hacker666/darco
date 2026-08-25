import json

import pytest

from darco.errors import DarcoError
from darco.models import BodyType, NameValue, Request
from darco.mutate import Mutation, apply_mutations, flip_value, parse_mutation_ops


def _req():
    return Request(
        method="POST",
        url="http://t.test/x",
        headers=[NameValue(name="Host", value="t.test"), NameValue(name="X-A", value="1")],
        params=[NameValue(name="enabled", value="true"), NameValue(name="q", value="x")],
        body_type=BodyType.FORM,
        body_form=[NameValue(name="enabled", value="true"), NameValue(name="user", value="u")],
    )


def test_set_and_unset_header():
    req = _req()
    req2, _ = apply_mutations(req, [Mutation("set_header", name="X-A", value="2"), Mutation("unset_header", name="host")])
    assert any(h.name == "X-A" and h.value == "2" for h in req2.headers)
    assert not any(h.name.lower() == "host" for h in req2.headers)
    assert next(h.value for h in req.headers if h.name == "X-A") == "1"  # original untouched


def test_set_unset_flip_param():
    req = _req()
    req2, _ = apply_mutations(req, [Mutation("flip_param", name="enabled")])
    assert next(p.value for p in req2.params if p.name == "enabled") == "false"
    assert next(p.value for p in req2.body_form if p.name == "enabled") == "false"
    req3, _ = apply_mutations(req2, [Mutation("set_param", name="q", value="z"), Mutation("unset_param", name="user")])
    assert next(p.value for p in req3.params if p.name == "q") == "z"
    assert not any(p.name == "user" for p in req3.body_form)


def test_flip_value_variants():
    assert flip_value("TRUE") == "FALSE"
    assert flip_value("1") == "0"
    assert flip_value("No") == "Yes"
    with pytest.raises(DarcoError):
        flip_value("maybe")


def test_strip_session():
    req = _req()
    req2, desc = apply_mutations(req, [Mutation("strip_session")])
    assert req2.session_stripped is True
    assert "strip session" in desc[0]


def test_set_body_from_file(tmp_path):
    f = tmp_path / "body.txt"
    f.write_text("raw body here")
    req = _req()
    req2, _ = apply_mutations(req, [Mutation("set_body", value=f"@{f}")])
    assert req2.body_type == BodyType.RAW
    assert req2.body_raw == "raw body here"


def test_mutations_lineage():
    req = _req()
    req2, desc = apply_mutations(req, [Mutation("set_header", name="X", value="1"), Mutation("set_header", name="X", value="2")])
    assert req2.mutations == ["set header X: 1", "set header X: 2"]
    assert len(desc) == 2


def test_parse_mutation_ops():
    ops = parse_mutation_ops({
        "set_header": ["A=1"],
        "unset_header": ["B"],
        "set_param": ["p=2"],
        "unset_param": ["q"],
        "flip_param": ["r"],
        "strip_session": True,
        "set_body": "zzz",
    })
    kinds = [o.op for o in ops]
    assert kinds == ["set_header", "unset_header", "set_param", "unset_param", "flip_param", "strip_session", "set_body"]
    assert ops[0].name == "A" and ops[0].value == "1"


def test_modify_file(tmp_path):
    f = tmp_path / "ops.json"
    f.write_text(json.dumps([{"op": "set_header", "name": "Y", "value": "9"}, {"op": "strip_session"}]))
    ops = parse_mutation_ops({"modify_file": str(f)})
    assert [o.op for o in ops] == ["set_header", "strip_session"]
    with pytest.raises(DarcoError):
        parse_mutation_ops({"modify_file": str(tmp_path / "missing.json")})
