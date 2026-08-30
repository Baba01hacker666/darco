from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .errors import DarcoError
from .models import BodyType, NameValue, Request

FLIP_MAP = {
    "true": "false",
    "false": "true",
    "1": "0",
    "0": "1",
    "yes": "no",
    "no": "yes",
    "on": "off",
    "off": "on",
}


@dataclass
class Mutation:
    op: str
    name: str = ""
    value: str = ""
    extra: dict = field(default_factory=dict)

    def describe(self) -> str:
        if self.op == "set_header":
            return f"set header {self.name}: {self.value}"
        if self.op == "unset_header":
            return f"unset header {self.name}"
        if self.op == "set_param":
            return f"set param {self.name}={self.value}"
        if self.op == "unset_param":
            return f"unset param {self.name}"
        if self.op == "flip_param":
            return f"flip param {self.name}"
        if self.op == "strip_session":
            return "strip session (remove cookies + auth headers)"
        if self.op == "set_body":
            return f"set body ({len(self.value)} bytes)"
        return f"{self.op} {self.name}"


def flip_value(value: str) -> str:
    key = value.strip().lower()
    if key not in FLIP_MAP:
        raise DarcoError(
            f"cannot flip value {value!r} (expected true/false, 1/0, yes/no, on/off)"
        )
    if value.strip() != value:
        return FLIP_MAP[key]
    if value.islower():
        return FLIP_MAP[key]
    if value.isupper():
        return FLIP_MAP[key].upper()
    return FLIP_MAP[key].capitalize()


def mutations_from_dicts(items: list[dict]) -> list[Mutation]:
    """Build a Mutation list from a list of op dicts (the --modify-file shape).

    Each dict must carry an ``op`` key. Unknown ops raise ``DarcoError``. This is
    the shared parser used by both ``--modify-file`` and the fuzz engine, so the
    op vocabulary stays in one place.
    """
    ops: list[Mutation] = []
    for item in items:
        op = item.get("op")
        if op == "set_header":
            ops.append(
                Mutation(
                    "set_header", name=item.get("name", ""), value=item.get("value", "")
                )
            )
        elif op == "unset_header":
            ops.append(Mutation("unset_header", name=item.get("name", "")))
        elif op == "set_param":
            ops.append(
                Mutation(
                    "set_param", name=item.get("name", ""), value=item.get("value", "")
                )
            )
        elif op == "unset_param":
            ops.append(Mutation("unset_param", name=item.get("name", "")))
        elif op == "flip_param":
            ops.append(Mutation("flip_param", name=item.get("name", "")))
        elif op == "strip_session":
            ops.append(Mutation("strip_session"))
        elif op == "set_body":
            ops.append(Mutation("set_body", value=item.get("value", "")))
        else:
            raise DarcoError(f"unknown mutation op: {op!r}")
    return ops


def parse_mutation_ops(options: dict) -> list[Mutation]:
    """Translate CLI mutation flags into a Mutation list."""
    ops: list[Mutation] = []
    for item in options.get("set_header", []):
        name, _, value = item.partition("=")
        if not name:
            raise DarcoError(f"invalid --set-header (expected NAME=VALUE): {item!r}")
        ops.append(Mutation("set_header", name=name.strip(), value=value))
    for name in options.get("unset_header", []):
        ops.append(Mutation("unset_header", name=name))
    for item in options.get("set_param", []):
        name, _, value = item.partition("=")
        if not name:
            raise DarcoError(f"invalid --set-param (expected NAME=VALUE): {item!r}")
        ops.append(Mutation("set_param", name=name.strip(), value=value))
    for name in options.get("unset_param", []):
        ops.append(Mutation("unset_param", name=name))
    for name in options.get("flip_param", []):
        ops.append(Mutation("flip_param", name=name))
    if options.get("strip_session"):
        ops.append(Mutation("strip_session"))
    body = options.get("set_body")
    if body is not None:
        ops.append(Mutation("set_body", value=body))
    modify_file = options.get("modify_file")
    if modify_file:
        ops.extend(_parse_modify_file(modify_file))
    return ops


def _parse_modify_file(path: str) -> list[Mutation]:
    import json

    try:
        items = json.loads(Path(path).read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise DarcoError(f"invalid --modify-file: {exc}") from exc
    if not isinstance(items, list):
        raise DarcoError("--modify-file must contain a JSON list of ops")
    return mutations_from_dicts(items)


def apply_mutations(request: Request, ops: list[Mutation]) -> tuple[Request, list[str]]:
    """Return (new Request, descriptions). Original request is not modified."""
    req = request.model_copy(deep=True)
    descriptions: list[str] = []

    def find_param(name: str) -> NameValue | None:
        for p in req.params:
            if p.name.lower() == name.lower():
                return p
        return None

    def find_form(name: str) -> NameValue | None:
        for p in req.body_form:
            if p.name.lower() == name.lower():
                return p
        return None

    def find_json_key(name: str) -> str | None:
        if req.body_type == BodyType.JSON and isinstance(req.body_json, dict):
            for k in req.body_json:
                if k.lower() == name.lower():
                    return k
        return None

    for op in ops:
        if op.op == "set_header":
            found = False
            for h in req.headers:
                if h.name.lower() == op.name.lower():
                    h.value = op.value
                    found = True
            if not found:
                req.headers.append(NameValue(name=op.name, value=op.value))
            descriptions.append(op.describe())
        elif op.op == "unset_header":
            req.headers = [h for h in req.headers if h.name.lower() != op.name.lower()]
            descriptions.append(op.describe())
        elif op.op == "set_param":
            found = find_param(op.name)
            form = find_form(op.name)
            jkey = find_json_key(op.name)
            if found:
                found.value = op.value
            if form:
                form.value = op.value
            if jkey is not None and isinstance(req.body_json, dict):
                orig_val = req.body_json[jkey]
                if isinstance(orig_val, bool):
                    req.body_json[jkey] = op.value.lower() in ("true", "1", "yes")
                elif isinstance(orig_val, int) and not isinstance(orig_val, bool):
                    try:
                        req.body_json[jkey] = int(op.value)
                    except ValueError:
                        req.body_json[jkey] = op.value
                elif isinstance(orig_val, float):
                    try:
                        req.body_json[jkey] = float(op.value)
                    except ValueError:
                        req.body_json[jkey] = op.value
                else:
                    req.body_json[jkey] = op.value
            if not found and not form and jkey is None:
                if req.body_type == BodyType.FORM:
                    req.body_form.append(NameValue(name=op.name, value=op.value))
                elif req.body_type == BodyType.JSON and isinstance(req.body_json, dict):
                    req.body_json[op.name] = op.value
                else:
                    req.params.append(NameValue(name=op.name, value=op.value))
            descriptions.append(op.describe())
        elif op.op == "unset_param":
            req.params = [p for p in req.params if p.name.lower() != op.name.lower()]
            req.body_form = [
                p for p in req.body_form if p.name.lower() != op.name.lower()
            ]
            if req.body_type == BodyType.JSON and isinstance(req.body_json, dict):
                keys_to_del = [k for k in req.body_json if k.lower() == op.name.lower()]
                for k in keys_to_del:
                    del req.body_json[k]
            descriptions.append(op.describe())
        elif op.op == "flip_param":
            p = find_param(op.name)
            form = find_form(op.name)
            jkey = find_json_key(op.name)
            if p is None and form is None and jkey is None:
                raise DarcoError(
                    f"cannot flip param {op.name!r}: not present in request"
                )
            if p is not None:
                p.value = flip_value(p.value)
            if form is not None:
                form.value = flip_value(form.value)
            if jkey is not None and isinstance(req.body_json, dict):
                cur_val = req.body_json[jkey]
                if isinstance(cur_val, bool):
                    req.body_json[jkey] = not cur_val
                elif str(cur_val).isdigit():
                    req.body_json[jkey] = 0 if int(cur_val) != 0 else 1
                else:
                    flipped_str = flip_value(str(cur_val))
                    if flipped_str.lower() in ("true", "false"):
                        req.body_json[jkey] = flipped_str.lower() == "true"
                    else:
                        req.body_json[jkey] = flipped_str
            descriptions.append(op.describe())
        elif op.op == "strip_session":
            req.session_stripped = True
            req.cookies = []
            req.headers = [
                h
                for h in req.headers
                if h.name.lower()
                not in {
                    "authorization",
                    "cookie",
                    "proxy-authorization",
                    "x-api-key",
                    "x-auth-token",
                }
            ]
            descriptions.append(op.describe())
        elif op.op == "set_body":
            value = op.value
            if value.startswith("@") and len(value) > 1:
                try:
                    value = Path(value[1:]).read_text()
                except OSError as exc:
                    raise DarcoError(f"cannot read --set-body file: {exc}") from exc
            req.body_type = BodyType.RAW
            req.body_raw = value
            req.body_json = None
            req.body_form = []
            descriptions.append(op.describe())
        else:
            raise DarcoError(f"unknown mutation op: {op.op}")

    req.mutations = list(request.mutations) + descriptions
    return req, descriptions
