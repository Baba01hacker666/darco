import json
import os
from pathlib import Path

from click.testing import CliRunner

from darco.cli import cli

REPO = Path(__file__).resolve().parent.parent


class CliResult:
    def __init__(self, returncode: int, stdout: str, stderr: str = ""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def run(args, cwd, json_only=True):
    runner = CliRunner()
    if json_only:
        args = ["--json", *args]
    old_cwd = os.getcwd()
    os.chdir(cwd)
    try:
        res = runner.invoke(cli, args)
        stderr = str(res.exception) if res.exception else getattr(res, "stderr", "")
        return CliResult(res.exit_code, res.stdout, stderr)
    finally:
        os.chdir(old_cwd)


def _write(target, name, text):
    p = Path(target) / name
    p.write_text(text)
    return p


# ------------------------------------------------------------------ config file
def test_config_json_discovery(tmp_path):
    from darco.configfile import load

    _write(
        tmp_path,
        "darco.json",
        json.dumps(
            {
                "target": "https://x.test",
                "format": "json",
                "headers": ["X-Key: abc", "Authorization: Bearer z"],
                "fuzz": {"enabled": True, "concurrency": 3},
            }
        ),
    )
    cfg = load(cwd=tmp_path)
    assert cfg.target == "https://x.test"
    assert cfg.format == "json"
    assert len(cfg.headers) == 2
    assert cfg.fuzz.concurrency == 3


def test_config_toml_discovery(tmp_path):
    from darco.configfile import load

    _write(
        tmp_path,
        "darco.toml",
        'target = "https://y.test"\nformat = "md"\n[fuzz]\nenabled = true\nconcurrency = 4\n',
    )
    cfg = load(cwd=tmp_path)
    assert cfg.target == "https://y.test"
    assert cfg.fuzz.concurrency == 4


def test_config_explicit_path(tmp_path):
    from darco.configfile import load

    p = _write(tmp_path, "my.toml", 'target = "https://z.test"\n')
    cfg = load(p, cwd=tmp_path)
    assert cfg.target == "https://z.test"


def test_config_none(tmp_path):
    from darco.configfile import load

    cfg = load(cwd=tmp_path)
    assert cfg.target is None
    assert cfg.fuzz.enabled is True


# ------------------------------------------------------------------ fuzz engine
def test_fuzz_build_variants_numeric_type_confusion():
    from darco.fuzz import build_variants
    from darco.models import NameValue, Request

    req = Request(
        method="GET", url="http://t/u", params=[NameValue(name="id", value="5")]
    )
    labels = [lbl for lbl, _, _ in build_variants(req)]
    assert any(lbl.startswith("type-confuse:id=") for lbl in labels)
    assert any(lbl.startswith("boundary:id=") for lbl in labels)


def test_fuzz_build_variants_flip_boolean():
    from darco.fuzz import build_variants
    from darco.models import NameValue, Request

    req = Request(
        method="GET", url="http://t/u", params=[NameValue(name="debug", value="true")]
    )
    labels = [lbl for lbl, _, _ in build_variants(req)]
    assert "flip:debug" in labels
    assert "strip-session" in labels


def test_fuzz_build_variants_form_body_boolean():
    from darco.fuzz import build_variants
    from darco.models import BodyType, NameValue, Request

    req = Request(
        method="POST",
        url="http://t/login",
        body_type=BodyType.FORM,
        body_form=[
            NameValue(name="is_admin", value="false"),
            NameValue(name="user_id", value="100"),
        ],
    )
    variants = build_variants(req)
    labels = [lbl for lbl, _, _ in variants]
    assert "flip:is_admin" in labels
    assert any(lbl.startswith("type-confuse:user_id=") for lbl in labels)


def test_fuzz_run_detects_status_change(app, tmp_path):
    from darco.fuzz import _classify
    from darco.models import Response

    # direct classification check: 403 baseline, 200 after strip-session
    base = Response(
        status_code=403,
        reason="Forbidden",
        headers=[],
        body="forbidden",
        body_len=9,
        url=app,
        elapsed_ms=1,
        redirects=[],
        set_cookies=[],
    )
    resp200 = Response(
        status_code=200,
        reason="OK",
        headers=[],
        body="ok",
        body_len=2,
        url=app,
        elapsed_ms=1,
        redirects=[],
        set_cookies=[],
    )
    c = _classify("strip-session", base, resp200, None)
    assert c["anomaly"] == "status_change"
    assert "403 -> 200" in c["detail"]


def test_fuzz_command_oneshot(app, tmp_path):
    # /debug?enabled=true flips to false -> body changes (secret removed) -> anomaly
    r = run(["fuzz", "-u", f"{app}/debug?enabled=true"], tmp_path)
    assert r.returncode == 0, r.stderr
    d = json.loads(r.stdout)
    assert d["total_variants"] >= 1
    assert any(x["label"].startswith("flip:enabled") for x in d["results"])


def test_fuzz_disabled_in_config_errors(app, tmp_path):
    _write(tmp_path, "darco.json", json.dumps({"fuzz": {"enabled": False}}))
    r = run(["fuzz", "-u", f"{app}/echo"], tmp_path)
    assert r.returncode == 1
    assert "disabled" in r.stderr


def test_send_fuzz_flag_oneshot(app, tmp_path):
    r = run(["send", "-u", f"{app}/admin", "--fuzz"], tmp_path)
    assert r.returncode == 0, r.stderr
    d = json.loads(r.stdout)
    assert "fuzz" in d
    assert d["fuzz"]["total_variants"] >= 1
