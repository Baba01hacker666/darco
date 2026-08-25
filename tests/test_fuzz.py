from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent


def run(args, cwd, json_only=True):
    import os

    env = dict(os.environ)
    env["PYTHONPATH"] = str(REPO)
    if json_only:
        args = ["--json", *args]
    return subprocess.run(
        [sys.executable, "-m", "darco", *args],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        timeout=90,
    )


def _write(target, name, text):
    p = Path(target) / name
    p.write_text(text)
    return p


# ------------------------------------------------------------------ config file
def test_config_json_discovery(tmp_path):
    from darco.configfile import load

    _write(tmp_path, "darco.json", json.dumps({
        "target": "https://x.test",
        "format": "json",
        "headers": ["X-Key: abc", "Authorization: Bearer z"],
        "fuzz": {"enabled": True, "concurrency": 3},
    }))
    cfg = load(cwd=tmp_path)
    assert cfg.target == "https://x.test"
    assert cfg.format == "json"
    assert len(cfg.headers) == 2
    assert cfg.fuzz.concurrency == 3


def test_config_toml_discovery(tmp_path):
    from darco.configfile import load

    _write(tmp_path, "darco.toml", 'target = "https://y.test"\nformat = "md"\n'
            '[fuzz]\nenabled = true\nconcurrency = 4\n')
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
    from darco.models import Request, NameValue

    req = Request(method="GET", url="http://t/u", params=[NameValue(name="id", value="5")])
    labels = [l for l, _, _ in build_variants(req)]
    assert any(l.startswith("type-confuse:id=") for l in labels)
    assert any(l.startswith("boundary:id=") for l in labels)


def test_fuzz_build_variants_flip_boolean():
    from darco.fuzz import build_variants
    from darco.models import Request, NameValue

    req = Request(method="GET", url="http://t/u", params=[NameValue(name="debug", value="true")])
    labels = [l for l, _, _ in build_variants(req)]
    assert "flip:debug" in labels
    assert "strip-session" in labels


def test_fuzz_run_detects_status_change(app, tmp_path):
    from darco.fuzz import build_variants, run_fuzz, _classify
    from darco.models import Request, NameValue, Response, SessionState

    # direct classification check: 403 baseline, 200 after strip-session
    base = Response(status_code=403, reason="Forbidden", headers=[], body="forbidden",
                    body_len=9, url=app, elapsed_ms=1, redirects=[], set_cookies=[])
    resp200 = Response(status_code=200, reason="OK", headers=[], body="ok",
                       body_len=2, url=app, elapsed_ms=1, redirects=[], set_cookies=[])
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
