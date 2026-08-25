from __future__ import annotations

"""Configuration file support (smart defaults without `init`).

Darco reads an optional config from the current working directory:

    darco.toml  /  .darco.toml        (preferred; TOML)
    darco.json  /  .darco.json        (fallback; JSON)

It can also be pointed at explicitly with `--config <path>`.

Example (darco.toml)::

    target = "https://app.example.com"
    format = "md"                 # md | json | table (default md)

    [fuzz]
    enabled = true                # master switch for `darco fuzz`
    auto = false                  # if true, `send` also runs fuzz variants
    concurrency = 6
    mutations = ["flip", "type_confusion", "boundary", "sql", "xss"]

    # base headers applied to every request
    headers = ["X-API-Key: deadbeef", "Authorization: Bearer tok"]

    follow_redirects = true
    timeout = 10.0
    insecure = false
"""

import json
from dataclasses import dataclass, field
from pathlib import Path

from .errors import DarcoError
from .models import NameValue

_CONFIG_NAMES = ("darco.toml", ".darco.toml", "darco.json", ".darco.json")

DEFAULT_FUZZ_MUTATIONS = ["flip", "type_confusion", "boundary", "sql", "xss"]


@dataclass
class FuzzConfig:
    enabled: bool = True
    auto: bool = False
    concurrency: int = 6
    mutations: list[str] = field(default_factory=lambda: list(DEFAULT_FUZZ_MUTATIONS))


@dataclass
class DarcoConfig:
    target: str | None = None
    format: str = "md"
    fuzz: FuzzConfig = field(default_factory=FuzzConfig)
    headers: list[NameValue] = field(default_factory=list)
    follow_redirects: bool = True
    timeout: float = 10.0
    insecure: bool = False

    @classmethod
    def empty(cls) -> DarcoConfig:
        return cls()


def _parse_headers(raw) -> list[NameValue]:
    out: list[NameValue] = []
    if not raw:
        return out
    if isinstance(raw, dict):
        items = raw.items()
    else:
        items = []
        for line in raw:
            name, sep, value = str(line).partition(":")
            if not sep:
                raise DarcoError(
                    f"invalid config header (expected 'Name: value'): {line!r}"
                )
            items.append((name.strip(), value.strip()))
    for name, value in items:
        out.append(NameValue(name=name, value=value))
    return out


def _parse_fuzz(raw) -> FuzzConfig:
    if not raw:
        return FuzzConfig()
    return FuzzConfig(
        enabled=bool(raw.get("enabled", True)),
        auto=bool(raw.get("auto", False)),
        concurrency=int(raw.get("concurrency", 6)),
        mutations=list(raw.get("mutations", DEFAULT_FUZZ_MUTATIONS)),
    )


def from_dict(data: dict) -> DarcoConfig:
    if not isinstance(data, dict):
        raise DarcoError("config root must be a table/object")
    return DarcoConfig(
        target=data.get("target"),
        format=str(data.get("format", "md")),
        fuzz=_parse_fuzz(data.get("fuzz")),
        headers=_parse_headers(data.get("headers")),
        follow_redirects=bool(data.get("follow_redirects", True)),
        timeout=float(data.get("timeout", 10.0)),
        insecure=bool(data.get("insecure", False)),
    )


def _read_file(path: Path) -> DarcoConfig:
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".json":
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise DarcoError(f"invalid JSON config {path}: {exc}") from exc
    else:
        try:
            import tomllib

            data = tomllib.loads(text)
        except ModuleNotFoundError:  # pragma: no cover - py<3.11
            raise DarcoError(
                "TOML config requires Python 3.11+; use darco.json instead"
            )
        except Exception as exc:  # tomllib.TOMLDecodeError in 3.11+
            raise DarcoError(f"invalid TOML config {path}: {exc}") from exc
    return from_dict(data)


def discover(cwd: Path | None = None) -> Path | None:
    base = Path(cwd or Path.cwd())
    for name in _CONFIG_NAMES:
        cand = base / name
        if cand.is_file():
            return cand
    return None


def load(path: Path | None = None, cwd: Path | None = None) -> DarcoConfig:
    """Load config from `path` (explicit), else discover in `cwd`, else empty."""
    if path is not None:
        p = Path(path)
        if not p.is_file():
            raise DarcoError(f"config file not found: {path}")
        return _read_file(p)
    found = discover(cwd)
    if found is None:
        return DarcoConfig.empty()
    return _read_file(found)
