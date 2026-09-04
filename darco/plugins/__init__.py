"""Scan plugin system.

Darco's active scanners (`scan_sqli` and friends) dispatch to registered
plugins at well-defined hook points. Each plugin can contribute testable
parameters, extend per-parameter analysis, run post-scan logic, and register
**custom template matcher/extractor types** (see ``darco.templates.custom``)
— without touching the core scanner or template-engine code.

Built-in plugins register themselves when this package is imported:

* ``xml_inject`` — detects XML-body endpoints and tests entity-encoded SQLi
  (WAF bypass via ``&#x..;`` character references).
* ``timing`` — registers the ``delay`` custom template matcher for
  time-based blind detection in attack templates.

External plugins are plain ``*.py`` files loaded from directories passed to
``--plugin-dir`` (``sql``, ``template run``, ...) or listed in the
``DARCO_PLUGIN_PATH`` environment variable (colon-separated). Any
``ScanPlugin`` subclass decorated with ``@register_plugin`` in those files is
picked up automatically.
"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path


class ScanPlugin:
    """Base class for scan extensions.

    Subclasses set ``name`` / ``description`` and override any of the hooks.
    Hook points:

    * ``collect_params`` — contribute ``(param_type, name, value)`` tuples the
      SQLi scanner should test (e.g. XML element text from a raw body).
    * ``after_param`` — called after the core tests for every parameter the
      scanner audited; use for channel-specific probes and findings.
    * ``after_scan`` — called once after the whole scan; use for summary
      findings or cleanup.
    * ``template_matcher_types`` / ``template_extractor_types`` — return
      ``{type_name: callable}`` dicts of custom template matcher/extractor
      implementations. These are synced into the ``darco.templates.custom``
      registries when the plugin loads, so YAML templates can use the new
      types immediately.
    """

    name: str = ""
    description: str = ""
    source: str = "builtin"

    def collect_params(
        self,
        request,
        include_state_fields: bool = False,
        param_filter: str | None = None,
    ) -> list[tuple[str, str, str]]:
        return []

    def after_param(
        self,
        request,
        session,
        param_type: str,
        param_name: str,
        orig_val: str,
        baseline,
        result,
    ) -> None:
        pass

    def after_scan(self, request, session, result) -> None:
        pass

    def template_matcher_types(self) -> dict:
        """Custom template matcher types contributed by this plugin."""
        return {}

    def template_extractor_types(self) -> dict:
        """Custom template extractor types contributed by this plugin."""
        return {}


_REGISTRY: dict[str, ScanPlugin] = {}

# File paths of external plugins loaded this session.
EXTERNAL_SOURCES: list[str] = []


def _sync_template_types(plugin: ScanPlugin) -> None:
    """Register plugin-contributed custom template types (best effort)."""
    try:
        from ..templates.custom import (
            register_extractor_type,
            register_matcher_type,
        )
    except ImportError:  # pragma: no cover - templates package always present
        return
    for type_name, fn in (plugin.template_matcher_types() or {}).items():
        register_matcher_type(type_name, fn, source=f"plugin:{plugin.name}")
    for type_name, fn in (plugin.template_extractor_types() or {}).items():
        register_extractor_type(type_name, fn, source=f"plugin:{plugin.name}")


def register_plugin(cls):
    """Class decorator: instantiate and register a ScanPlugin subclass."""
    plugin = cls()
    if not plugin.name:
        raise ValueError(f"plugin {cls.__name__} must define a name")
    _REGISTRY[plugin.name] = plugin
    _sync_template_types(plugin)
    return cls


def registered_plugins() -> list[ScanPlugin]:
    """All registered plugins in registration order."""
    ensure_external_plugins()
    return list(_REGISTRY.values())


def active_plugins(
    only: list[str] | None = None, skip: list[str] | None = None
) -> list[ScanPlugin]:
    """Plugins to run for a scan, honoring --plugin / --skip-plugin filters."""
    ensure_external_plugins()
    plugs = list(_REGISTRY.values())
    if only:
        plugs = [p for p in plugs if p.name in only]
    if skip:
        plugs = [p for p in plugs if p.name not in skip]
    return plugs


def get_plugin(name: str) -> ScanPlugin | None:
    ensure_external_plugins()
    return _REGISTRY.get(name)


# ------------------------------------------------------------- external loading

_EXTERNAL_LOADED = False


def load_plugin_file(path: str | Path) -> list[ScanPlugin]:
    """Import a single ``*.py`` plugin file and return newly loaded plugins."""
    p = Path(path).resolve()
    before = set(_REGISTRY)
    mod_name = (
        f"_darco_ext_plugin_{p.stem.replace('-', '_')}_{abs(hash(str(p))) % 10000}"
    )
    spec = importlib.util.spec_from_file_location(mod_name, p)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load plugin file: {p}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = module
    try:
        spec.loader.exec_module(module)
    except Exception as exc:
        sys.modules.pop(mod_name, None)
        raise ImportError(f"error loading plugin {p}: {exc}") from exc
    if p.parent not in EXTERNAL_SOURCES:
        EXTERNAL_SOURCES.append(str(p))
    fresh = [pl for name, pl in _REGISTRY.items() if name not in before]
    for pl in fresh:
        pl.source = str(p)
    return fresh


def load_plugins_from_dir(
    dir_path: str | Path, recursive: bool = True
) -> list[ScanPlugin]:
    """Load every ``*.py`` plugin file from a directory (sorted, recursive)."""
    d = Path(dir_path)
    if not d.is_dir():
        raise FileNotFoundError(f"plugin directory not found: {d}")
    pattern = "**/*.py" if recursive else "*.py"
    loaded: list[ScanPlugin] = []
    for f in sorted(d.glob(pattern)):
        try:
            loaded.extend(load_plugin_file(f))
        except ImportError:
            continue
    return loaded


def ensure_external_plugins() -> None:
    """Load plugins from DARCO_PLUGIN_PATH once per process."""
    global _EXTERNAL_LOADED
    if _EXTERNAL_LOADED:
        return
    _EXTERNAL_LOADED = True
    raw = os.environ.get("DARCO_PLUGIN_PATH", "")
    for entry in [e.strip() for e in raw.split(os.pathsep) if e.strip()]:
        try:
            load_plugins_from_dir(entry)
        except (FileNotFoundError, OSError):
            continue


def reset_external_state() -> None:
    """Testing helper: allow DARCO_PLUGIN_PATH re-processing."""
    global _EXTERNAL_LOADED
    _EXTERNAL_LOADED = False


# Import built-in plugins so they register themselves.
from . import timing, xml_inject  # noqa: F401

# Only register evilspider plugin if evilspider CLI is installed
try:
    from . import evilspider_plugin  # noqa: F401
except ImportError:
    pass

__all__ = [
    "EXTERNAL_SOURCES",
    "ScanPlugin",
    "active_plugins",
    "ensure_external_plugins",
    "get_plugin",
    "load_plugin_file",
    "load_plugins_from_dir",
    "register_plugin",
    "registered_plugins",
    "reset_external_state",
]
