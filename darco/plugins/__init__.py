"""Scan plugin system.

Darco's active scanners (`scan_sqli` and friends) dispatch to registered
plugins at well-defined hook points. Each plugin can contribute testable
parameters, extend per-parameter analysis, and run post-scan logic — without
touching the core scanner code.

Built-in plugins register themselves when this package is imported:

* ``xml_inject`` — detects XML-body endpoints and tests entity-encoded SQLi
  (WAF bypass via ``&#x..;`` character references).
"""

from __future__ import annotations


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
    """

    name: str = ""
    description: str = ""

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


_REGISTRY: dict[str, ScanPlugin] = {}


def register_plugin(cls):
    """Class decorator: instantiate and register a ScanPlugin subclass."""
    plugin = cls()
    if not plugin.name:
        raise ValueError(f"plugin {cls.__name__} must define a name")
    _REGISTRY[plugin.name] = plugin
    return cls


def registered_plugins() -> list[ScanPlugin]:
    """All registered plugins in registration order."""
    return list(_REGISTRY.values())


def active_plugins(
    only: list[str] | None = None, skip: list[str] | None = None
) -> list[ScanPlugin]:
    """Plugins to run for a scan, honoring --plugin / --skip-plugin filters."""
    plugs = list(_REGISTRY.values())
    if only:
        plugs = [p for p in plugs if p.name in only]
    if skip:
        plugs = [p for p in plugs if p.name not in skip]
    return plugs


def get_plugin(name: str) -> ScanPlugin | None:
    return _REGISTRY.get(name)


# Import built-in plugins so they register themselves.
from . import xml_inject  # noqa: F401

__all__ = [
    "ScanPlugin",
    "active_plugins",
    "get_plugin",
    "register_plugin",
    "registered_plugins",
]
