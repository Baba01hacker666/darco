"""Built-in ``timing`` scan plugin.

Demonstrates the plugin -> template bridge: it registers the ``delay``
custom matcher type so YAML attack templates can detect time-based blind
behavior without any engine changes::

    matchers:
      - type: delay
        min_ms: 2000

The matcher fires when the request took at least ``min_ms`` milliseconds.
"""

from __future__ import annotations

import httpx

from . import ScanPlugin, register_plugin


def _match_delay(
    matcher, resp: httpx.Response, elapsed_ms: float = 0.0
) -> tuple[bool, list[str]]:
    """Match when response time >= min_ms (time-based blind detection)."""
    threshold = float(getattr(matcher, "min_ms", 0) or 0)
    ok = elapsed_ms >= threshold
    return ok, ([f"{elapsed_ms:.0f}ms>={threshold:.0f}ms"] if ok else [])


@register_plugin
class TimingPlugin(ScanPlugin):
    name = "timing"
    description = (
        "Registers the 'delay' custom template matcher (time-based blind detection)"
    )

    def template_matcher_types(self) -> dict:
        return {"delay": _match_delay}


__all__ = ["TimingPlugin"]
