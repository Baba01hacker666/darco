from __future__ import annotations

from typing import Any

from ..models import Request, Response, TechDetection, WafDetection
from .tech import detect_technologies
from .waf import detect_waf


def detect_all(response: Response, request: Request | None = None) -> dict[str, Any]:
    """Run full technology and WAF detection on a response."""
    return {
        "technologies": detect_technologies(response, request),
        "wafs": detect_waf(response, request),
    }


__all__ = [
    "TechDetection",
    "WafDetection",
    "detect_all",
    "detect_technologies",
    "detect_waf",
]
