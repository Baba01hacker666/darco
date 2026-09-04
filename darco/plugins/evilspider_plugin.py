"""Darco plugin: wrap evilspider as a scan backend.

EvilSpider runs as a subprocess (`evilspider` CLI), crawls the target, and
produces JSON output. This plugin:
  * runs evilspider against a discovered target
  * ingests its JSON results as Darco findings
  * contributes evilspider-discovered params to the SQLi scanner
  * passes HTTP_PROXY/HTTPS_PROXY env vars through to evilspider
  * gracefully disables itself if evilspider is not installed
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from darco.models import Request, SessionState, SqliFinding, SqliScanResult

from . import ScanPlugin, register_plugin


def _evilspider_available() -> bool:
    """Check if evilspider CLI is installed."""
    return shutil.which("evilspider") is not None


# Module-level proxy config (set by scanner before running scan)
_proxy: str | None = None


def configure(proxy: str | None = None) -> None:
    """Set proxy for evilspider subprocess. Called by scanner before scan."""
    global _proxy
    _proxy = proxy


def _run_evilspider(url: str, depth: int = 3, timeout: int = 120) -> dict | None:
    """Run evilspider and return parsed JSON, or None on failure."""
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        out_path = f.name

    # Pass proxy env vars through
    env = os.environ.copy()
    if _proxy:
        env["HTTP_PROXY"] = _proxy
        env["HTTPS_PROXY"] = _proxy

    try:
        result = subprocess.run(
            ["evilspider", url, "-d", str(depth), "-o", out_path, "--no-color"],
            capture_output=True,
            timeout=timeout,
            env=env,
            check=False,
        )
        if result.returncode != 0:
            return None
        data = json.loads(Path(out_path).read_text())
        return data
    except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError, OSError):
        return None
    finally:
        try:
            Path(out_path).unlink()
        except OSError:
            pass


@register_plugin
class EvilSpiderPlugin(ScanPlugin):
    name = "evilspider"
    description = (
        "Runs evilspider crawler against the target and imports "
        "discovered endpoints, forms, secrets, and security signals as Darco findings"
    )

    _last_result: dict | None = None
    _available: bool | None = None

    def _is_available(self) -> bool:
        if self._available is None:
            self._available = _evilspider_available()
        return self._available

    def collect_params(
        self,
        request: Request,
        include_state_fields: bool = False,
        param_filter: str | None = None,
    ) -> list[tuple[str, str, str]]:
        """Trigger evilspider crawl on the first request, contribute params."""
        if not self._is_available():
            return []

        if self._last_result is None:
            self._last_result = _run_evilspider(request.url)

        if not self._last_result:
            return []

        params: list[tuple[str, str, str]] = []
        seen: set[tuple[str, str]] = set()

        for ep in self._last_result.get("endpoints", []):
            for p in ep.get("params", []):
                key = (ep["url"], p["name"])
                if key in seen:
                    continue
                seen.add(key)
                if param_filter is None or p["name"] == param_filter:
                    params.append(("url", p["name"], p.get("value", "1")))

        for form in self._last_result.get("forms", []):
            for inp in form.get("inputs", []):
                key = (form["action"], inp["name"])
                if key in seen:
                    continue
                seen.add(key)
                if param_filter is None or inp["name"] == param_filter:
                    params.append(("form", inp["name"], inp.get("default", "1")))

        return params

    def after_param(self, request, session, param_type, param_name, orig_val, baseline, result):
        pass

    def after_scan(self, request: Request, session: SessionState, result: SqliScanResult) -> None:
        """After the core scan, ingest evilspider findings."""
        if not self._is_available():
            return

        if self._last_result is None:
            self._last_result = _run_evilspider(request.url)
        if not self._last_result:
            return

        # Secrets
        for s in self._last_result.get("secrets", []):
            result.vulnerabilities.append(
                SqliFinding(
                    param=s.get("type", "unknown"),
                    param_type="secret",
                    injection_type="secret_exposure",
                    confidence="high",
                    payload=s.get("value", ""),
                    baseline_status=200,
                    payload_status=200,
                    evidence=f"Secret found: {s.get('type')} = {s.get('value')}",
                    suggestion="Rotate exposed credentials. Remove secrets from client-side code.",
                )
            )

        # Security issues
        for issue in self._last_result.get("security_issues", []):
            result.vulnerabilities.append(
                SqliFinding(
                    param=issue.get("type", "unknown"),
                    param_type="security",
                    injection_type="security_issue",
                    confidence=issue.get("confidence", "medium"),
                    payload="",
                    baseline_status=200,
                    payload_status=200,
                    evidence=issue.get("description", ""),
                    suggestion=issue.get("recommendation", ""),
                )
            )

        self._last_result = None
