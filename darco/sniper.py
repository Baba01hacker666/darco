"""Automated parameter payload injection and attack matrix engine.

Allows marking injection positions (e.g. `§param§`) across URL paths, query
parameters, headers, cookies, and request bodies, then iterating over them
using customizable attack modes:

* **Sniper**: Uses a single payload set; tests each position one by one
  while keeping all other positions at their base value.
* **Battering Ram**: Uses a single payload set; replaces all marked positions
  simultaneously with the same payload.
* **Pitchfork**: Uses multiple payload sets (one per position); iterates
  through them in lockstep (parallel vectors).
* **Cluster Bomb**: Uses multiple payload sets (one per position); tests all
  permutations (Cartesian product).

Includes response latency tracking, body size deviation, regex matchers,
and field extractors.
"""

from __future__ import annotations

import itertools
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path

from .engine import execute
from .models import (
    Request,
    SessionState,
    SniperItem,
    SniperMode,
    SniperReport,
)

DEFAULT_MARKER = "§"


@dataclass
class Position:
    loc_type: str  # "url", "header", "cookie", "param", "body_form", "body_raw"
    loc_key: str | None  # header/cookie/param name if applicable
    original_value: str
    marked_template: str


def find_positions(req: Request, marker: str = DEFAULT_MARKER) -> list[Position]:
    """Identify all marked insertion points across a Request."""
    positions: list[Position] = []

    def _has_markers(s: str) -> bool:
        return s.count(marker) >= 2

    # 1. URL
    if _has_markers(req.url):
        positions.append(
            Position(
                loc_type="url",
                loc_key=None,
                original_value=req.url.replace(marker, ""),
                marked_template=req.url,
            )
        )

    # 2. Query Parameters
    for idx, p in enumerate(req.params):
        if _has_markers(p.value):
            positions.append(
                Position(
                    loc_type="param",
                    loc_key=str(idx),
                    original_value=p.value.replace(marker, ""),
                    marked_template=p.value,
                )
            )

    # 3. Headers
    for idx, h in enumerate(req.headers):
        if _has_markers(h.value):
            positions.append(
                Position(
                    loc_type="header",
                    loc_key=str(idx),
                    original_value=h.value.replace(marker, ""),
                    marked_template=h.value,
                )
            )

    # 4. Form Body
    for idx, p in enumerate(req.body_form):
        if _has_markers(p.value):
            positions.append(
                Position(
                    loc_type="body_form",
                    loc_key=str(idx),
                    original_value=p.value.replace(marker, ""),
                    marked_template=p.value,
                )
            )

    # 5. Raw Body / JSON
    if req.body_raw and _has_markers(req.body_raw):
        positions.append(
            Position(
                loc_type="body_raw",
                loc_key=None,
                original_value=req.body_raw.replace(marker, ""),
                marked_template=req.body_raw,
            )
        )

    return positions


def _substitute_marker(template: str, payload: str, marker: str = DEFAULT_MARKER) -> str:
    """Replace content inside first §...§ with payload."""
    parts = template.split(marker)
    if len(parts) < 3:
        return template
    # Replace odd-indexed parts (inside markers) or first marker pair
    out = []
    i = 0
    while i < len(parts):
        if i == 1:
            out.append(payload)
        elif i % 2 == 1 and i > 1:
            out.append(parts[i])  # keep original for remaining pairs
        else:
            out.append(parts[i])
        i += 1
    return "".join(out)


def _clean_markers(s: str, marker: str = DEFAULT_MARKER) -> str:
    return s.replace(marker, "")


def apply_payloads(
    base: Request,
    positions: list[Position],
    payload_map: dict[int, str],
    marker: str = DEFAULT_MARKER,
) -> Request:
    """Create a mutated Request applying payloads to selected positions."""
    req = base.model_copy(deep=True)

    for idx, pos in enumerate(positions):
        payload = payload_map.get(idx)
        val = (
            _substitute_marker(pos.marked_template, payload, marker)
            if payload is not None
            else _clean_markers(pos.marked_template, marker)
        )

        if pos.loc_type == "url":
            req.url = val
        elif pos.loc_type == "param" and pos.loc_key:
            req.params[int(pos.loc_key)].value = val
        elif pos.loc_type == "header" and pos.loc_key:
            req.headers[int(pos.loc_key)].value = val
        elif pos.loc_type == "body_form" and pos.loc_key:
            req.body_form[int(pos.loc_key)].value = val
        elif pos.loc_type == "body_raw":
            req.body_raw = val

    # Clean any remaining markers across clean request fields
    req.url = _clean_markers(req.url, marker)
    for p in req.params:
        p.value = _clean_markers(p.value, marker)
    for h in req.headers:
        h.value = _clean_markers(h.value, marker)
    for p in req.body_form:
        p.value = _clean_markers(p.value, marker)
    if req.body_raw:
        req.body_raw = _clean_markers(req.body_raw, marker)

    return req


def build_attack_matrix(
    mode: str | SniperMode,
    positions_count: int,
    payload_lists: list[list[str]],
) -> list[dict[int, str]]:
    """Build the list of payload assignments across positions based on attack mode."""
    if positions_count <= 0 or not payload_lists or not payload_lists[0]:
        return []

    mode_str = str(mode).lower().replace("snipermode.", "")
    assignments: list[dict[int, str]] = []

    if mode_str == "sniper":
        payloads = payload_lists[0]
        for pos_idx in range(positions_count):
            for p in payloads:
                assignments.append({pos_idx: p})

    elif mode_str == "battering_ram":
        payloads = payload_lists[0]
        for p in payloads:
            assignments.append({pos_idx: p for pos_idx in range(positions_count)})

    elif mode_str == "pitchfork":
        # Pad payload lists to match number of positions
        padded_lists = [
            payload_lists[i] if i < len(payload_lists) else payload_lists[-1]
            for i in range(positions_count)
        ]
        for combo in zip(*padded_lists):
            assignments.append({pos_idx: p for pos_idx, p in enumerate(combo)})

    elif mode_str == "cluster_bomb":
        padded_lists = [
            payload_lists[i] if i < len(payload_lists) else payload_lists[-1]
            for i in range(positions_count)
        ]
        for combo in itertools.product(*padded_lists):
            assignments.append({pos_idx: p for pos_idx, p in enumerate(combo)})

    return assignments


def parse_payload_source(source: str) -> list[str]:
    """Parse payload list from file path, comma-separated string, or numbers range."""
    p = Path(source)
    if p.exists() and p.is_file():
        return [ln.rstrip("\r\n") for ln in p.read_text().splitlines() if ln]
    if "," in source:
        return [s.strip() for s in source.split(",") if s.strip()]
    if "-" in source and any(c.isdigit() for c in source):
        # Range e.g. 1-100 or 1-100:2
        step = 1
        range_part = source
        if ":" in source:
            range_part, step_str = source.split(":", 1)
            step = int(step_str) if step_str.isdigit() else 1
        parts = range_part.split("-", 1)
        if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
            start, end = int(parts[0]), int(parts[1])
            pad = max(len(parts[0]), len(parts[1])) if parts[0].startswith("0") else 0
            return [f"{n:0{pad}d}" if pad else str(n) for n in range(start, end + 1, step)]
    return [source]


def execute_sniper(
    base_request: Request,
    session: SessionState | None = None,
    mode: str | SniperMode = "sniper",
    payload_lists: list[list[str]] | None = None,
    concurrency: int = 10,
    match_status: list[int] | None = None,
    match_regex: str | None = None,
    extract_regex: str | None = None,
    marker: str = DEFAULT_MARKER,
    delay_ms: int = 0,
) -> SniperReport:
    """Execute the multi-position attack matrix against target and aggregate responses."""
    if session is None:
        session = SessionState()

    positions = find_positions(base_request, marker=marker)
    if not positions:
        # If no explicit markers found, test full request as baseline
        positions = [
            Position(
                loc_type="url",
                loc_key=None,
                original_value=base_request.url,
                marked_template=base_request.url,
            )
        ]

    if not payload_lists:
        payload_lists = [["test"]]

    assignments = build_attack_matrix(mode, len(positions), payload_lists)

    # 1. Baseline Request
    baseline_req = apply_payloads(base_request, positions, {}, marker=marker)
    baseline_status = None
    baseline_len = 0
    try:
        _, b_resp, _ = execute(baseline_req, session)
        baseline_status = b_resp.status_code
        baseline_len = b_resp.body_len
    except Exception:  # noqa: BLE001, S110
        pass

    matcher_re = re.compile(match_regex) if match_regex else None
    extractor_re = re.compile(extract_regex) if extract_regex else None

    report = SniperReport(
        target=base_request.url.replace(marker, ""),
        mode=str(mode).lower().replace("snipermode.", ""),
        total_positions=len(positions),
        total_requests=len(assignments),
        baseline_status=baseline_status,
        baseline_len=baseline_len,
    )

    def _worker(item: tuple[int, dict[int, str]]) -> SniperItem:
        idx, payload_map = item
        if delay_ms > 0:
            time.sleep(delay_ms / 1000.0)

        m_req = apply_payloads(base_request, positions, payload_map, marker=marker)
        p_named = {f"pos_{p_idx}": val for p_idx, val in payload_map.items()}

        start_t = time.perf_counter()
        try:
            _, resp, _ = execute(m_req, session)
            elapsed = int((time.perf_counter() - start_t) * 1000)

            matches = []
            if match_status and resp.status_code in match_status:
                matches.append(f"status_{resp.status_code}")
            if matcher_re and matcher_re.search(resp.body):
                matches.append("regex_match")

            extracted = {}
            if extractor_re:
                em = extractor_re.search(resp.body)
                if em:
                    extracted["match"] = em.group(0)[:60]

            is_anomaly = False
            if baseline_status is not None and resp.status_code != baseline_status or baseline_len > 0 and abs(resp.body_len - baseline_len) > (baseline_len * 0.3):
                is_anomaly = True

            return SniperItem(
                index=idx + 1,
                payloads=p_named,
                status_code=resp.status_code,
                body_len=resp.body_len,
                elapsed_ms=elapsed,
                matches=matches,
                extracted=extracted,
                anomaly=is_anomaly,
            )
        except Exception as exc:  # noqa: BLE001
            elapsed = int((time.perf_counter() - start_t) * 1000)
            return SniperItem(
                index=idx + 1,
                payloads=p_named,
                elapsed_ms=elapsed,
                error=str(exc),
                anomaly=True,
            )

    results: list[SniperItem] = []
    with ThreadPoolExecutor(max_workers=max(1, min(concurrency, 32))) as pool:
        futures = [pool.submit(_worker, (i, assign)) for i, assign in enumerate(assignments)]
        for fut in as_completed(futures):
            results.append(fut.result())

    results.sort(key=lambda r: r.index)
    report.results = results
    return report
