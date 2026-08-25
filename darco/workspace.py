from __future__ import annotations

import json
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path

from .errors import DarcoError
from .models import (
    Cookie,
    Finding,
    HistoryRecord,
    NameValue,
    Request,
    Response,
    SessionState,
    SiteMap,
    WorkspaceConfig,
    to_json,
)

BODY_PREVIEW_CAP = 1_000_000  # inline body preview cap stored in history.jsonl


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def default_workspace_name(target: str) -> str:
    host = re.sub(r"^[a-z]+://", "", target, flags=re.IGNORECASE).split("/")[0].split(":")[0]
    host = re.sub(r"[^A-Za-z0-9._-]", "_", host) or "target"
    return f"{host}.darco"


class Workspace:
    """Per-target workspace: config, session state, history, findings, site map."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.config_file = self.path / "workspace.json"
        self.session_file = self.path / "session.json"
        self.history_file = self.path / "history.jsonl"
        self.findings_file = self.path / "findings.json"
        self.sitemap_file = self.path / "sitemap.json"
        self.bodies_dir = self.path / "bodies"
        self._count = 0

    # ------------------------------------------------------------------ create/open
    @classmethod
    def create(
        cls,
        target: str,
        path: Path | None = None,
        *,
        base_headers: list[NameValue] | None = None,
        follow_redirects: bool = True,
        timeout: float = 10.0,
        insecure: bool = False,
    ) -> "Workspace":
        path = Path(path) if path else Path(default_workspace_name(target))
        if path.exists():
            if (path / "workspace.json").exists():
                raise DarcoError(f"workspace already exists: {path}")
            if any(path.iterdir()):
                raise DarcoError(f"directory already exists and is not empty: {path}")
        path.mkdir(parents=True, exist_ok=True)
        ws = cls(path)
        cfg = WorkspaceConfig(
            target=target,
            created_at=_now_iso(),
            base_headers=base_headers or [],
            follow_redirects=follow_redirects,
            timeout=timeout,
            insecure=insecure,
        )
        ws.save_config(cfg)
        ws.save_session(SessionState(updated_at=_now_iso()))
        ws.history_file.touch()
        ws.findings_file.write_text(json.dumps([]))
        ws.sitemap_file.write_text(json.dumps({}))
        ws.bodies_dir.mkdir(exist_ok=True)
        return ws

    @classmethod
    def open(cls, path: Path) -> "Workspace":
        path = Path(path)
        if not (path / "workspace.json").exists():
            raise DarcoError(f"not a darco workspace: {path}")
        ws = cls(path)
        max_id = 0
        if ws.history_file.exists():
            with ws.history_file.open() as fh:
                for line in fh:
                    if line.strip():
                        try:
                            rec_id = json.loads(line).get("id", "")
                            if str(rec_id).isdigit():
                                max_id = max(max_id, int(rec_id))
                            else:
                                max_id += 1
                        except Exception:
                            max_id += 1
        ws._count = max_id
        return ws

    # ------------------------------------------------------------------ config/session
    def load_config(self) -> WorkspaceConfig:
        try:
            return WorkspaceConfig.model_validate_json(self.config_file.read_text())
        except Exception as exc:  # noqa: BLE001
            raise DarcoError(f"corrupt workspace.json: {exc}") from exc

    def save_config(self, cfg: WorkspaceConfig) -> None:
        self.config_file.write_text(json.dumps(to_json(cfg), indent=2))

    def load_session(self) -> SessionState:
        try:
            return SessionState.model_validate_json(self.session_file.read_text())
        except Exception:  # noqa: BLE001
            return SessionState()

    def save_session(self, session: SessionState) -> None:
        session.updated_at = _now_iso()
        self.session_file.write_text(json.dumps(to_json(session), indent=2))

    # ------------------------------------------------------------------ history
    def next_id(self) -> str:
        self._count += 1
        return f"{self._count:04d}"

    def add_history(self, record: HistoryRecord) -> None:
        rec = to_json(record)
        resp = rec.get("response")
        if resp and resp.get("body"):
            body: str = resp["body"]
            raw = body.encode("utf-8")
            if len(raw) > BODY_PREVIEW_CAP:
                body_file = f"bodies/{record.id}.body"
                (self.bodies_dir / f"{record.id}.body").write_bytes(raw)
                resp["body_file"] = body_file
                resp["body"] = (
                    body[:BODY_PREVIEW_CAP]
                    + f"\n...[truncated {len(raw) - BODY_PREVIEW_CAP} bytes; full body in {body_file}]"
                )
        with self.history_file.open("a") as fh:
            fh.write(json.dumps(rec) + "\n")
        try:
            self._count = max(self._count, int(record.id))
        except (ValueError, TypeError):
            pass

    def get_record(self, record_id: str) -> HistoryRecord:
        with self.history_file.open() as fh:
            for line in fh:
                if not line.strip():
                    continue
                data = json.loads(line)
                if data.get("id") == record_id:
                    return HistoryRecord.model_validate(data)
        raise DarcoError(f"no history record with id {record_id!r}")

    def iter_records(self):
        with self.history_file.open() as fh:
            for line in fh:
                if line.strip():
                    yield HistoryRecord.model_validate(json.loads(line))

    def list_records(self) -> list[HistoryRecord]:
        return list(self.iter_records())

    # ------------------------------------------------------------------ findings / sitemap
    def load_findings(self) -> list[Finding]:
        try:
            return [Finding.model_validate(f) for f in json.loads(self.findings_file.read_text())]
        except Exception:  # noqa: BLE001
            return []

    def save_findings(self, findings: list[Finding]) -> None:
        self.findings_file.write_text(
            json.dumps([to_json(f) for f in findings], indent=2)
        )

    def add_findings(self, findings: list[Finding]) -> int:
        existing = self.load_findings()
        seen = {(f.type, f.location, f.evidence) for f in existing}
        added = 0
        for f in findings:
            key = (f.type, f.location, f.evidence)
            if key not in seen:
                existing.append(f)
                seen.add(key)
                added += 1
        self.save_findings(existing)
        return added

    def save_sitemap(self, sitemap: SiteMap) -> None:
        self.sitemap_file.write_text(json.dumps(to_json(sitemap), indent=2))

    # ------------------------------------------------------------------ status
    def status(self) -> dict:
        cfg = self.load_config()
        session = self.load_session()
        findings = self.load_findings()
        return {
            "path": str(self.path),
            "target": cfg.target,
            "created_at": cfg.created_at,
            "history_count": self._count,
            "cookies": [{"name": c.name, "domain": c.domain} for c in session.cookies],
            "csrf_hosts": sorted(session.csrf_headers),
            "findings_count": len(findings),
            "sitemap": self.sitemap_file.exists() and self.sitemap_file.stat().st_size > 2,
        }


def merge_cookies(base: list[Cookie], incoming: list[Cookie], host: str) -> list[Cookie]:
    """Merge incoming cookies into base, replacing by (domain, name)."""
    merged = list(base)
    for cookie in incoming:
        domain = cookie.domain or host
        path = cookie.path or "/"
        merged = [
            c
            for c in merged
            if not (c.name == cookie.name and (c.domain or host) == domain)
        ]
        merged.append(Cookie(name=cookie.name, value=cookie.value, domain=domain, path=path))
    return merged
