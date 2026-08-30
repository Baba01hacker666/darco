"""Workspace resolution and shared session helpers."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path


from ..errors import DarcoError
from ..models import SessionState
from ..workspace import Workspace, default_workspace_name



# ------------------------------------------------------------------ workspace resolution
def _find_workspace(
    ctx, require: bool = True, auto_create_target: str | None = None
) -> Workspace | None:
    ws_path = (ctx.obj or {}).get("workspace_path")
    if ws_path:
        return Workspace.open(Path(ws_path))
    candidates = [
        p for p in Path.cwd().iterdir() if p.is_dir() and p.name.endswith(".darco")
    ]
    if len(candidates) == 1:
        return Workspace.open(candidates[0])
    if len(candidates) > 1:
        if auto_create_target:
            def_name = default_workspace_name(auto_create_target)
            match = [p for p in candidates if p.name == def_name]
            if match:
                return Workspace.open(match[0])
        raise DarcoError(
            f"multiple workspaces found ({', '.join(p.name for p in candidates)}); pass --workspace"
        )

    # Search parent directories (up to 3 levels)
    try:
        curr = Path.cwd().parent
        for _ in range(3):
            if curr == curr.parent:
                break
            p_candidates = [
                p for p in curr.iterdir() if p.is_dir() and p.name.endswith(".darco")
            ]
            if len(p_candidates) == 1:
                return Workspace.open(p_candidates[0])
            curr = curr.parent
    except OSError:
        pass

    cfg = (ctx.obj or {}).get("config")
    target = auto_create_target or (cfg.target if cfg else None)
    if target:
        ws_name = default_workspace_name(target)
        ws_dir = Path.cwd() / ws_name
        if ws_dir.exists() and (ws_dir / "workspace.json").exists():
            return Workspace.open(ws_dir)
        return Workspace.create(target, ws_dir)

    if require:
        raise DarcoError(
            "no workspace found; use 'darco -u <url>' for one-shot mode or 'darco init <target>' to create a workspace"
        )
    return None


def _one_shot_session() -> SessionState:
    """A throwaway session for one-shot (-u) commands: nothing persisted."""
    return SessionState(updated_at=datetime.now(UTC).isoformat())
