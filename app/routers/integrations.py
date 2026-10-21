"""Per-workspace GitHub connection. The token is write-only: stored encrypted, never returned."""
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit
from app.config import Settings, get_settings
from app.crypto import SecretKeyMissing, encrypt
from app.db import get_db
from app.deps import WorkspaceAccess, csrf_origin_check, workspace_access
from app.integrations.github import GitHubError, GitHubFactory, valid_repo
from app.models import Integration
from app.rbac import P

router = APIRouter(prefix="/workspaces/{ws_id}/integrations/github", tags=["integrations"])
MANAGE = workspace_access(P["integrations_manage"])


class ConnectBody(BaseModel):
    repo: str = Field(min_length=3, max_length=200)
    token: str | None = Field(default=None, max_length=512)


def get_factory(settings: Settings = Depends(get_settings)) -> GitHubFactory:
    return GitHubFactory(settings)


def _row(db: Session, acc: WorkspaceAccess) -> Integration | None:
    return db.scalar(select(Integration).where(Integration.workspace_id == acc.workspace.id,
                                               Integration.provider == "github"))


def _status(row: Integration | None) -> dict:
    return {"connected": row is not None, "repo": (row.config or {}).get("repo") if row else None,
            "tokenSet": bool(row and row.secret_ciphertext),
            "lastSyncedAt": row.last_synced_at.isoformat() if row and row.last_synced_at else None}


def _ctx(acc: WorkspaceAccess) -> dict:
    return {"actor_id": acc.principal.user.id, "org_id": acc.workspace.org_id, "workspace_id": acc.workspace.id}


@router.get("")
def get_status(acc: WorkspaceAccess = Depends(MANAGE), db: Session = Depends(get_db)):
    return _status(_row(db, acc))


@router.put("", dependencies=[Depends(csrf_origin_check)])
def connect(body: ConnectBody, acc: WorkspaceAccess = Depends(MANAGE), db: Session = Depends(get_db),
            settings: Settings = Depends(get_settings)):
    repo = body.repo.strip()
    if not valid_repo(repo):
        raise HTTPException(422, "invalid_repo")
    token = (body.token or "").strip()
    row = _row(db, acc)
    if token and not 20 <= len(token) <= 512:
        raise HTTPException(422, "invalid_token")
    if row is None:
        row = Integration(org_id=acc.workspace.org_id, workspace_id=acc.workspace.id, provider="github", config={})
        db.add(row)
    if token:
        try:
            row.secret_ciphertext = encrypt(settings, token)
        except SecretKeyMissing as exc:
            db.rollback()
            raise HTTPException(503, "encryption_not_configured") from exc
    if (row.config or {}).get("repo") != repo:
        row.last_synced_at = None
    row.config = {"repo": repo}
    row.updated_by, row.updated_at = acc.principal.user.id, datetime.now(UTC)
    db.commit()
    audit.record(db, "integration.github.connected", resource=f"repo:{repo}",
                 detail="token updated" if token else "repo updated", **_ctx(acc))
    return _status(row)


@router.delete("", dependencies=[Depends(csrf_origin_check)])
def disconnect(acc: WorkspaceAccess = Depends(MANAGE), db: Session = Depends(get_db)):
    row = _row(db, acc)
    if row is None:
        raise HTTPException(404, "not_found")
    repo = (row.config or {}).get("repo", "")
    db.delete(row)
    db.commit()
    audit.record(db, "integration.github.disconnected", resource=f"repo:{repo}", **_ctx(acc))
    return {"connected": False}


@router.post("/test", dependencies=[Depends(csrf_origin_check)])
def test_connection(acc: WorkspaceAccess = Depends(MANAGE), db: Session = Depends(get_db),
                    factory: GitHubFactory = Depends(get_factory)):
    row = _row(db, acc)
    if row is None:
        raise HTTPException(409, "integration_not_connected")
    gh = factory.for_integration(row)
    if not gh.configured:
        return {"ok": False, "reason": "no_token"}
    try:
        gh.list_runs((row.config or {})["repo"], limit=1)
    except GitHubError as exc:
        reason = {"github_401": "unauthorized", "github_403": "forbidden", "github_404": "repo_not_found_or_no_access"
                  }.get(str(exc), "error")  # only a coarse class; GitHub's message is never relayed
        audit.record(db, "integration.github.test", outcome="failure", detail=reason, **_ctx(acc))
        return {"ok": False, "reason": reason}
    audit.record(db, "integration.github.test", **_ctx(acc))
    return {"ok": True}
