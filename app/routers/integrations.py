"""Per-workspace GitHub connection: a shared token plus any number of repositories.

Tokens are write-only: stored encrypted, never returned. A repository may carry its own token; otherwise it uses the
workspace's shared one.
"""
import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app import audit
from app.config import Settings, get_settings
from app.crypto import SecretKeyMissing, encrypt
from app.db import get_db
from app.deps import WorkspaceAccess, csrf_origin_check, workspace_access
from app.integrations.github import GitHubError, GitHubFactory, valid_repo
from app.models import Integration, Repository
from app.rbac import P
from app.repos import MAX_REPOS_PER_WORKSPACE, client_for, find_repo, workspace_integration, workspace_repos

router = APIRouter(prefix="/workspaces/{ws_id}/integrations/github", tags=["integrations"])
MANAGE = workspace_access(P["integrations_manage"])


class ConnectBody(BaseModel):
    repo: str | None = Field(default=None, min_length=3, max_length=200)  # optional: add a repository in the same call
    token: str | None = Field(default=None, max_length=512)  # the workspace's shared token


class RepoBody(BaseModel):
    repo: str = Field(min_length=3, max_length=200)
    token: str | None = Field(default=None, max_length=512)  # this repository's own token (optional)


class RepoUpdateBody(BaseModel):
    token: str | None = Field(default=None, max_length=512)
    useSharedToken: bool = False  # drop the repository's own token


def get_factory(settings: Settings = Depends(get_settings)) -> GitHubFactory:
    return GitHubFactory(settings)


def _status(db: Session, acc: WorkspaceAccess) -> dict:
    integ = workspace_integration(db, acc.workspace.id)
    repos = workspace_repos(db, acc.workspace.id)
    synced = [r.last_synced_at for r in repos if r.last_synced_at]
    return {"connected": integ is not None or bool(repos), "tokenSet": bool(integ and integ.secret_ciphertext),
            "maxRepositories": MAX_REPOS_PER_WORKSPACE,
            "lastSyncedAt": max(synced).isoformat() if synced else None,
            "repositories": [{"id": str(r.id), "repo": r.full_name, "ownToken": bool(r.secret_ciphertext),
                              "lastSyncedAt": r.last_synced_at.isoformat() if r.last_synced_at else None} for r in repos]}


def _ctx(acc: WorkspaceAccess) -> dict:
    return {"actor_id": acc.principal.user.id, "org_id": acc.workspace.org_id, "workspace_id": acc.workspace.id}


def _token(settings: Settings, token: str | None, db: Session) -> str | None:
    """Validate and encrypt a submitted token. None when none was submitted."""
    token = (token or "").strip()
    if not token:
        return None
    if not 20 <= len(token) <= 512:
        raise HTTPException(422, "invalid_token")
    try:
        return encrypt(settings, token)
    except SecretKeyMissing as exc:
        db.rollback()
        raise HTTPException(503, "encryption_not_configured") from exc


def _ensure_integration(db: Session, acc: WorkspaceAccess) -> Integration:
    integ = workspace_integration(db, acc.workspace.id)
    if integ is None:
        integ = Integration(org_id=acc.workspace.org_id, workspace_id=acc.workspace.id, provider="github", config={})
        db.add(integ)
    return integ


def _add_repo(db: Session, acc: WorkspaceAccess, name: str, cipher: str | None) -> Repository:
    name = name.strip()
    if not valid_repo(name):
        raise HTTPException(422, "invalid_repo")
    row = find_repo(db, acc.workspace.id, name)
    if row is None:
        if len(workspace_repos(db, acc.workspace.id)) >= MAX_REPOS_PER_WORKSPACE:
            raise HTTPException(409, "too_many_repositories")
        row = Repository(org_id=acc.workspace.org_id, workspace_id=acc.workspace.id, provider="github",
                         full_name=name, created_by=acc.principal.user.id)
        db.add(row)
    if cipher:
        row.secret_ciphertext = cipher
    return row


@router.get("")
def get_status(acc: WorkspaceAccess = Depends(MANAGE), db: Session = Depends(get_db)):
    return _status(db, acc)


@router.put("", dependencies=[Depends(csrf_origin_check)])
def connect(body: ConnectBody, acc: WorkspaceAccess = Depends(MANAGE), db: Session = Depends(get_db),
            settings: Settings = Depends(get_settings)):
    """Sets the shared token and/or adds a repository."""
    if body.repo is not None and not valid_repo(body.repo.strip()):
        raise HTTPException(422, "invalid_repo")
    cipher = _token(settings, body.token, db)
    integ = _ensure_integration(db, acc)
    if cipher:
        integ.secret_ciphertext = cipher
    integ.updated_by, integ.updated_at = acc.principal.user.id, datetime.now(UTC)
    if body.repo:
        _add_repo(db, acc, body.repo, None)
    db.commit()
    audit.record(db, "integration.github.connected", resource=f"repo:{body.repo}" if body.repo else "workspace",
                 detail="token updated" if cipher else "repository added", **_ctx(acc))
    return _status(db, acc)


@router.post("/repositories", dependencies=[Depends(csrf_origin_check)])
def add_repository(body: RepoBody, acc: WorkspaceAccess = Depends(MANAGE), db: Session = Depends(get_db),
                   settings: Settings = Depends(get_settings)):
    cipher = _token(settings, body.token, db)
    _ensure_integration(db, acc)
    row = _add_repo(db, acc, body.repo, cipher)
    db.commit()
    audit.record(db, "integration.github.repository_added", resource=f"repo:{row.full_name}",
                 detail="own token" if cipher else "shared token", **_ctx(acc))
    return _status(db, acc)


def _repo_or_404(db: Session, acc: WorkspaceAccess, repo_id: uuid.UUID) -> Repository:
    row = db.get(Repository, repo_id)
    if row is None or row.workspace_id != acc.workspace.id:
        raise HTTPException(404, "not_found")
    return row


@router.put("/repositories/{repo_id}", dependencies=[Depends(csrf_origin_check)])
def update_repository(repo_id: uuid.UUID, body: RepoUpdateBody, acc: WorkspaceAccess = Depends(MANAGE),
                      db: Session = Depends(get_db), settings: Settings = Depends(get_settings)):
    row = _repo_or_404(db, acc, repo_id)
    cipher = _token(settings, body.token, db)
    if cipher:
        row.secret_ciphertext = cipher
    elif body.useSharedToken:
        row.secret_ciphertext = None
    db.commit()
    audit.record(db, "integration.github.repository_updated", resource=f"repo:{row.full_name}",
                 detail="own token" if cipher else ("shared token" if body.useSharedToken else "no change"), **_ctx(acc))
    return _status(db, acc)


@router.delete("/repositories/{repo_id}", dependencies=[Depends(csrf_origin_check)])
def remove_repository(repo_id: uuid.UUID, acc: WorkspaceAccess = Depends(MANAGE), db: Session = Depends(get_db)):
    """Stops tracking the repository. Runs already synced stay as history."""
    row = _repo_or_404(db, acc, repo_id)
    name = row.full_name
    db.delete(row)
    db.commit()
    audit.record(db, "integration.github.repository_removed", resource=f"repo:{name}", **_ctx(acc))
    return _status(db, acc)


@router.delete("", dependencies=[Depends(csrf_origin_check)])
def disconnect(acc: WorkspaceAccess = Depends(MANAGE), db: Session = Depends(get_db)):
    integ = workspace_integration(db, acc.workspace.id)
    repos = workspace_repos(db, acc.workspace.id)
    if integ is None and not repos:
        raise HTTPException(404, "not_found")
    for r in repos:
        db.delete(r)
    if integ is not None:
        db.delete(integ)
    db.commit()
    audit.record(db, "integration.github.disconnected", resource=f"{len(repos)} repositories", **_ctx(acc))
    return {"connected": False}


_REASONS = {"github_401": "unauthorized", "github_403": "forbidden", "github_404": "repo_not_found_or_no_access"}


@router.post("/test", dependencies=[Depends(csrf_origin_check)])
def test_connection(acc: WorkspaceAccess = Depends(MANAGE), db: Session = Depends(get_db),
                    factory: GitHubFactory = Depends(get_factory)):
    """Checks every repository with the token it would really use. Only a coarse reason is returned per repository."""
    repos = workspace_repos(db, acc.workspace.id)
    if not repos:
        raise HTTPException(409, "integration_not_connected")
    results = []
    for r in repos:
        gh = client_for(factory, db, acc.workspace.id, r.full_name)
        if not gh.configured:
            results.append({"repo": r.full_name, "ok": False, "reason": "no_token"})
            continue
        try:
            gh.list_runs(r.full_name, limit=1)
            results.append({"repo": r.full_name, "ok": True})
        except GitHubError as exc:  # GitHub's message is never relayed
            results.append({"repo": r.full_name, "ok": False, "reason": _REASONS.get(str(exc), "error")})
    failed = [x for x in results if not x["ok"]]
    audit.record(db, "integration.github.test", outcome="failure" if failed else "success",
                 detail=f"{len(failed)} of {len(results)} failed", **_ctx(acc))
    out: dict = {"ok": not failed, "results": results}
    if failed:
        out["reason"] = failed[0]["reason"]
    return out
