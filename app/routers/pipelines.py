import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit
from app.config import Settings, get_settings
from app.db import get_db
from app.deps import WorkspaceAccess, csrf_origin_check, workspace_access
from app.integrations.github import GitHubClient, GitHubError, RunData
from app.models import Integration, PipelineRun
from app.rbac import P

router = APIRouter(prefix="/workspaces/{ws_id}", tags=["pipelines"])


def get_github(settings: Settings = Depends(get_settings)) -> GitHubClient:
    return GitHubClient(settings)


def _dto(r: PipelineRun) -> dict:
    return {
        "id": str(r.id), "externalId": r.external_id, "repo": r.repo, "workflow": r.workflow,
        "branch": r.branch, "commit": r.commit_sha[:7], "status": r.status,
        "conclusion": r.conclusion, "url": r.html_url,
        "startedAt": r.started_at.isoformat() if r.started_at else None,
        "fetchedAt": r.fetched_at.isoformat(),
    }


def _integration(db: Session, ws_id: uuid.UUID) -> Integration | None:
    return db.scalar(select(Integration).where(Integration.workspace_id == ws_id,
                                               Integration.provider == "github"))


def upsert_run(db: Session, integ: Integration, d: RunData) -> PipelineRun:
    row = db.scalar(select(PipelineRun).where(
        PipelineRun.workspace_id == integ.workspace_id, PipelineRun.provider == "github",
        PipelineRun.external_id == d.external_id))
    if row is None:
        row = PipelineRun(org_id=integ.org_id, workspace_id=integ.workspace_id, provider="github",
                          external_id=d.external_id, repo=integ.config["repo"], workflow="", status="")
        db.add(row)
    row.workflow, row.branch, row.commit_sha = d.workflow, d.branch, d.commit_sha
    row.status, row.conclusion, row.html_url, row.started_at = d.status, d.conclusion, d.html_url, d.started_at
    row.fetched_at = datetime.now(UTC)
    return row


@router.get("/pipelines/runs")
def list_runs(limit: int = 50, acc: WorkspaceAccess = Depends(workspace_access(P["pipelines_read"])),
              db: Session = Depends(get_db)):
    rows = db.scalars(select(PipelineRun).where(PipelineRun.workspace_id == acc.workspace.id)
                      .order_by(PipelineRun.started_at.desc()).limit(min(max(limit, 1), 100)))
    integ = _integration(db, acc.workspace.id)
    return {"connected": integ is not None,
            "lastSyncedAt": integ.last_synced_at.isoformat() if integ and integ.last_synced_at else None,
            "runs": [_dto(r) for r in rows]}


@router.post("/pipelines/sync", dependencies=[Depends(csrf_origin_check)])
def sync(acc: WorkspaceAccess = Depends(workspace_access(P["pipelines_execute"])),
         db: Session = Depends(get_db), gh: GitHubClient = Depends(get_github),
         settings: Settings = Depends(get_settings)):
    integ = _integration(db, acc.workspace.id)
    if integ is None:
        raise HTTPException(409, "integration_not_connected")
    if not gh.configured:
        raise HTTPException(503, "github_not_configured")
    last = integ.last_synced_at
    if last is not None:
        last = last if last.tzinfo else last.replace(tzinfo=UTC)
        if (datetime.now(UTC) - last).total_seconds() < settings.sync_min_interval_seconds:
            raise HTTPException(429, "sync_too_frequent")
    try:
        runs = gh.list_runs(integ.config["repo"])
    except GitHubError as exc:
        audit.record(db, "pipelines.sync", actor_id=acc.principal.user.id, org_id=acc.workspace.org_id,
                     workspace_id=acc.workspace.id, outcome="failure", detail=str(exc))
        raise HTTPException(502, "upstream_error") from exc
    for d in runs:
        upsert_run(db, integ, d)
    integ.last_synced_at = datetime.now(UTC)
    db.commit()
    audit.record(db, "pipelines.sync", actor_id=acc.principal.user.id, org_id=acc.workspace.org_id,
                 workspace_id=acc.workspace.id, detail=f"{len(runs)} runs")
    return {"synced": len(runs)}


def _run(db: Session, acc: WorkspaceAccess, run_id: uuid.UUID) -> PipelineRun:
    row = db.get(PipelineRun, run_id)
    if row is None or row.workspace_id != acc.workspace.id:
        raise HTTPException(404, "not_found")
    return row


@router.get("/pipelines/runs/{run_id}")
def get_run(run_id: uuid.UUID, acc: WorkspaceAccess = Depends(workspace_access(P["pipelines_read"])),
            db: Session = Depends(get_db)):
    return _dto(_run(db, acc, run_id))


@router.get("/pipelines/runs/{run_id}/logs")
def get_logs(run_id: uuid.UUID, acc: WorkspaceAccess = Depends(workspace_access(P["pipelines_read"])),
             db: Session = Depends(get_db), gh: GitHubClient = Depends(get_github)):
    row = _run(db, acc, run_id)
    if not gh.configured:
        raise HTTPException(503, "github_not_configured")
    try:
        text = gh.get_logs(row.repo, row.external_id)
    except GitHubError as exc:
        raise HTTPException(502, "upstream_error") from exc
    audit.record(db, "pipelines.logs.read", actor_id=acc.principal.user.id, org_id=acc.workspace.org_id,
                 workspace_id=acc.workspace.id, resource=f"run:{row.id}")
    # Untrusted content: clients must render as plain text.
    return {"runId": str(row.id), "untrusted": True, "log": text}


@router.get("/overview")
def overview(acc: WorkspaceAccess = Depends(workspace_access(P["overview_read"])),
             db: Session = Depends(get_db)):
    integ = _integration(db, acc.workspace.id)
    runs = list(db.scalars(select(PipelineRun).where(PipelineRun.workspace_id == acc.workspace.id)
                           .order_by(PipelineRun.started_at.desc()).limit(100)))
    counts: dict[str, int] = {}
    for r in runs:
        k = r.conclusion or r.status
        counts[k] = counts.get(k, 0) + 1
    return {
        "workspace": {"id": str(acc.workspace.id), "name": acc.workspace.name},
        "pipelines": {"connected": integ is not None, "counts": counts, "total": len(runs),
                      "lastSyncedAt": integ.last_synced_at.isoformat() if integ and integ.last_synced_at else None,
                      "recent": [_dto(r) for r in runs[:10]]},
        # Not implemented yet: explicitly flagged so the UI never shows invented data.
        "notConnected": ["incidents", "alerts", "metrics", "approvals", "automation"],
    }
