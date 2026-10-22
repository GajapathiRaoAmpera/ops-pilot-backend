import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import audit
from app.config import Settings, get_settings
from app.db import get_db
from app.deps import WorkspaceAccess, csrf_origin_check, workspace_access
from app.integrations.github import GitHubError, GitHubFactory, RunData
from app.models import ActionRequest, AuditEvent, PipelineRun, Repository, User
from app.rbac import P
from app.repos import client_for, workspace_repos

router = APIRouter(prefix="/workspaces/{ws_id}", tags=["pipelines"])


def get_github_factory(settings: Settings = Depends(get_settings)) -> GitHubFactory:
    return GitHubFactory(settings)


def _dto(r: PipelineRun) -> dict:
    return {
        "id": str(r.id), "externalId": r.external_id, "repo": r.repo, "workflow": r.workflow,
        "branch": r.branch, "commit": r.commit_sha[:7], "status": r.status,
        "conclusion": r.conclusion, "url": r.html_url,
        "startedAt": r.started_at.isoformat() if r.started_at else None,
        "fetchedAt": r.fetched_at.isoformat(),
    }


def upsert_run(db: Session, repo: Repository, d: RunData) -> PipelineRun:
    row = db.scalar(select(PipelineRun).where(
        PipelineRun.workspace_id == repo.workspace_id, PipelineRun.provider == "github",
        PipelineRun.external_id == d.external_id))
    if row is None:
        row = PipelineRun(org_id=repo.org_id, workspace_id=repo.workspace_id, provider="github",
                          external_id=d.external_id, repo=repo.full_name, workflow="", status="")
        db.add(row)
    row.workflow, row.branch, row.commit_sha = d.workflow, d.branch, d.commit_sha
    row.status, row.conclusion, row.html_url, row.started_at = d.status, d.conclusion, d.html_url, d.started_at
    row.fetched_at = datetime.now(UTC)
    return row


@router.get("/pipelines/runs")
def list_runs(limit: int = 50, repo: str | None = None,
              acc: WorkspaceAccess = Depends(workspace_access(P["pipelines_read"])), db: Session = Depends(get_db)):
    q = select(PipelineRun).where(PipelineRun.workspace_id == acc.workspace.id)
    if repo:
        q = q.where(PipelineRun.repo == repo)
    rows = db.scalars(q.order_by(PipelineRun.started_at.desc()).limit(min(max(limit, 1), 100)))
    repos = workspace_repos(db, acc.workspace.id)
    synced = [r.last_synced_at for r in repos if r.last_synced_at]
    return {"connected": bool(repos), "repositories": [r.full_name for r in repos],
            "lastSyncedAt": max(synced).isoformat() if synced else None,
            "runs": [_dto(r) for r in rows]}


def _aware(dt: datetime | None) -> datetime | None:
    return dt if dt is None or dt.tzinfo else dt.replace(tzinfo=UTC)


@router.post("/pipelines/sync", dependencies=[Depends(csrf_origin_check)])
def sync(acc: WorkspaceAccess = Depends(workspace_access(P["pipelines_execute"])),
         db: Session = Depends(get_db), factory: GitHubFactory = Depends(get_github_factory),
         settings: Settings = Depends(get_settings)):
    """Syncs every tracked repository. One failing repository does not stop the others."""
    repos = workspace_repos(db, acc.workspace.id)
    if not repos:
        raise HTTPException(409, "integration_not_connected")
    synced = [r for r in (_aware(x.last_synced_at) for x in repos) if r]
    if synced and (datetime.now(UTC) - max(synced)).total_seconds() < settings.sync_min_interval_seconds:
        raise HTTPException(429, "sync_too_frequent")
    total, failed = 0, []
    for r in repos:
        gh = client_for(factory, db, acc.workspace.id, r.full_name)
        if not gh.configured:
            failed.append({"repo": r.full_name, "reason": "github_not_configured"})
            continue
        try:
            runs = gh.list_runs(r.full_name)
        except GitHubError as exc:
            failed.append({"repo": r.full_name, "reason": "upstream_error"})
            audit.record(db, "pipelines.sync", actor_id=acc.principal.user.id, org_id=acc.workspace.org_id,
                         workspace_id=acc.workspace.id, resource=f"repo:{r.full_name}", outcome="failure", detail=str(exc))
            continue
        for d in runs:
            upsert_run(db, r, d)
        r.last_synced_at = datetime.now(UTC)
        total += len(runs)
    db.commit()
    if len(failed) == len(repos):
        reason = failed[0]["reason"]
        raise HTTPException(503 if reason == "github_not_configured" else 502, reason)
    audit.record(db, "pipelines.sync", actor_id=acc.principal.user.id, org_id=acc.workspace.org_id,
                 workspace_id=acc.workspace.id, detail=f"{total} runs from {len(repos) - len(failed)} of {len(repos)} repositories")
    return {"synced": total, "repositories": len(repos), "failed": failed}


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
             db: Session = Depends(get_db), factory: GitHubFactory = Depends(get_github_factory)):
    row = _run(db, acc, run_id)
    gh = client_for(factory, db, acc.workspace.id, row.repo)
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
    """Everything here is real. Sections the caller may not see are omitted and flagged in `visible`."""
    ws_id = acc.workspace.id
    can = acc.permissions
    repos = workspace_repos(db, ws_id)
    synced = [r.last_synced_at for r in repos if r.last_synced_at]
    runs = list(db.scalars(select(PipelineRun).where(PipelineRun.workspace_id == ws_id)
                           .order_by(PipelineRun.started_at.desc()).limit(100)))
    pending = db.scalar(select(func.count()).select_from(ActionRequest).where(
        ActionRequest.workspace_id == ws_id, ActionRequest.status == "pending")) or 0
    last = db.scalar(select(ActionRequest).where(
        ActionRequest.workspace_id == ws_id, ActionRequest.status.in_(["succeeded", "failed"]))
        .order_by(ActionRequest.created_at.desc()).limit(1))
    counts: dict[str, int] = {}
    for r in runs:
        k = r.conclusion or r.status
        counts[k] = counts.get(k, 0) + 1

    visible = {"approvals": P["approvals_read"] in can, "executions": P["automation_read"] in can,
               "activity": P["audit_read"] in can}
    pending_items, executions, activity = [], [], []
    if visible["approvals"]:
        for r in db.scalars(select(ActionRequest).where(ActionRequest.workspace_id == ws_id, ActionRequest.status == "pending")
                            .order_by(ActionRequest.created_at.desc()).limit(5)):
            run = db.get(PipelineRun, r.run_id)
            who = db.get(User, r.requested_by)
            pending_items.append({"id": str(r.id), "risk": r.risk, "createdAt": r.created_at.isoformat(),
                                  "requester": who.name if who else None,
                                  "workflow": run.workflow if run else "", "repo": run.repo if run else "",
                                  "branch": run.branch if run else ""})
    if visible["executions"]:
        for r in db.scalars(select(ActionRequest).where(ActionRequest.workspace_id == ws_id,
                                                         ActionRequest.status.in_(["succeeded", "failed", "executing"]))
                            .order_by(ActionRequest.created_at.desc()).limit(5)):
            run = db.get(PipelineRun, r.run_id)
            executions.append({"id": str(r.id), "status": r.status, "type": r.type,
                               "workflow": run.workflow if run else "", "repo": run.repo if run else "",
                               "createdAt": r.created_at.isoformat()})
    if visible["activity"]:
        for e, name in db.execute(select(AuditEvent, User.name).outerjoin(User, User.id == AuditEvent.actor_id)
                                  .where(AuditEvent.workspace_id == ws_id).order_by(AuditEvent.id.desc()).limit(10)):
            activity.append({"id": e.id, "ts": e.ts.isoformat(), "actor": name, "action": e.action,
                             "resource": e.resource, "outcome": e.outcome})
    return {
        "workspace": {"id": str(ws_id), "name": acc.workspace.name},
        "pipelines": {"connected": bool(repos), "repositories": len(repos), "counts": counts, "total": len(runs),
                      "lastSyncedAt": max(synced).isoformat() if synced else None,
                      "recent": [_dto(r) for r in runs[:10]]},
        "approvals": {"pending": pending, "items": pending_items},
        "lastExecution": None if last is None else {"status": last.status, "type": last.type},
        "recentExecutions": executions,
        "activity": activity,
        "visible": visible,
        # Not implemented: stated so the UI never invents numbers for them.
        "notConnected": ["incidents", "alerts", "metrics"],
    }
