"""AI investigations of failed runs. Advisory only: suggestions go through the normal request -> approval flow."""
import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import audit
from app.ai.groq import AiError, GroqClient
from app.ai.investigate import analyse
from app.config import Settings, get_settings
from app.db import get_db
from app.deps import WorkspaceAccess, csrf_origin_check, workspace_access
from app.integrations.github import GitHubError, GitHubFactory
from app.models import Investigation, PipelineRun, User
from app.rbac import P
from app.repos import client_for
from app.routers.pipelines import get_github_factory

router = APIRouter(prefix="/workspaces/{ws_id}/investigations", tags=["ai"])
USE = workspace_access(P["copilot_use"])
FAILED = {"failure", "timed_out", "startup_failure"}


class InvestigateBody(BaseModel):
    runId: uuid.UUID


def get_ai(settings: Settings = Depends(get_settings)) -> GroqClient:
    return GroqClient(settings.groq_api_key, settings.groq_model)


def _dto(db: Session, i: Investigation) -> dict:
    who = db.get(User, i.created_by)
    return {"id": str(i.id), "runId": str(i.run_id), "summary": i.summary, "rootCause": i.root_cause,
            "confidence": i.confidence, "evidence": i.evidence, "evidenceVerified": i.evidence_verified,
            "nextSteps": i.next_steps, "suggestedAction": i.suggested_action, "suggestionReason": i.suggestion_reason,
            "model": i.model, "createdAt": i.created_at.isoformat(), "createdBy": who.name if who else None}


def _ctx(acc: WorkspaceAccess) -> dict:
    return {"actor_id": acc.principal.user.id, "org_id": acc.workspace.org_id, "workspace_id": acc.workspace.id}


@router.get("/status")
def ai_status(acc: WorkspaceAccess = Depends(USE), settings: Settings = Depends(get_settings)):
    """Whether investigations can run. Never reveals the key."""
    return {"configured": bool(settings.groq_api_key), "provider": "groq", "model": settings.groq_model}


@router.get("")
def list_investigations(runId: uuid.UUID | None = None, limit: int = 20, acc: WorkspaceAccess = Depends(USE),
                        db: Session = Depends(get_db)):
    q = select(Investigation).where(Investigation.workspace_id == acc.workspace.id)
    if runId:
        q = q.where(Investigation.run_id == runId)
    rows = db.scalars(q.order_by(Investigation.created_at.desc()).limit(min(max(limit, 1), 100)))
    return {"investigations": [_dto(db, i) for i in rows]}


@router.post("", dependencies=[Depends(csrf_origin_check)])
def investigate(body: InvestigateBody, acc: WorkspaceAccess = Depends(USE), db: Session = Depends(get_db),
                settings: Settings = Depends(get_settings), ai: GroqClient = Depends(get_ai),
                factory: GitHubFactory = Depends(get_github_factory)):
    run = db.get(PipelineRun, body.runId)
    if run is None or run.workspace_id != acc.workspace.id:
        raise HTTPException(404, "not_found")
    if run.conclusion not in FAILED:
        raise HTTPException(409, "run_not_failed")
    if not settings.groq_api_key:
        raise HTTPException(503, "ai_not_configured")
    since = datetime.now(UTC) - timedelta(minutes=1)
    recent = db.scalar(select(func.count()).select_from(Investigation).where(
        Investigation.created_by == acc.principal.user.id, Investigation.created_at >= since)) or 0
    if recent >= settings.ai_investigations_per_minute:
        raise HTTPException(429, "ai_rate_limited")

    gh = client_for(factory, db, acc.workspace.id, run.repo)
    if not gh.configured:
        raise HTTPException(503, "github_not_configured")
    try:
        log = gh.get_logs(run.repo, run.external_id)  # redacted and size-capped by the adapter
    except GitHubError as exc:
        raise HTTPException(502, "upstream_error") from exc

    run_info = {"repo": run.repo, "workflow": run.workflow, "branch": run.branch, "conclusion": run.conclusion}
    try:
        out = analyse(ai, run_info, log, settings.ai_max_log_chars)
    except AiError as exc:
        audit.record(db, "ai.investigation", resource=f"run:{run.id}", outcome="failure", detail=str(exc), **_ctx(acc))
        raise HTTPException(503 if str(exc) == "ai_not_configured" else 502, str(exc)) from exc

    row = Investigation(org_id=acc.workspace.org_id, workspace_id=acc.workspace.id, run_id=run.id,
                        summary=out["summary"], root_cause=out["rootCause"], confidence=out["confidence"],
                        evidence=out["evidence"], evidence_verified=out["evidenceVerified"], next_steps=out["nextSteps"],
                        suggested_action=out["suggestedAction"], suggestion_reason=out["suggestionReason"],
                        model=ai.model, created_by=acc.principal.user.id)
    db.add(row)
    db.commit()
    audit.record(db, "ai.investigation", resource=f"run:{run.id}",
                 detail=f"confidence={out['confidence']} suggested={out['suggestedAction']}", **_ctx(acc))
    return _dto(db, row)
