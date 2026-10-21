"""Action requests, approvals and execution. Allowlisted action: rerun_failed_jobs only."""
import uuid
from datetime import UTC, datetime
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app import audit
from app.db import get_db
from app.deps import WorkspaceAccess, csrf_origin_check, workspace_access
from app.integrations.github import GitHubClient, GitHubError, GitHubFactory
from app.models import ActionRequest, Approval, Execution, Integration, PipelineRun, User
from app.rbac import P
from app.routers.pipelines import get_github_factory

router = APIRouter(prefix="/workspaces/{ws_id}", tags=["actions"])
ACTION_TYPES = {"rerun_failed_jobs"}


class RequestBody(BaseModel):
    runId: uuid.UUID
    type: Literal["rerun_failed_jobs"]
    reason: str = Field(default="", max_length=1000)


class DecisionBody(BaseModel):
    decision: Literal["approve", "reject"]
    reason: str = Field(default="", max_length=1000)


def _risk(run: PipelineRun) -> str:
    return "medium" if run.branch in {"main", "master"} or run.branch.startswith("release") else "low"


def _dto(r: ActionRequest, approval: Approval | None, ex: Execution | None) -> dict:
    return {
        "id": str(r.id), "runId": str(r.run_id), "type": r.type, "risk": r.risk, "status": r.status,
        "reason": r.reason, "requestedBy": str(r.requested_by), "createdAt": r.created_at.isoformat(),
        "decision": None if approval is None else {
            "decision": approval.decision, "decidedBy": str(approval.decided_by), "reason": approval.reason,
            "decidedAt": approval.decided_at.isoformat()},
        "execution": None if ex is None else {
            "id": str(ex.id), "status": ex.status, "error": ex.error, "result": ex.result,
            "endedAt": ex.ended_at.isoformat() if ex.ended_at else None},
    }


def _full(db: Session, r: ActionRequest) -> dict:
    """Request + decision + execution + the context a reviewer needs (run, people)."""
    approval = db.scalar(select(Approval).where(Approval.request_id == r.id))
    ex = db.scalar(select(Execution).where(Execution.request_id == r.id))
    out = _dto(r, approval, ex)
    run = db.get(PipelineRun, r.run_id)
    out["run"] = None if run is None else {
        "repo": run.repo, "workflow": run.workflow, "branch": run.branch, "commit": run.commit_sha[:7],
        "status": run.status, "conclusion": run.conclusion, "url": run.html_url}
    requester = db.get(User, r.requested_by)
    out["requester"] = {"name": requester.name, "email": requester.email} if requester else None
    if approval is not None and out["decision"] is not None:
        decider = db.get(User, approval.decided_by)
        out["decision"]["decidedByName"] = decider.name if decider else None
    return out


def _get_request(db: Session, acc: WorkspaceAccess, req_id: uuid.UUID) -> ActionRequest:
    req = db.get(ActionRequest, req_id)
    if req is None or req.workspace_id != acc.workspace.id:
        raise HTTPException(404, "not_found")
    return req


def _ctx(acc: WorkspaceAccess) -> dict:
    return {"actor_id": acc.principal.user.id, "org_id": acc.workspace.org_id, "workspace_id": acc.workspace.id}


@router.post("/action-requests", status_code=201, dependencies=[Depends(csrf_origin_check)])
def create_request(body: RequestBody, acc: WorkspaceAccess = Depends(workspace_access(P["pipelines_execute"])),
                   db: Session = Depends(get_db)):
    run = db.get(PipelineRun, body.runId)
    if run is None or run.workspace_id != acc.workspace.id:
        raise HTTPException(404, "not_found")
    if run.status != "completed" or run.conclusion != "failure":
        raise HTTPException(409, "run_not_failed")
    open_req = db.scalar(select(ActionRequest).where(
        ActionRequest.run_id == run.id, ActionRequest.type == body.type,
        ActionRequest.status.in_(["pending", "approved", "executing"])))
    if open_req is not None:
        raise HTTPException(409, "request_already_open")
    req = ActionRequest(org_id=run.org_id, workspace_id=run.workspace_id, run_id=run.id, type=body.type,
                        risk=_risk(run), reason=body.reason, requested_by=acc.principal.user.id)
    db.add(req)
    db.commit()
    audit.record(db, "action.requested", resource=f"request:{req.id}", detail=f"{req.type} risk={req.risk}",
                 **_ctx(acc))
    return _full(db, req)


@router.get("/approvals")
def list_approvals(status: str | None = None,
                   acc: WorkspaceAccess = Depends(workspace_access(P["approvals_read"])),
                   db: Session = Depends(get_db)):
    q = select(ActionRequest).where(ActionRequest.workspace_id == acc.workspace.id)
    if status:
        q = q.where(ActionRequest.status == status)
    rows = db.scalars(q.order_by(ActionRequest.created_at.desc()).limit(100))
    return {"requests": [_full(db, r) for r in rows]}


@router.post("/approvals/{req_id}/decision", dependencies=[Depends(csrf_origin_check)])
def decide(req_id: uuid.UUID, body: DecisionBody,
           acc: WorkspaceAccess = Depends(workspace_access(P["approvals_decide"])),
           db: Session = Depends(get_db), factory: GitHubFactory = Depends(get_github_factory)):
    req = _get_request(db, acc, req_id)
    user = acc.principal.user
    if req.requested_by == user.id:
        audit.record(db, "approval.denied", outcome="failure", resource=f"request:{req.id}",
                     detail="separation_of_duties", **_ctx(acc))
        raise HTTPException(403, "separation_of_duties")
    new_status = "approved" if body.decision == "approve" else "rejected"
    # Atomic compare-and-set: exactly one decision can move a request out of "pending".
    won = db.execute(update(ActionRequest).where(ActionRequest.id == req.id, ActionRequest.status == "pending")
                     .values(status=new_status)).rowcount
    if won != 1:
        db.rollback()
        raise HTTPException(409, "not_pending")
    db.add(Approval(request_id=req.id, decided_by=user.id, decision=body.decision, reason=body.reason))
    db.commit()
    audit.record(db, f"approval.{body.decision}", resource=f"request:{req.id}", **_ctx(acc))
    if body.decision == "approve":
        integ = db.scalar(select(Integration).where(Integration.workspace_id == acc.workspace.id,
                                                    Integration.provider == "github"))
        _execute(db, acc, req.id, factory.for_integration(integ))
    db.expire_all()
    return _full(db, db.get(ActionRequest, req.id))


def _execute(db: Session, acc: WorkspaceAccess, req_id: uuid.UUID, gh: GitHubClient) -> None:
    """Runs inline for the MVP (a worker takes this over later). Success is recorded only on GitHub's 201."""
    req = db.get(ActionRequest, req_id)
    run = db.get(PipelineRun, req.run_id)
    ex = Execution(request_id=req.id, idempotency_key=f"{req.type}:{req.id}", status="executing")
    db.add(ex)
    try:
        db.commit()
    except IntegrityError:  # duplicate execution attempt
        db.rollback()
        return
    req.status = "executing"
    db.commit()
    audit.record(db, "execution.started", resource=f"execution:{ex.id}", **_ctx(acc))
    status, error, result = "succeeded", "", {}
    try:
        if not gh.configured:
            raise GitHubError("github_not_configured")
        gh.rerun_failed_jobs(run.repo, run.external_id)
        result = {"requested": "rerun_failed_jobs", "runExternalId": run.external_id}
        try:  # verification is best-effort; it is reported, not assumed
            current = gh.get_run(run.repo, run.external_id)
            result["observedStatus"] = current.status
        except GitHubError:
            result["observedStatus"] = "unverified"
    except GitHubError as exc:
        status, error = "failed", str(exc)[:500]
    ex.status, ex.error, ex.result, ex.ended_at = status, error, result, datetime.now(UTC)
    req.status = status
    db.commit()
    audit.record(db, f"execution.{status}", resource=f"execution:{ex.id}", outcome="success" if status == "succeeded" else "failure",
                 detail=error, **_ctx(acc))


@router.get("/executions")
def list_executions(status: str | None = None, limit: int = 50,
                    acc: WorkspaceAccess = Depends(workspace_access(P["automation_read"])),
                    db: Session = Depends(get_db)):
    """Automation history: every approved action that was (or is being) executed in this workspace."""
    q = (select(ActionRequest).join(Execution, Execution.request_id == ActionRequest.id)
         .where(ActionRequest.workspace_id == acc.workspace.id))
    if status in ("executing", "succeeded", "failed"):
        q = q.where(Execution.status == status)
    rows = db.scalars(q.order_by(Execution.started_at.desc()).limit(min(max(limit, 1), 100)))
    return {"executions": [_full(db, r) for r in rows]}


@router.get("/executions/{ex_id}")
def get_execution(ex_id: uuid.UUID, acc: WorkspaceAccess = Depends(workspace_access(P["automation_read"])),
                  db: Session = Depends(get_db)):
    ex = db.get(Execution, ex_id)
    req = db.get(ActionRequest, ex.request_id) if ex else None
    if ex is None or req is None or req.workspace_id != acc.workspace.id:
        raise HTTPException(404, "not_found")
    return _full(db, req)
