from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import get_db
from app.deps import Principal, WorkspaceAccess, current_principal, require_permission, workspace_access
from app.models import AuditEvent, Role, User
from app.rbac import ROLES, WORKSPACE_ROLES, WS_ADMIN_GRANTABLE, P

router = APIRouter(tags=["governance"])


@router.get("/meta/roles")
def role_catalog(_: Principal = Depends(current_principal)):
    """Role names and which of them can be granted where. One source for every role picker in the UI."""
    return {
        "roles": [{"key": k, "label": label} for k, (label, _perms) in ROLES.items()],
        "workspaceRoles": sorted(WORKSPACE_ROLES),
        "wsAdminGrantable": sorted(WS_ADMIN_GRANTABLE),
    }


@router.get("/rbac/matrix")
def rbac_matrix(_: Principal = Depends(require_permission(P["rbac_read"])), db: Session = Depends(get_db)):
    roles = db.scalars(select(Role).order_by(Role.key))
    return {"roles": [{"key": r.key, "label": r.label,
                       "permissions": sorted(rp.permission for rp in r.permissions)} for r in roles]}


def _audit_page(db: Session, org_id, workspace_id, limit: int, action: str | None, outcome: str | None,
                before_id: int | None) -> dict:
    limit = min(max(limit, 1), 500)
    q = (select(AuditEvent, User.name, User.email).outerjoin(User, User.id == AuditEvent.actor_id)
         .where(AuditEvent.org_id == org_id))
    if workspace_id is not None:
        q = q.where(AuditEvent.workspace_id == workspace_id)
    if action:
        q = q.where(AuditEvent.action == action[:100])
    if outcome in ("success", "failure"):
        q = q.where(AuditEvent.outcome == outcome)
    if before_id:
        q = q.where(AuditEvent.id < before_id)
    rows = db.execute(q.order_by(AuditEvent.id.desc()).limit(limit + 1)).all()
    page, more = rows[:limit], len(rows) > limit
    return {"events": [{"id": e.id, "ts": e.ts.isoformat(), "actorId": str(e.actor_id) if e.actor_id else None,
                        "actorName": name, "actorEmail": email, "action": e.action, "resource": e.resource,
                        "outcome": e.outcome, "detail": e.detail,
                        "workspaceId": str(e.workspace_id) if e.workspace_id else None} for e, name, email in page],
            "nextBefore": page[-1][0].id if more and page else None}


@router.get("/audit-events")
def audit_events(limit: int = 100, action: str | None = None, outcome: str | None = None,
                 before_id: int | None = None, p: Principal = Depends(require_permission(P["audit_read"])),
                 db: Session = Depends(get_db)):
    """The whole active organization (tenant isolation: only where this permission was checked)."""
    return _audit_page(db, p.active_org, None, limit, action, outcome, before_id)


@router.get("/workspaces/{ws_id}/audit-events")
def workspace_audit_events(limit: int = 100, action: str | None = None, outcome: str | None = None,
                           before_id: int | None = None,
                           acc: WorkspaceAccess = Depends(workspace_access(P["ws_audit_read"], P["audit_read"])),
                           db: Session = Depends(get_db)):
    """One workspace's events, for its administrators (org-level auditors may read it too)."""
    return _audit_page(db, acc.workspace.org_id, acc.workspace.id, limit, action, outcome, before_id)
