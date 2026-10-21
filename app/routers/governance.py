from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import get_db
from app.deps import Principal, require_permission
from app.models import AuditEvent, Role
from app.rbac import P

router = APIRouter(tags=["governance"])


@router.get("/rbac/matrix")
def rbac_matrix(_: Principal = Depends(require_permission(P["rbac_read"])), db: Session = Depends(get_db)):
    roles = db.scalars(select(Role).order_by(Role.key))
    return {"roles": [{"key": r.key, "label": r.label,
                       "permissions": sorted(rp.permission for rp in r.permissions)} for r in roles]}


@router.get("/audit-events")
def audit_events(limit: int = 100, p: Principal = Depends(require_permission(P["audit_read"])),
                 db: Session = Depends(get_db)):
    org_ids = {m.org_id for m in p.memberships}  # tenant isolation: only the user's orgs
    rows = db.scalars(select(AuditEvent).where(AuditEvent.org_id.in_(org_ids))
                      .order_by(AuditEvent.id.desc()).limit(min(max(limit, 1), 500)))
    return {"events": [{"id": e.id, "ts": e.ts.isoformat(), "actorId": str(e.actor_id) if e.actor_id else None,
                        "action": e.action, "resource": e.resource, "outcome": e.outcome,
                        "workspaceId": str(e.workspace_id) if e.workspace_id else None} for e in rows]}
