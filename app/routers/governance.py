from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import get_db
from app.deps import Principal, require_permission
from app.models import AuditEvent, Role, User
from app.rbac import P

router = APIRouter(tags=["governance"])


@router.get("/rbac/matrix")
def rbac_matrix(_: Principal = Depends(require_permission(P["rbac_read"])), db: Session = Depends(get_db)):
    roles = db.scalars(select(Role).order_by(Role.key))
    return {"roles": [{"key": r.key, "label": r.label,
                       "permissions": sorted(rp.permission for rp in r.permissions)} for r in roles]}


@router.get("/audit-events")
def audit_events(limit: int = 100, action: str | None = None, outcome: str | None = None,
                 before_id: int | None = None, p: Principal = Depends(require_permission(P["audit_read"])),
                 db: Session = Depends(get_db)):
    org_ids = {m.org_id for m in p.memberships}  # tenant isolation: only the user's orgs
    limit = min(max(limit, 1), 500)
    q = (select(AuditEvent, User.name, User.email).outerjoin(User, User.id == AuditEvent.actor_id)
         .where(AuditEvent.org_id.in_(org_ids)))
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
