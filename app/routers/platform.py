"""Platform operator: manages organizations and their people (create, rename, block, archive; members, roles,
blocks and password-reset links). Never sees a tenant's operational data (runs, approvals, logs, AI results).
Every action is recorded in the target organization's audit trail."""
import uuid
from datetime import UTC, datetime
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import audit
from app import member_ops as ops
from app.db import get_db
from app.deps import Principal, csrf_origin_check, require_platform_admin
from app.models import Membership, Organization, User, Workspace
from app.onboarding import create_invitation

router = APIRouter(prefix="/platform", tags=["platform"])


class OrgBody(BaseModel):
    name: str = Field(min_length=2, max_length=200)
    adminEmail: str = Field(min_length=3, max_length=320, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


@router.post("/organizations", status_code=201, dependencies=[Depends(csrf_origin_check)])
def create_org(body: OrgBody, p: Principal = Depends(require_platform_admin), db: Session = Depends(get_db)):
    name = body.name.strip()
    if db.scalar(select(Organization).where(func.lower(Organization.name) == name.lower())):
        raise HTTPException(409, "organization_exists")
    org = Organization(name=name)
    db.add(org)
    db.flush()
    db.add(Workspace(org_id=org.id, name="Default Workspace"))
    db.commit()
    inv, token = create_invitation(db, kind="invite", org_id=org.id, email=body.adminEmail, invited_by=p.user.id,
                                   role_key="org_admin")
    audit.record(db, "organization.created", actor_id=p.user.id, org_id=org.id, resource=f"org:{org.id}")
    return {"id": str(org.id), "name": org.name, "adminInvitation": {"email": inv.email, "token": token,
            "expiresAt": inv.expires_at.isoformat()}}


def _org_dto(db: Session, org: Organization) -> dict:
    return {"id": str(org.id), "name": org.name, "status": org.status,
            "statusChangedAt": org.status_changed_at.isoformat() if org.status_changed_at else None,
            "workspaces": db.scalar(select(func.count()).select_from(Workspace).where(Workspace.org_id == org.id)),
            "members": db.scalar(select(func.count(func.distinct(Membership.user_id))).where(Membership.org_id == org.id))}


@router.get("/organizations")
def list_orgs(_: Principal = Depends(require_platform_admin), db: Session = Depends(get_db)):
    return {"organizations": [_org_dto(db, o) for o in db.scalars(select(Organization).order_by(Organization.name))]}


def _org(db: Session, org_id: uuid.UUID) -> Organization:
    org = db.get(Organization, org_id)
    if org is None:
        raise HTTPException(404, "not_found")
    return org


class OrgUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=200)
    # active <-> suspended (blocked). Archived organizations can be restored to active.
    status: Literal["active", "suspended"] | None = None


@router.patch("/organizations/{org_id}", dependencies=[Depends(csrf_origin_check)])
def update_org(org_id: uuid.UUID, body: OrgUpdate, p: Principal = Depends(require_platform_admin),
               db: Session = Depends(get_db)):
    org = _org(db, org_id)
    if body.name is not None:
        name = body.name.strip()
        clash = db.scalar(select(Organization).where(func.lower(Organization.name) == name.lower(), Organization.id != org.id))
        if clash:
            raise HTTPException(409, "organization_exists")
        old, org.name = org.name, name
        db.commit()
        audit.record(db, "organization.renamed", actor_id=p.user.id, org_id=org.id, resource=f"org:{org.id}",
                     detail=f"{old} -> {name}"[:1000])
    if body.status is not None and body.status != org.status:
        before, org.status, org.status_changed_at = org.status, body.status, datetime.now(UTC)
        db.commit()
        action = "organization.blocked" if body.status == "suspended" else "organization.reactivated"
        audit.record(db, action, actor_id=p.user.id, org_id=org.id, resource=f"org:{org.id}", detail=f"was {before}")
    return _org_dto(db, org)


class ArchiveBody(BaseModel):
    confirm: str = Field(max_length=200)  # must repeat the organization's name


@router.delete("/organizations/{org_id}", dependencies=[Depends(csrf_origin_check)])
def archive_org(org_id: uuid.UUID, body: ArchiveBody, p: Principal = Depends(require_platform_admin),
                db: Session = Depends(get_db)):
    """'Delete': the organization must be blocked first and its name typed again. Access ends, data is kept
    (archived), so a mistake can be undone with PATCH status=active."""
    org = _org(db, org_id)
    if org.status != "suspended":
        raise HTTPException(409, "block_before_delete")
    if body.confirm.strip() != org.name:
        raise HTTPException(422, "confirmation_mismatch")
    org.status, org.status_changed_at = "archived", datetime.now(UTC)
    db.commit()
    audit.record(db, "organization.archived", actor_id=p.user.id, org_id=org.id, resource=f"org:{org.id}")
    return _org_dto(db, org)


# ---- people inside an organization (same rules as the organization's own administrators) ----

@router.get("/organizations/{org_id}/members")
def org_members(org_id: uuid.UUID, _: Principal = Depends(require_platform_admin), db: Session = Depends(get_db)):
    _org(db, org_id)
    return {"members": ops.list_members(db, org_id)}


@router.get("/organizations/{org_id}/workspaces")
def org_workspaces(org_id: uuid.UUID, _: Principal = Depends(require_platform_admin), db: Session = Depends(get_db)):
    _org(db, org_id)
    rows = db.scalars(select(Workspace).where(Workspace.org_id == org_id).order_by(Workspace.name))
    return {"workspaces": [{"id": str(w.id), "name": w.name} for w in rows]}


class InviteBody(BaseModel):
    email: str = Field(min_length=3, max_length=320, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    role: str
    workspaceId: uuid.UUID | None = None


@router.post("/organizations/{org_id}/invitations", status_code=201, dependencies=[Depends(csrf_origin_check)])
def org_invite(org_id: uuid.UUID, body: InviteBody, p: Principal = Depends(require_platform_admin),
               db: Session = Depends(get_db)):
    if _org(db, org_id).status != "active":
        raise HTTPException(409, "organization_not_active")
    inv, token = ops.invite(db, org_id, body.email, body.role, body.workspaceId, p.user)
    return {"id": str(inv.id), "email": inv.email, "token": token, "expiresAt": inv.expires_at.isoformat()}


class RoleBody(BaseModel):
    role: str


@router.patch("/organizations/{org_id}/memberships/{mid}", dependencies=[Depends(csrf_origin_check)])
def org_change_role(org_id: uuid.UUID, mid: uuid.UUID, body: RoleBody, p: Principal = Depends(require_platform_admin),
                    db: Session = Depends(get_db)):
    _org(db, org_id)
    m = ops.change_role(db, org_id, mid, body.role, p.user)
    return {"ok": True, "role": m.role.key}


@router.delete("/organizations/{org_id}/memberships/{mid}", dependencies=[Depends(csrf_origin_check)])
def org_remove_membership(org_id: uuid.UUID, mid: uuid.UUID, p: Principal = Depends(require_platform_admin),
                          db: Session = Depends(get_db)):
    _org(db, org_id)
    ops.remove_membership(db, org_id, mid, p.user)
    return {"ok": True}


class BlockBody(BaseModel):
    blocked: bool


@router.post("/organizations/{org_id}/members/{user_id}/block", dependencies=[Depends(csrf_origin_check)])
def org_block_member(org_id: uuid.UUID, user_id: uuid.UUID, body: BlockBody, p: Principal = Depends(require_platform_admin),
                     db: Session = Depends(get_db)):
    """Blocks or unblocks the person in this organization only."""
    _org(db, org_id)
    ops.set_blocked(db, org_id, user_id, body.blocked, p.user)
    return {"ok": True, "blocked": body.blocked}


@router.post("/organizations/{org_id}/members/{user_id}/reset-link", status_code=201,
             dependencies=[Depends(csrf_origin_check)])
def org_reset_link(org_id: uuid.UUID, user_id: uuid.UUID, p: Principal = Depends(require_platform_admin),
                   db: Session = Depends(get_db)):
    """Any role, including people in several organizations (platform administrators are above organizations)."""
    _org(db, org_id)
    return ops.issue_reset_link(db, org_id, user_id, p.user, platform=True)


@router.post("/users/{user_id}/block", dependencies=[Depends(csrf_origin_check)])
def block_account(user_id: uuid.UUID, body: BlockBody, p: Principal = Depends(require_platform_admin),
                  db: Session = Depends(get_db)):
    """Blocks (or unblocks) the whole account: every organization, sessions ended. Platform administrators are
    managed on the server, not here."""
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(404, "not_found")
    if user.id == p.user.id or user.is_platform_admin:
        raise HTTPException(409, "cannot_block_platform_admin")
    user.disabled = body.blocked
    if body.blocked:
        ops.revoke_sessions(db, user.id)
    db.commit()
    for org_id in {m.org_id for m in db.scalars(select(Membership).where(Membership.user_id == user.id))}:
        audit.record(db, "account.blocked" if body.blocked else "account.unblocked", actor_id=p.user.id,
                     org_id=org_id, resource=f"user:{user.id}")
    return {"ok": True, "blocked": body.blocked}
