"""Membership administration. Org admins manage the whole org; workspace admins only their workspace."""
import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit
from app.db import get_db
from app.deps import Principal, WorkspaceAccess, csrf_origin_check, require_permission, workspace_access
from app.models import AuthSession, Membership, Role, User, Workspace
from app.onboarding import create_invitation
from app.rbac import ROLES, WORKSPACE_ROLES, WS_ADMIN_GRANTABLE, P
from app.routers.invitations import ORG_MGR

router = APIRouter(tags=["members"])


class RoleBody(BaseModel):
    role: str


class WorkspaceBody(BaseModel):
    name: str = Field(min_length=2, max_length=200)


def _org(p: Principal) -> uuid.UUID:
    if p.active_org is None:  # set by require_permission; never act on a guessed organization
        raise HTTPException(403, "forbidden")
    return p.active_org


def _dto(m: Membership, user: User, ws_name: str | None) -> dict:
    return {"membershipId": str(m.id), "userId": str(user.id), "email": user.email, "name": user.name,
            "role": m.role.key, "roleLabel": m.role.label, "workspaceId": str(m.workspace_id) if m.workspace_id else None,
            "workspace": ws_name, "disabled": user.disabled}


def _org_admin_count(db: Session, org_id: uuid.UUID) -> int:
    rows = db.execute(select(Membership, User).join(User, User.id == Membership.user_id).where(
        Membership.org_id == org_id, Membership.workspace_id.is_(None), User.disabled.is_(False))).all()
    return sum(1 for m, _ in rows if m.role.key == "org_admin")


def _role(db: Session, key: str) -> Role:
    if key not in ROLES:
        raise HTTPException(422, "unknown_role")
    return db.scalar(select(Role).where(Role.key == key))


def _revoke_sessions(db: Session, user_id: uuid.UUID) -> None:
    for s in db.scalars(select(AuthSession).where(AuthSession.user_id == user_id, AuthSession.revoked_at.is_(None))):
        s.revoked_at = datetime.now(UTC)


# ---- org level ----

@router.get("/org/members")
def list_members(p: Principal = Depends(require_permission(ORG_MGR)), db: Session = Depends(get_db)):
    rows = db.execute(select(Membership, User, Workspace.name).join(User, User.id == Membership.user_id)
                      .outerjoin(Workspace, Workspace.id == Membership.workspace_id)
                      .where(Membership.org_id == _org(p)).order_by(User.email)).all()
    return {"members": [_dto(m, u, wn) for m, u, wn in rows]}


@router.get("/org/workspaces")
def list_workspaces(p: Principal = Depends(require_permission(ORG_MGR)), db: Session = Depends(get_db)):
    rows = db.scalars(select(Workspace).where(Workspace.org_id == _org(p)).order_by(Workspace.name))
    return {"workspaces": [{"id": str(w.id), "name": w.name} for w in rows]}


@router.post("/org/workspaces", status_code=201, dependencies=[Depends(csrf_origin_check)])
def create_workspace(body: WorkspaceBody, p: Principal = Depends(require_permission(ORG_MGR)),
                     db: Session = Depends(get_db)):
    name = body.name.strip()
    if db.scalar(select(Workspace).where(Workspace.org_id == _org(p), Workspace.name == name)):
        raise HTTPException(409, "workspace_exists")
    ws = Workspace(org_id=_org(p), name=name)
    db.add(ws)
    db.commit()
    audit.record(db, "workspace.created", actor_id=p.user.id, org_id=ws.org_id, workspace_id=ws.id, resource=f"workspace:{ws.id}")
    return {"id": str(ws.id), "name": ws.name}


def _membership(db: Session, org_id: uuid.UUID, mid: uuid.UUID) -> Membership:
    m = db.get(Membership, mid)
    if m is None or m.org_id != org_id:
        raise HTTPException(404, "not_found")
    return m


@router.patch("/org/memberships/{mid}", dependencies=[Depends(csrf_origin_check)])
def change_role(mid: uuid.UUID, body: RoleBody, p: Principal = Depends(require_permission(ORG_MGR)),
                db: Session = Depends(get_db)):
    m = _membership(db, _org(p), mid)
    if m.user_id == p.user.id:
        raise HTTPException(409, "cannot_change_own_role")
    if m.workspace_id and body.role not in WORKSPACE_ROLES:
        raise HTTPException(422, "role_not_allowed_for_workspace")
    new = _role(db, body.role)
    if m.workspace_id is None and m.role.key == "org_admin" and body.role != "org_admin" and _org_admin_count(db, m.org_id) <= 1:
        raise HTTPException(409, "last_org_admin")
    m.role_id = new.id
    db.commit()
    db.refresh(m)
    audit.record(db, "member.role_changed", actor_id=p.user.id, org_id=m.org_id, workspace_id=m.workspace_id,
                 resource=f"user:{m.user_id}", detail=f"role={body.role}")
    return {"ok": True, "role": m.role.key}


@router.delete("/org/memberships/{mid}", dependencies=[Depends(csrf_origin_check)])
def remove_membership(mid: uuid.UUID, p: Principal = Depends(require_permission(ORG_MGR)), db: Session = Depends(get_db)):
    m = _membership(db, _org(p), mid)
    if m.user_id == p.user.id:
        raise HTTPException(409, "cannot_remove_self")
    if m.workspace_id is None and m.role.key == "org_admin" and _org_admin_count(db, m.org_id) <= 1:
        raise HTTPException(409, "last_org_admin")
    org_id, ws_id, uid = m.org_id, m.workspace_id, m.user_id
    db.delete(m)
    db.commit()
    audit.record(db, "member.removed", actor_id=p.user.id, org_id=org_id, workspace_id=ws_id, resource=f"user:{uid}")
    return {"ok": True}


@router.delete("/org/members/{user_id}", dependencies=[Depends(csrf_origin_check)])
def disable_member(user_id: uuid.UUID, p: Principal = Depends(require_permission(ORG_MGR)), db: Session = Depends(get_db)):
    """Removes the person from this organization. The account itself is disabled (and its sessions ended) only when
    it belongs to no other organization: one org's admin must never lock someone out of another org."""
    if user_id == p.user.id:
        raise HTTPException(409, "cannot_disable_self")
    org = _org(p)
    in_org = db.scalar(select(Membership).where(Membership.user_id == user_id, Membership.org_id == org))
    user = db.get(User, user_id) if in_org else None
    if user is None:
        raise HTTPException(404, "not_found")
    if _in_other_orgs(db, user.id, org):
        for m in db.scalars(select(Membership).where(Membership.user_id == user.id, Membership.org_id == org)):
            db.delete(m)
        db.commit()
        audit.record(db, "member.removed_from_org", actor_id=p.user.id, org_id=org, resource=f"user:{user.id}")
        return {"ok": True, "disabled": False}
    user.disabled = True
    _revoke_sessions(db, user.id)
    db.commit()
    audit.record(db, "member.disabled", actor_id=p.user.id, org_id=org, resource=f"user:{user.id}")
    return {"ok": True, "disabled": True}


def _in_other_orgs(db: Session, user_id: uuid.UUID, org: uuid.UUID) -> bool:
    return db.scalar(select(Membership).where(Membership.user_id == user_id, Membership.org_id != org).limit(1)) is not None


@router.post("/org/members/{user_id}/reset-link", status_code=201, dependencies=[Depends(csrf_origin_check)])
def reset_link(user_id: uuid.UUID, p: Principal = Depends(require_permission(ORG_MGR)), db: Session = Depends(get_db)):
    in_org = db.scalar(select(Membership).where(Membership.user_id == user_id, Membership.org_id == _org(p)))
    if in_org is not None and _in_other_orgs(db, user_id, _org(p)):
        # A password reset unlocks the whole account, including other organizations: not this admin's to grant.
        raise HTTPException(409, "user_in_other_organizations")
    user = db.get(User, user_id) if in_org else None
    if user is None or user.is_platform_admin:
        raise HTTPException(404, "not_found")
    inv, token = create_invitation(db, kind="reset", org_id=_org(p), email=user.email, invited_by=p.user.id, user_id=user.id)
    audit.record(db, "member.reset_link_issued", actor_id=p.user.id, org_id=_org(p), resource=f"user:{user.id}")
    return {"token": token, "expiresAt": inv.expires_at.isoformat()}


# ---- workspace level ----

def _ws_membership(db: Session, acc: WorkspaceAccess, mid: uuid.UUID) -> Membership:
    m = db.get(Membership, mid)
    if m is None or m.workspace_id != acc.workspace.id:
        raise HTTPException(404, "not_found")
    return m


@router.get("/workspaces/{ws_id}/members")
def ws_members(acc: WorkspaceAccess = Depends(workspace_access(P["ws_members_manage"])), db: Session = Depends(get_db)):
    rows = db.execute(select(Membership, User).join(User, User.id == Membership.user_id).where(
        Membership.workspace_id == acc.workspace.id).order_by(User.email)).all()
    return {"members": [_dto(m, u, acc.workspace.name) for m, u in rows]}


@router.patch("/workspaces/{ws_id}/memberships/{mid}", dependencies=[Depends(csrf_origin_check)])
def ws_change_role(mid: uuid.UUID, body: RoleBody, acc: WorkspaceAccess = Depends(workspace_access(P["ws_members_manage"])),
                   db: Session = Depends(get_db)):
    m = _ws_membership(db, acc, mid)
    org_wide = ORG_MGR in acc.principal.org_wide_permissions(acc.workspace.org_id)
    if m.user_id == acc.principal.user.id:
        raise HTTPException(409, "cannot_change_own_role")
    if body.role not in (WORKSPACE_ROLES if org_wide else WS_ADMIN_GRANTABLE) or (
            not org_wide and m.role.key == "workspace_admin"):
        raise HTTPException(403, "role_not_grantable")  # cannot grant or demote at/above your own level
    m.role_id = _role(db, body.role).id
    db.commit()
    audit.record(db, "member.role_changed", actor_id=acc.principal.user.id, org_id=m.org_id, workspace_id=m.workspace_id,
                 resource=f"user:{m.user_id}", detail=f"role={body.role}")
    return {"ok": True}


@router.delete("/workspaces/{ws_id}/memberships/{mid}", dependencies=[Depends(csrf_origin_check)])
def ws_remove(mid: uuid.UUID, acc: WorkspaceAccess = Depends(workspace_access(P["ws_members_manage"])),
              db: Session = Depends(get_db)):
    m = _ws_membership(db, acc, mid)
    org_wide = ORG_MGR in acc.principal.org_wide_permissions(acc.workspace.org_id)
    if m.user_id == acc.principal.user.id:
        raise HTTPException(409, "cannot_remove_self")
    if not org_wide and m.role.key == "workspace_admin":
        raise HTTPException(403, "role_not_grantable")
    uid = m.user_id
    db.delete(m)
    db.commit()
    audit.record(db, "member.removed", actor_id=acc.principal.user.id, org_id=acc.workspace.org_id,
                 workspace_id=acc.workspace.id, resource=f"user:{uid}")
    return {"ok": True}
