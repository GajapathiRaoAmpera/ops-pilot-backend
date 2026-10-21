"""Invite flow. Admin side creates links; the public side previews and accepts them."""
import uuid

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app import audit
from app.db import get_db
from app.deps import (
    Principal,
    WorkspaceAccess,
    csrf_origin_check,
    current_principal,
    require_permission,
    workspace_access,
)
from app.models import AuthSession, Invitation, Membership, Organization, Role, User, Workspace
from app.onboarding import aware, create_invitation, find_valid, now
from app.rbac import ROLES, WORKSPACE_ROLES, WS_ADMIN_GRANTABLE, P
from app.security import hash_password

router = APIRouter(tags=["invitations"])
EMAIL = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
ORG_MGR = P["members_manage"]


class InviteBody(BaseModel):
    email: str = Field(min_length=3, max_length=320, pattern=EMAIL)
    role: str
    workspaceId: uuid.UUID | None = None


class WsInviteBody(BaseModel):
    email: str = Field(min_length=3, max_length=320, pattern=EMAIL)
    role: str


class AcceptBody(BaseModel):
    token: str = Field(min_length=20, max_length=200)
    name: str = Field(default="", max_length=200)
    password: str = Field(min_length=12, max_length=1024)


class TokenBody(BaseModel):
    token: str = Field(min_length=20, max_length=200)


def _already_member(db: Session, org_id: uuid.UUID, workspace_id: uuid.UUID | None, email: str) -> bool:
    user = db.scalar(select(User).where(User.email == email))
    if user is None:
        return False
    q = select(Membership).where(Membership.user_id == user.id, Membership.org_id == org_id)
    q = q.where(Membership.workspace_id.is_(None) if workspace_id is None else Membership.workspace_id == workspace_id)
    return db.scalar(q) is not None


def _dto(inv: Invitation, token: str | None = None) -> dict:
    out = {"id": str(inv.id), "email": inv.email, "kind": inv.kind, "expiresAt": aware(inv.expires_at).isoformat(),
           "workspaceId": str(inv.workspace_id) if inv.workspace_id else None}
    if token:
        out["token"] = token  # shown once; the UI builds /accept-invite?token=...
    return out


@router.post("/org/invitations", status_code=201, dependencies=[Depends(csrf_origin_check)])
def invite_org(body: InviteBody, p: Principal = Depends(require_permission(ORG_MGR)), db: Session = Depends(get_db)):
    org_id = p.memberships[0].org_id
    email = body.email.strip().lower()
    if body.role not in ROLES:
        raise HTTPException(422, "unknown_role")
    if body.workspaceId is not None:
        ws = db.get(Workspace, body.workspaceId)
        if ws is None or ws.org_id != org_id:
            raise HTTPException(404, "not_found")
        if body.role not in WORKSPACE_ROLES:
            raise HTTPException(422, "role_not_allowed_for_workspace")
    if _already_member(db, org_id, body.workspaceId, email):
        raise HTTPException(409, "already_member")
    inv, token = create_invitation(db, kind="invite", org_id=org_id, email=email, invited_by=p.user.id,
                                   role_key=body.role, workspace_id=body.workspaceId)
    audit.record(db, "invitation.created", actor_id=p.user.id, org_id=org_id, workspace_id=body.workspaceId,
                 resource=f"invitation:{inv.id}", detail=f"role={body.role}")
    return _dto(inv, token)


@router.post("/workspaces/{ws_id}/invitations", status_code=201, dependencies=[Depends(csrf_origin_check)])
def invite_workspace(body: WsInviteBody, acc: WorkspaceAccess = Depends(workspace_access(P["ws_members_manage"])),
                     db: Session = Depends(get_db)):
    org_wide = ORG_MGR in acc.principal.org_wide_permissions()
    allowed = WORKSPACE_ROLES if org_wide else WS_ADMIN_GRANTABLE  # no privilege escalation
    if body.role not in allowed:
        raise HTTPException(403, "role_not_grantable")
    email = body.email.strip().lower()
    if _already_member(db, acc.workspace.org_id, acc.workspace.id, email):
        raise HTTPException(409, "already_member")
    inv, token = create_invitation(db, kind="invite", org_id=acc.workspace.org_id, email=email,
                                   invited_by=acc.principal.user.id, role_key=body.role, workspace_id=acc.workspace.id)
    audit.record(db, "invitation.created", actor_id=acc.principal.user.id, org_id=acc.workspace.org_id,
                 workspace_id=acc.workspace.id, resource=f"invitation:{inv.id}", detail=f"role={body.role}")
    return _dto(inv, token)


@router.get("/org/invitations")
def list_invitations(p: Principal = Depends(require_permission(ORG_MGR)), db: Session = Depends(get_db)):
    rows = db.scalars(select(Invitation).where(
        Invitation.org_id == p.memberships[0].org_id, Invitation.accepted_at.is_(None),
        Invitation.revoked_at.is_(None), Invitation.expires_at > now()).order_by(Invitation.created_at.desc()))
    return {"invitations": [_dto(i) for i in rows]}


@router.delete("/org/invitations/{inv_id}", dependencies=[Depends(csrf_origin_check)])
def revoke_invitation(inv_id: uuid.UUID, p: Principal = Depends(require_permission(ORG_MGR)),
                      db: Session = Depends(get_db)):
    inv = db.get(Invitation, inv_id)
    if inv is None or inv.org_id != p.memberships[0].org_id:
        raise HTTPException(404, "not_found")
    inv.revoked_at = now()
    db.commit()
    audit.record(db, "invitation.revoked", actor_id=p.user.id, org_id=inv.org_id, resource=f"invitation:{inv.id}")
    return {"ok": True}


# ---- public side (token is the credential) ----

@router.get("/invitations/{token}")
def preview(token: str, db: Session = Depends(get_db)):
    inv = find_valid(db, token)
    if inv is None:
        raise HTTPException(404, "invalid_or_expired")
    org = db.get(Organization, inv.org_id)
    ws = db.get(Workspace, inv.workspace_id) if inv.workspace_id else None
    role = db.get(Role, inv.role_id) if inv.role_id else None
    return {"kind": inv.kind, "email": inv.email, "organization": org.name, "workspace": ws.name if ws else None,
            "role": role.label if role else None, "accountExists": db.scalar(select(User).where(User.email == inv.email)) is not None}


def _consume(db: Session, inv: Invitation) -> bool:
    """Atomic single-use: only one caller can flip accepted_at from NULL."""
    won = db.execute(update(Invitation).where(Invitation.id == inv.id, Invitation.accepted_at.is_(None),
                                              Invitation.revoked_at.is_(None)).values(accepted_at=now())).rowcount
    return won == 1


@router.post("/invitations/accept", dependencies=[Depends(csrf_origin_check)])
def accept(body: AcceptBody, db: Session = Depends(get_db)):
    inv = find_valid(db, body.token)
    if inv is None:
        raise HTTPException(404, "invalid_or_expired")
    existing = db.scalar(select(User).where(User.email == inv.email))
    if inv.kind == "reset":
        if existing is None or existing.id != inv.user_id:
            raise HTTPException(404, "invalid_or_expired")
        if not _consume(db, inv):
            db.rollback()
            raise HTTPException(404, "invalid_or_expired")
        existing.password_hash = hash_password(body.password)
        existing.must_change_password = False
        for s in db.scalars(select(AuthSession).where(AuthSession.user_id == existing.id, AuthSession.revoked_at.is_(None))):
            s.revoked_at = now()
        db.commit()
        audit.record(db, "auth.password_reset", actor_id=existing.id, org_id=inv.org_id)
        return {"ok": True, "email": existing.email}
    if existing is not None:
        raise HTTPException(409, "account_exists")  # sign in, then POST /invitations/accept-existing
    if not body.name.strip():
        raise HTTPException(422, "name_required")
    if not _consume(db, inv):
        db.rollback()
        raise HTTPException(404, "invalid_or_expired")
    user = User(email=inv.email, name=body.name.strip(), password_hash=hash_password(body.password))
    db.add(user)
    db.flush()
    db.add(Membership(user_id=user.id, org_id=inv.org_id, workspace_id=inv.workspace_id, role_id=inv.role_id))
    db.commit()
    audit.record(db, "invitation.accepted", actor_id=user.id, org_id=inv.org_id, workspace_id=inv.workspace_id,
                 resource=f"invitation:{inv.id}")
    return {"ok": True, "email": user.email}


@router.post("/invitations/accept-existing", dependencies=[Depends(csrf_origin_check)])
def accept_existing(body: TokenBody, p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    inv = find_valid(db, body.token)
    if inv is None or inv.kind != "invite" or inv.email != p.user.email.lower():
        raise HTTPException(404, "invalid_or_expired")  # the link only works for the invited account
    if _already_member(db, inv.org_id, inv.workspace_id, inv.email):
        raise HTTPException(409, "already_member")
    if not _consume(db, inv):
        db.rollback()
        raise HTTPException(404, "invalid_or_expired")
    db.add(Membership(user_id=p.user.id, org_id=inv.org_id, workspace_id=inv.workspace_id, role_id=inv.role_id))
    db.commit()
    audit.record(db, "invitation.accepted", actor_id=p.user.id, org_id=inv.org_id, workspace_id=inv.workspace_id,
                 resource=f"invitation:{inv.id}")
    return {"ok": True}
