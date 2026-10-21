"""Org admins add and manage their own members. Scope is always the caller's organization."""
import secrets
import uuid
from datetime import UTC, datetime
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit
from app.db import get_db
from app.deps import Principal, csrf_origin_check, require_permission
from app.models import AuthSession, Membership, Role, User
from app.rbac import P
from app.security import hash_password

router = APIRouter(prefix="/org/members", tags=["members"])
RoleKey = Literal["org_admin", "devops_engineer", "security_auditor", "viewer"]


class AddBody(BaseModel):
    email: str = Field(min_length=3, max_length=320, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    name: str = Field(min_length=1, max_length=200)
    role: RoleKey


class RoleBody(BaseModel):
    role: RoleKey


def _org(p: Principal) -> uuid.UUID:
    if not p.memberships:
        raise HTTPException(403, "no_membership")
    return p.memberships[0].org_id


def _member(db: Session, org_id: uuid.UUID, user_id: uuid.UUID) -> tuple[User, Membership]:
    m = db.scalar(select(Membership).where(Membership.user_id == user_id, Membership.org_id == org_id))
    user = db.get(User, user_id) if m else None
    if m is None or user is None:
        raise HTTPException(404, "not_found")  # other orgs' users are indistinguishable from missing
    return user, m


def _dto(u: User, m: Membership) -> dict:
    return {"id": str(u.id), "email": u.email, "name": u.name, "role": m.role.key, "roleLabel": m.role.label,
            "disabled": u.disabled, "mustChangePassword": u.must_change_password}


@router.get("")
def list_members(p: Principal = Depends(require_permission(P["members_manage"])), db: Session = Depends(get_db)):
    org_id = _org(p)
    rows = db.execute(select(User, Membership).join(Membership, Membership.user_id == User.id)
                      .where(Membership.org_id == org_id).order_by(User.email)).all()
    return {"members": [_dto(u, m) for u, m in rows]}


@router.post("", status_code=201, dependencies=[Depends(csrf_origin_check)])
def add_member(body: AddBody, p: Principal = Depends(require_permission(P["members_manage"])),
               db: Session = Depends(get_db)):
    org_id = _org(p)
    email = body.email.strip().lower()
    if db.scalar(select(User).where(User.email == email)):
        raise HTTPException(409, "email_unavailable")
    role = db.scalar(select(Role).where(Role.key == body.role))
    temp = secrets.token_urlsafe(12)  # shown once; the user must change it at first sign-in
    user = User(email=email, name=body.name.strip(), password_hash=hash_password(temp), must_change_password=True)
    db.add(user)
    db.flush()
    db.add(Membership(user_id=user.id, org_id=org_id, role_id=role.id))
    db.commit()
    audit.record(db, "member.added", actor_id=p.user.id, org_id=org_id, resource=f"user:{user.id}",
                 detail=f"role={body.role}")
    m = db.scalar(select(Membership).where(Membership.user_id == user.id))
    return {**_dto(user, m), "temporaryPassword": temp}


@router.patch("/{user_id}", dependencies=[Depends(csrf_origin_check)])
def change_role(user_id: uuid.UUID, body: RoleBody, p: Principal = Depends(require_permission(P["members_manage"])),
                db: Session = Depends(get_db)):
    org_id = _org(p)
    user, m = _member(db, org_id, user_id)
    if user.id == p.user.id:
        raise HTTPException(409, "cannot_change_own_role")
    m.role_id = db.scalar(select(Role).where(Role.key == body.role)).id
    db.commit()
    audit.record(db, "member.role_changed", actor_id=p.user.id, org_id=org_id, resource=f"user:{user.id}",
                 detail=f"role={body.role}")
    db.refresh(m)
    return _dto(user, m)


@router.delete("/{user_id}", dependencies=[Depends(csrf_origin_check)])
def disable_member(user_id: uuid.UUID, p: Principal = Depends(require_permission(P["members_manage"])),
                   db: Session = Depends(get_db)):
    org_id = _org(p)
    user, m = _member(db, org_id, user_id)
    if user.id == p.user.id:
        raise HTTPException(409, "cannot_disable_self")
    user.disabled = True
    for s in db.scalars(select(AuthSession).where(AuthSession.user_id == user.id,
                                                  AuthSession.revoked_at.is_(None))):
        s.revoked_at = datetime.now(UTC)
    db.commit()
    audit.record(db, "member.disabled", actor_id=p.user.id, org_id=org_id, resource=f"user:{user.id}")
    return _dto(user, m)


