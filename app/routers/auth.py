import time
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit
from app.config import Settings, get_settings
from app.db import get_db
from app.deps import COOKIE, Principal, csrf_origin_check, current_principal
from app.models import AuthSession, Membership, Organization, User, Workspace
from app.rbac import PLATFORM_PERMISSION
from app.security import hash_password, hash_token, new_session_token, verify_password

router = APIRouter(prefix="/auth", tags=["auth"])

# In-memory limiter: per-process only. Replace with a shared store before multi-instance deploy.
_FAILS: dict[str, list[float]] = {}
MAX_FAILS, WINDOW = 5, 15 * 60


def _limited(key: str) -> bool:
    now = time.time()
    _FAILS[key] = [t for t in _FAILS.get(key, []) if now - t < WINDOW]
    return len(_FAILS[key]) >= MAX_FAILS


class LoginBody(BaseModel):
    email: str = Field(max_length=320)
    password: str = Field(max_length=1024)


@router.post("/login", dependencies=[Depends(csrf_origin_check)])
def login(body: LoginBody, request: Request, response: Response, db: Session = Depends(get_db),
          s: Settings = Depends(get_settings)):
    email = body.email.strip().lower()
    key = f"{email}|{request.client.host if request.client else ''}"
    if _limited(key):
        raise HTTPException(429, "rate_limited")
    user = db.scalar(select(User).where(User.email == email))
    ok = verify_password(user.password_hash if user else None, body.password)
    if not ok or user is None or user.disabled:
        _FAILS.setdefault(key, []).append(time.time())
        audit.record(db, "auth.login", outcome="failure", resource=f"user:{email}"[:200])
        raise HTTPException(401, "invalid_credentials")
    _FAILS.pop(key, None)
    token, digest = new_session_token()
    db.add(AuthSession(id_hash=digest, user_id=user.id,
                       expires_at=datetime.now(UTC) + timedelta(hours=s.session_ttl_hours)))
    db.commit()
    first = db.scalar(select(Membership).where(Membership.user_id == user.id))
    audit.record(db, "auth.login", actor_id=user.id, org_id=first.org_id if first else None)
    response.set_cookie(COOKIE, token, httponly=True, secure=s.cookie_secure, samesite="lax",
                        max_age=s.session_ttl_hours * 3600, path="/")
    return {"ok": True}


@router.get("/me")
def me(p: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    base = {"user": {"id": str(p.user.id), "email": p.user.email, "name": p.user.name},
            "mustChangePassword": p.user.must_change_password}
    if p.user.is_platform_admin and not p.memberships:
        # Platform operators manage tenants only; they hold no tenant permissions.
        return {**base, "role": "Platform Administrator", "organization": {"id": "platform", "name": "OpsPilot Platform"},
                "workspaces": [], "permissions": [PLATFORM_PERMISSION]}
    if not p.memberships:
        raise HTTPException(403, "no_membership")
    primary = next((m for m in p.memberships if m.workspace_id is None), p.memberships[0])
    org = db.get(Organization, primary.org_id)
    workspaces = []
    for ws in db.scalars(select(Workspace).where(Workspace.org_id == org.id).order_by(Workspace.name)):
        ms = [m for m in p.memberships if m.org_id == org.id and m.workspace_id in (None, ws.id)]
        if ms:
            workspaces.append({"id": str(ws.id), "name": ws.name, "role": ms[0].role.label})
    perms = p.permissions([m for m in p.memberships if m.org_id == org.id])  # for navigation only
    if p.user.is_platform_admin:
        perms = perms | {PLATFORM_PERMISSION}  # an operator who was also invited into an org keeps both
    return {**base, "role": primary.role.label, "organization": {"id": str(org.id), "name": org.name},
            "workspaces": workspaces, "permissions": sorted(perms)}


@router.post("/logout", dependencies=[Depends(csrf_origin_check)])
def logout(request: Request, response: Response, db: Session = Depends(get_db)):
    token = request.cookies.get(COOKIE)
    if token and (sess := db.get(AuthSession, hash_token(token))):
        sess.revoked_at = datetime.now(UTC)
        db.commit()
        audit.record(db, "auth.logout", actor_id=sess.user_id)
    response.delete_cookie(COOKIE, path="/")
    return {"ok": True}




class ChangePasswordBody(BaseModel):
    currentPassword: str = Field(max_length=1024)
    newPassword: str = Field(min_length=12, max_length=1024)


@router.post("/change-password", dependencies=[Depends(csrf_origin_check)])
def change_password(body: ChangePasswordBody, request: Request, p: Principal = Depends(current_principal),
                    db: Session = Depends(get_db)):
    if not verify_password(p.user.password_hash, body.currentPassword):
        audit.record(db, "auth.password_change", actor_id=p.user.id, outcome="failure")
        raise HTTPException(401, "invalid_credentials")
    if body.newPassword == body.currentPassword:
        raise HTTPException(422, "password_unchanged")
    p.user.password_hash = hash_password(body.newPassword)
    p.user.must_change_password = False
    keep = hash_token(request.cookies.get(COOKIE, ""))
    for sess in db.scalars(select(AuthSession).where(AuthSession.user_id == p.user.id,
                                                      AuthSession.revoked_at.is_(None))):
        if sess.id_hash != keep:  # sign out every other device
            sess.revoked_at = datetime.now(UTC)
    db.commit()
    audit.record(db, "auth.password_change", actor_id=p.user.id,
                 org_id=p.memberships[0].org_id if p.memberships else None)
    return {"ok": True}
