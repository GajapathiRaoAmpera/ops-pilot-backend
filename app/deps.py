import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from fastapi import Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import Settings, get_settings
from app.db import get_db
from app.models import AuthSession, Membership, User, Workspace
from app.security import hash_token

COOKIE = "opspilot_session"
UNSAFE = {"POST", "PUT", "PATCH", "DELETE"}


def csrf_origin_check(request: Request, settings: Settings = Depends(get_settings)) -> None:
    """Browsers always send Origin on cross-site unsafe requests; reject any that is not allowed.
    A missing Origin (server-to-server relay, curl) is not a CSRF vector. Cookie is also SameSite=Lax."""
    if request.method in UNSAFE:
        origin = request.headers.get("origin")
        if origin is not None and origin not in settings.allowed_origins:
            raise HTTPException(403, "forbidden_origin")


@dataclass
class Principal:
    user: User
    memberships: list[Membership]

    def permissions(self, memberships: list[Membership] | None = None) -> set[str]:
        ms = self.memberships if memberships is None else memberships
        return {rp.permission for m in ms for rp in m.role.permissions}


def current_principal(request: Request, db: Session = Depends(get_db)) -> Principal:
    token = request.cookies.get(COOKIE)
    if not token:
        raise HTTPException(401, "unauthenticated")
    sess = db.get(AuthSession, hash_token(token))
    now = datetime.now(UTC)
    if sess is None or sess.revoked_at is not None or _aware(sess.expires_at) <= now:
        raise HTTPException(401, "unauthenticated")
    user = db.get(User, sess.user_id)
    if user is None or user.disabled:
        raise HTTPException(401, "unauthenticated")
    ms = list(db.scalars(select(Membership).where(Membership.user_id == user.id)))
    return Principal(user, ms)


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def require_permission(permission: str):
    """Org-level permission check (union across the user's memberships)."""

    def dep(p: Principal = Depends(current_principal)) -> Principal:
        if permission not in p.permissions():
            raise HTTPException(403, "forbidden")
        return p

    return dep


@dataclass
class WorkspaceAccess:
    principal: Principal
    workspace: Workspace


def workspace_access(permission: str):
    """Workspace-scoped check. Out-of-scope workspaces return 404 (no existence leak);
    in-scope but lacking the permission returns 403."""

    def dep(
        ws_id: uuid.UUID,
        p: Principal = Depends(current_principal),
        db: Session = Depends(get_db),
    ) -> WorkspaceAccess:
        ws = db.get(Workspace, ws_id)
        applicable = [
            m for m in p.memberships
            if ws is not None and m.org_id == ws.org_id and m.workspace_id in (None, ws.id)
        ]
        if ws is None or not applicable:
            raise HTTPException(404, "not_found")
        if permission not in p.permissions(applicable):
            raise HTTPException(403, "forbidden")
        return WorkspaceAccess(p, ws)

    return dep
