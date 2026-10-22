import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from fastapi import Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import Settings, get_settings
from app.db import get_db
from app.models import AuthSession, Membership, Organization, User, Workspace
from app.security import hash_token

COOKIE = "opspilot_session"
# UI hints for the active organization / workspace. Never trusted: always checked against the user's memberships.
ORG_COOKIE = "opspilot_org"
WS_COOKIE = "opspilot_ws"
UNSAFE = {"POST", "PUT", "PATCH", "DELETE"}
PASSWORD_CHANGE_OK = {"/auth/me", "/auth/logout", "/auth/change-password"}


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
    # Set by require_permission: the one organization an org-level request acts on.
    active_org: uuid.UUID | None = None

    def org_ids(self) -> set[uuid.UUID]:
        return {m.org_id for m in self.memberships}

    def org_wide_permissions(self, org_id: uuid.UUID) -> set[str]:
        """Org-wide memberships IN THIS ORG only. Workspace roles, and rights in other orgs, never count."""
        return self.permissions([m for m in self.memberships if m.workspace_id is None and m.org_id == org_id])

    def permissions(self, memberships: list[Membership] | None = None) -> set[str]:
        ms = self.memberships if memberships is None else memberships
        if self.user.is_platform_admin:
            return set()  # platform operators govern tenants from /platform; they never act inside one
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
    if user.must_change_password and request.url.path not in PASSWORD_CHANGE_OK:
        raise HTTPException(403, "password_change_required")
    return Principal(user, usable_memberships(db, user.id))


def usable_memberships(db: Session, user_id: uuid.UUID) -> list[Membership]:
    """Memberships that grant access right now: not blocked, in an organization that is active.
    Blocking takes effect on the very next request, even for sessions that are already open."""
    return list(db.scalars(select(Membership).join(Organization, Organization.id == Membership.org_id).where(
        Membership.user_id == user_id, Membership.blocked.is_(False), Organization.status == "active")))


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def resolve_org(p: Principal, request: Request, db: Session) -> uuid.UUID | None:
    """The organization the user is working in: the cookie hint if they belong to it, else a stable default
    (an org where they hold an org-wide role first, then by name). None when they belong to no organization."""
    ids = p.org_ids()
    if not ids:
        return None
    wanted = request.cookies.get(ORG_COOKIE)
    try:
        if wanted and uuid.UUID(wanted) in ids:
            return uuid.UUID(wanted)
    except ValueError:
        pass
    org_wide = {m.org_id for m in p.memberships if m.workspace_id is None}
    orgs = db.scalars(select(Organization).where(Organization.id.in_(ids))).all()
    return min(orgs, key=lambda o: (o.id not in org_wide, o.name.lower(), str(o.id))).id


def require_permission(permission: str):
    """Org-level permission check, scoped to the active organization only."""

    def dep(request: Request, p: Principal = Depends(current_principal), db: Session = Depends(get_db)) -> Principal:
        org = resolve_org(p, request, db)
        if org is None or permission not in p.org_wide_permissions(org):
            raise HTTPException(403, "forbidden")
        p.active_org = org
        return p

    return dep


def require_platform_admin(p: Principal = Depends(current_principal)) -> Principal:
    if not p.user.is_platform_admin:
        raise HTTPException(403, "forbidden")
    return p


@dataclass
class WorkspaceAccess:
    principal: Principal
    workspace: Workspace
    permissions: set[str]  # what this user may do in THIS workspace


def workspace_access(permission: str, *also: str):
    """Workspace-scoped check. Out-of-scope workspaces return 404 (no existence leak);
    in-scope but holding none of the permissions returns 403. Extra permissions are alternatives (any one is enough)."""
    accepted = {permission, *also}

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
        granted = p.permissions(applicable)
        if not accepted & granted:
            raise HTTPException(403, "forbidden")
        return WorkspaceAccess(p, ws, granted)

    return dep
