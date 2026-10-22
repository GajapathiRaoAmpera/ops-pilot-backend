"""Member administration inside one organization, shared by Organization Administrators (/org/*) and
Platform Administrators (/platform/organizations/{id}/*), so both follow exactly the same rules.

`org_id` is always the organization being administered, already authorised by the caller.
"""
import uuid
from datetime import UTC, datetime

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit
from app.models import AuthSession, Membership, Role, User, Workspace
from app.onboarding import create_invitation
from app.rbac import ROLES, WORKSPACE_ROLES


def member_dto(m: Membership, user: User, ws_name: str | None) -> dict:
    return {"membershipId": str(m.id), "userId": str(user.id), "email": user.email, "name": user.name,
            "role": m.role.key, "roleLabel": m.role.label, "workspaceId": str(m.workspace_id) if m.workspace_id else None,
            "workspace": ws_name, "disabled": user.disabled, "blocked": m.blocked}


def list_members(db: Session, org_id: uuid.UUID) -> list[dict]:
    rows = db.execute(select(Membership, User, Workspace.name).join(User, User.id == Membership.user_id)
                      .outerjoin(Workspace, Workspace.id == Membership.workspace_id)
                      .where(Membership.org_id == org_id).order_by(User.email)).all()
    return [member_dto(m, u, wn) for m, u, wn in rows]


def org_admin_count(db: Session, org_id: uuid.UUID) -> int:
    """Organization admins who can actually act: active account, membership not blocked."""
    rows = db.execute(select(Membership, User).join(User, User.id == Membership.user_id).where(
        Membership.org_id == org_id, Membership.workspace_id.is_(None), Membership.blocked.is_(False),
        User.disabled.is_(False))).all()
    return sum(1 for m, _ in rows if m.role.key == "org_admin")


def role_by_key(db: Session, key: str) -> Role:
    if key not in ROLES:
        raise HTTPException(422, "unknown_role")
    return db.scalar(select(Role).where(Role.key == key))


def revoke_sessions(db: Session, user_id: uuid.UUID) -> None:
    for s in db.scalars(select(AuthSession).where(AuthSession.user_id == user_id, AuthSession.revoked_at.is_(None))):
        s.revoked_at = datetime.now(UTC)


def membership_in(db: Session, org_id: uuid.UUID, mid: uuid.UUID) -> Membership:
    m = db.get(Membership, mid)
    if m is None or m.org_id != org_id:
        raise HTTPException(404, "not_found")
    return m


def _is_last_admin(db: Session, m: Membership) -> bool:
    return m.workspace_id is None and m.role.key == "org_admin" and not m.blocked and org_admin_count(db, m.org_id) <= 1


def change_role(db: Session, org_id: uuid.UUID, mid: uuid.UUID, role: str, actor: User) -> Membership:
    m = membership_in(db, org_id, mid)
    if m.user_id == actor.id:
        raise HTTPException(409, "cannot_change_own_role")
    if m.workspace_id and role not in WORKSPACE_ROLES:
        raise HTTPException(422, "role_not_allowed_for_workspace")
    new = role_by_key(db, role)
    if role != "org_admin" and _is_last_admin(db, m):
        raise HTTPException(409, "last_org_admin")
    m.role_id = new.id
    db.commit()
    db.refresh(m)
    audit.record(db, "member.role_changed", actor_id=actor.id, org_id=m.org_id, workspace_id=m.workspace_id,
                 resource=f"user:{m.user_id}", detail=f"role={role}")
    return m


def remove_membership(db: Session, org_id: uuid.UUID, mid: uuid.UUID, actor: User) -> None:
    m = membership_in(db, org_id, mid)
    if m.user_id == actor.id:
        raise HTTPException(409, "cannot_remove_self")
    if _is_last_admin(db, m):
        raise HTTPException(409, "last_org_admin")
    ws_id, uid = m.workspace_id, m.user_id
    db.delete(m)
    db.commit()
    audit.record(db, "member.removed", actor_id=actor.id, org_id=org_id, workspace_id=ws_id, resource=f"user:{uid}")


def set_blocked(db: Session, org_id: uuid.UUID, user_id: uuid.UUID, blocked: bool, actor: User) -> int:
    """Blocks (or unblocks) a person in this organization: all their memberships here grant nothing while blocked.
    Their account and other organizations are untouched. Returns how many memberships changed."""
    if user_id == actor.id:
        raise HTTPException(409, "cannot_block_self")
    ms = list(db.scalars(select(Membership).where(Membership.user_id == user_id, Membership.org_id == org_id)))
    if not ms:
        raise HTTPException(404, "not_found")
    if blocked and any(_is_last_admin(db, m) for m in ms):
        raise HTTPException(409, "last_org_admin")
    for m in ms:
        m.blocked = blocked
    db.commit()
    audit.record(db, "member.blocked" if blocked else "member.unblocked", actor_id=actor.id, org_id=org_id,
                 resource=f"user:{user_id}")
    return len(ms)


def in_other_orgs(db: Session, user_id: uuid.UUID, org_id: uuid.UUID) -> bool:
    return db.scalar(select(Membership).where(Membership.user_id == user_id, Membership.org_id != org_id).limit(1)) is not None


def issue_reset_link(db: Session, org_id: uuid.UUID, user_id: uuid.UUID, actor: User, *, platform: bool) -> dict:
    """A single-use link that lets the person set a new password; nobody else ever sees or sets it.
    An organization admin may not reset someone who also belongs to another organization (the reset would unlock
    that organization too); a platform admin, who is above all organizations, may."""
    in_org = db.scalar(select(Membership).where(Membership.user_id == user_id, Membership.org_id == org_id))
    user = db.get(User, user_id) if in_org else None
    if user is None or (user.is_platform_admin and not platform):
        raise HTTPException(404, "not_found")
    if user.id == actor.id:
        raise HTTPException(409, "use_change_password")  # your own password: change it while signed in
    if not platform and in_other_orgs(db, user_id, org_id):
        raise HTTPException(409, "user_in_other_organizations")
    inv, token = create_invitation(db, kind="reset", org_id=org_id, email=user.email, invited_by=actor.id, user_id=user.id)
    audit.record(db, "member.reset_link_issued", actor_id=actor.id, org_id=org_id, resource=f"user:{user.id}",
                 detail="by platform administrator" if platform else "")
    return {"token": token, "expiresAt": inv.expires_at.isoformat()}


def already_member(db: Session, org_id: uuid.UUID, workspace_id: uuid.UUID | None, email: str) -> bool:
    user = db.scalar(select(User).where(User.email == email))
    if user is None:
        return False
    q = select(Membership).where(Membership.user_id == user.id, Membership.org_id == org_id)
    q = q.where(Membership.workspace_id.is_(None) if workspace_id is None else Membership.workspace_id == workspace_id)
    return db.scalar(q) is not None


def invite(db: Session, org_id: uuid.UUID, email: str, role: str, workspace_id: uuid.UUID | None, actor: User):
    """Invitation for any role (organization-wide, or one workspace). Returns (invitation, token)."""
    email = email.strip().lower()
    if role not in ROLES:
        raise HTTPException(422, "unknown_role")
    if workspace_id is not None:
        ws = db.get(Workspace, workspace_id)
        if ws is None or ws.org_id != org_id:
            raise HTTPException(404, "not_found")
        if role not in WORKSPACE_ROLES:
            raise HTTPException(422, "role_not_allowed_for_workspace")
    if already_member(db, org_id, workspace_id, email):
        raise HTTPException(409, "already_member")
    inv, token = create_invitation(db, kind="invite", org_id=org_id, email=email, invited_by=actor.id,
                                   role_key=role, workspace_id=workspace_id)
    audit.record(db, "invitation.created", actor_id=actor.id, org_id=org_id, workspace_id=workspace_id,
                 resource=f"invitation:{inv.id}", detail=f"role={role}")
    return inv, token
