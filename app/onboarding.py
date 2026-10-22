"""Invitation and reset-link primitives. Tokens are 256-bit random, stored only as SHA-256, single use."""
import secrets
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import Invitation, Organization, Role
from app.security import hash_token


def now() -> datetime:
    return datetime.now(UTC)


def aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def _ttl(kind: str) -> timedelta:
    s = get_settings()
    return timedelta(hours=s.invite_ttl_hours) if kind == "invite" else timedelta(minutes=s.reset_ttl_minutes)


def create_invitation(db: Session, *, kind: str, org_id: uuid.UUID, email: str, invited_by: uuid.UUID | None,
                      role_key: str | None = None, workspace_id: uuid.UUID | None = None,
                      user_id: uuid.UUID | None = None) -> tuple[Invitation, str]:
    """Supersedes any still-pending invitation for the same target. Returns (row, plaintext token)."""
    email = email.strip().lower()
    for old in db.scalars(select(Invitation).where(
            Invitation.org_id == org_id, Invitation.email == email, Invitation.kind == kind,
            Invitation.workspace_id.is_(workspace_id) if workspace_id is None else Invitation.workspace_id == workspace_id,
            Invitation.accepted_at.is_(None), Invitation.revoked_at.is_(None))):
        old.revoked_at = now()
    role_id = db.scalar(select(Role.id).where(Role.key == role_key)) if role_key else None
    token = secrets.token_urlsafe(32)
    inv = Invitation(kind=kind, token_hash=hash_token(token), org_id=org_id, workspace_id=workspace_id,
                     role_id=role_id, email=email, user_id=user_id, invited_by=invited_by,
                     expires_at=now() + _ttl(kind))
    db.add(inv)
    db.commit()
    return inv, token


def find_valid(db: Session, token: str) -> Invitation | None:
    inv = db.scalar(select(Invitation).where(Invitation.token_hash == hash_token(token)))
    if inv is None or inv.accepted_at or inv.revoked_at or aware(inv.expires_at) <= now():
        return None
    if inv.kind == "invite":  # joining a blocked or archived organization must not work through an old link
        org = db.get(Organization, inv.org_id)
        if org is None or org.status != "active":
            return None
    return inv
