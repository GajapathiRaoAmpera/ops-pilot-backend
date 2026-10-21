import uuid
from datetime import UTC, datetime

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base


def _now() -> datetime:
    return datetime.now(UTC)


def _id() -> uuid.UUID:
    return uuid.uuid4()


class Organization(Base):
    __tablename__ = "organizations"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_id)
    name: Mapped[str] = mapped_column(String(200))


class Workspace(Base):
    __tablename__ = "workspaces"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_id)
    org_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("opspilot.organizations.id"), index=True)
    name: Mapped[str] = mapped_column(String(200))


class User(Base):
    __tablename__ = "users"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_id)
    email: Mapped[str] = mapped_column(String(320), unique=True)
    name: Mapped[str] = mapped_column(String(200))
    password_hash: Mapped[str] = mapped_column(String(255))
    disabled: Mapped[bool] = mapped_column(Boolean, default=False)


class Role(Base):
    __tablename__ = "roles"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_id)
    key: Mapped[str] = mapped_column(String(64), unique=True)
    label: Mapped[str] = mapped_column(String(100))
    permissions: Mapped[list["RolePermission"]] = relationship(lazy="selectin")


class RolePermission(Base):
    __tablename__ = "role_permissions"
    role_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("opspilot.roles.id"), primary_key=True)
    permission: Mapped[str] = mapped_column(String(100), primary_key=True)


class Membership(Base):
    """workspace_id NULL means org-wide membership."""

    __tablename__ = "memberships"
    __table_args__ = (UniqueConstraint("user_id", "org_id", "workspace_id"),)
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_id)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("opspilot.users.id"), index=True)
    org_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("opspilot.organizations.id"))
    workspace_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("opspilot.workspaces.id"), nullable=True)
    role_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("opspilot.roles.id"))
    role: Mapped[Role] = relationship(lazy="joined")


class AuthSession(Base):
    __tablename__ = "sessions"
    id_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("opspilot.users.id"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Integration(Base):
    __tablename__ = "integrations"
    __table_args__ = (UniqueConstraint("workspace_id", "provider"),)
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_id)
    org_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("opspilot.organizations.id"))
    workspace_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("opspilot.workspaces.id"), index=True)
    provider: Mapped[str] = mapped_column(String(32))
    config: Mapped[dict] = mapped_column(JSON, default=dict)  # non-secret, e.g. {"repo": "owner/name"}
    last_synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class PipelineRun(Base):
    __tablename__ = "pipeline_runs"
    __table_args__ = (UniqueConstraint("workspace_id", "provider", "external_id"),)
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_id)
    org_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("opspilot.organizations.id"))
    workspace_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("opspilot.workspaces.id"), index=True)
    provider: Mapped[str] = mapped_column(String(32))
    external_id: Mapped[str] = mapped_column(String(64))
    repo: Mapped[str] = mapped_column(String(200))
    workflow: Mapped[str] = mapped_column(String(200))
    branch: Mapped[str] = mapped_column(String(200), default="")
    commit_sha: Mapped[str] = mapped_column(String(64), default="")
    status: Mapped[str] = mapped_column(String(32))  # queued | in_progress | completed
    conclusion: Mapped[str | None] = mapped_column(String(32), nullable=True)
    html_url: Mapped[str] = mapped_column(String(500), default="")
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class AuditEvent(Base):
    """Append-only: the application never updates or deletes rows."""

    __tablename__ = "audit_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, index=True)
    org_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True, index=True)
    workspace_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    actor_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    action: Mapped[str] = mapped_column(String(100))
    resource: Mapped[str] = mapped_column(String(200), default="")
    outcome: Mapped[str] = mapped_column(String(20), default="success")
    detail: Mapped[str] = mapped_column(Text, default="")


class ActionRequest(Base):
    """A proposed write action. Nothing executes without an approval by a different user."""

    __tablename__ = "action_requests"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_id)
    org_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("opspilot.organizations.id"))
    workspace_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("opspilot.workspaces.id"), index=True)
    run_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("opspilot.pipeline_runs.id"))
    type: Mapped[str] = mapped_column(String(64))  # allowlisted: rerun_failed_jobs
    risk: Mapped[str] = mapped_column(String(16))
    # pending | rejected | approved | executing | succeeded | failed
    status: Mapped[str] = mapped_column(String(16), default="pending", index=True)
    reason: Mapped[str] = mapped_column(String(1000), default="")
    requested_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("opspilot.users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class Approval(Base):
    __tablename__ = "approvals"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_id)
    request_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("opspilot.action_requests.id"), unique=True)
    decided_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("opspilot.users.id"))
    decision: Mapped[str] = mapped_column(String(16))  # approve | reject
    reason: Mapped[str] = mapped_column(String(1000), default="")
    decided_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)


class Execution(Base):
    __tablename__ = "executions"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_id)
    request_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("opspilot.action_requests.id"), unique=True)
    idempotency_key: Mapped[str] = mapped_column(String(128), unique=True)
    status: Mapped[str] = mapped_column(String(16))  # executing | succeeded | failed
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    result: Mapped[dict] = mapped_column(JSON, default=dict)
    error: Mapped[str] = mapped_column(String(500), default="")
