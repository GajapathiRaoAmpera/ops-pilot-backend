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
    # active | suspended (blocked: nobody inside has access) | archived ("deleted": blocked and hidden, data kept)
    status: Mapped[str] = mapped_column(String(16), default="active", server_default="active")
    status_changed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


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
    is_platform_admin: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")


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
    # Blocked by an admin: the membership stays (so it can be unblocked) but grants nothing.
    blocked: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")


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
    secret_ciphertext: Mapped[str | None] = mapped_column(Text, nullable=True)  # Fernet; never returned by the API
    updated_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class CloudConnection(Base):
    """An organization's read-only cloud account (one per provider). The key is Fernet-encrypted, never returned."""
    __tablename__ = "cloud_connections"
    __table_args__ = (UniqueConstraint("org_id", "provider"),)
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_id)
    org_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("opspilot.organizations.id"), index=True)
    provider: Mapped[str] = mapped_column(String(32))
    config: Mapped[dict] = mapped_column(JSON, default=dict)  # non-secret, e.g. {"projectId", "clientEmail"}
    secret_ciphertext: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Repository(Base):
    """A repository a workspace tracks. Uses its own token when set, otherwise the workspace's shared one."""
    __tablename__ = "repositories"
    __table_args__ = (UniqueConstraint("workspace_id", "provider", "full_name"),)
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_id)
    org_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("opspilot.organizations.id"))
    workspace_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("opspilot.workspaces.id"), index=True)
    provider: Mapped[str] = mapped_column(String(32), default="github")
    full_name: Mapped[str] = mapped_column(String(200), index=True)  # owner/name
    secret_ciphertext: Mapped[str | None] = mapped_column(Text, nullable=True)  # Fernet; never returned
    last_synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))


class Investigation(Base):
    """An AI diagnosis of one run. Advisory only: it can suggest an allowlisted action, never run one."""
    __tablename__ = "investigations"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_id)
    org_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("opspilot.organizations.id"))
    workspace_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("opspilot.workspaces.id"), index=True)
    run_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("opspilot.pipeline_runs.id"), index=True)
    summary: Mapped[str] = mapped_column(Text, default="")
    root_cause: Mapped[str] = mapped_column(Text, default="")
    confidence: Mapped[str] = mapped_column(String(16), default="low")
    evidence: Mapped[list] = mapped_column(JSON, default=list)  # [{"quote", "why"}], quotes verified against the log
    evidence_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    next_steps: Mapped[list] = mapped_column(JSON, default=list)
    suggested_action: Mapped[str] = mapped_column(String(64), default="none")  # allowlist: rerun_failed_jobs | none
    suggestion_reason: Mapped[str] = mapped_column(Text, default="")
    model: Mapped[str] = mapped_column(String(100), default="")
    created_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("opspilot.users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC), index=True)


class FixProposal(Base):
    """A code change proposed by the fix agent. Nothing reaches GitHub until a different person approves it."""
    __tablename__ = "fix_proposals"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_id)
    org_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("opspilot.organizations.id"))
    workspace_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("opspilot.workspaces.id"), index=True)
    run_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("opspilot.pipeline_runs.id"), index=True)
    status: Mapped[str] = mapped_column(String(16))  # proposed | no_fix
    title: Mapped[str] = mapped_column(String(200), default="")
    explanation: Mapped[str] = mapped_column(Text, default="")
    files: Mapped[list] = mapped_column(JSON, default=list)  # [{"path", "blobSha", "newText"}]
    diff: Mapped[str] = mapped_column(Text, default="")
    base_branch: Mapped[str] = mapped_column(String(200), default="")
    base_sha: Mapped[str] = mapped_column(String(40), default="")
    model: Mapped[str] = mapped_column(String(100), default="")
    trace: Mapped[list] = mapped_column(JSON, default=list)  # what the agent did, step by step (no file contents)
    created_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("opspilot.users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC), index=True)


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
    type: Mapped[str] = mapped_column(String(64))  # allowlisted: rerun_failed_jobs | open_fix_pr
    risk: Mapped[str] = mapped_column(String(16))
    # pending | rejected | approved | executing | succeeded | failed
    status: Mapped[str] = mapped_column(String(16), default="pending", index=True)
    reason: Mapped[str] = mapped_column(String(1000), default="")
    requested_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("opspilot.users.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    proposal_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("opspilot.fix_proposals.id"), nullable=True)


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


class Invitation(Base):
    """Single-use, expiring link. kind=invite adds a membership; kind=reset sets a new password."""

    __tablename__ = "invitations"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=_id)
    kind: Mapped[str] = mapped_column(String(16), default="invite")  # invite | reset
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    org_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("opspilot.organizations.id"), index=True)
    workspace_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("opspilot.workspaces.id"), nullable=True)
    role_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("opspilot.roles.id"), nullable=True)
    email: Mapped[str] = mapped_column(String(320))
    user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("opspilot.users.id"), nullable=True)  # reset only
    invited_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("opspilot.users.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    accepted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
