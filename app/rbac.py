"""Centralised permission model. Strings match the frontend's features/auth/permissions.ts."""
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Role, RolePermission

P = {
    "overview_read": "sys:overview:read",
    "pipelines_read": "cicd:pipelines:read",
    "pipelines_execute": "cicd:pipelines:execute",
    "automation_read": "auto:runbooks:read",
    "copilot_use": "ai:copilot:use",
    "approvals_read": "approvals:requests:read",
    "approvals_decide": "approvals:requests:approve",
    "rbac_read": "sys:rbac:read",
    "audit_read": "sec:telemetry:audit",
    "settings_read": "sys:settings:read",
    "members_manage": "sys:members:manage",
}

ROLES: dict[str, tuple[str, set[str]]] = {
    "org_admin": ("Organization Administrator", set(P.values())),
    "devops_engineer": (
        "DevOps Engineer",
        {P["overview_read"], P["pipelines_read"], P["pipelines_execute"], P["automation_read"],
         P["copilot_use"], P["approvals_read"], P["settings_read"]},
    ),
    "security_auditor": (
        "Security Auditor",
        {P["overview_read"], P["pipelines_read"], P["approvals_read"], P["rbac_read"], P["audit_read"]},
    ),
    "viewer": ("Viewer", {P["overview_read"], P["pipelines_read"]}),
}


def seed_roles(db: Session) -> dict[str, Role]:
    out: dict[str, Role] = {}
    for key, (label, perms) in ROLES.items():
        role = db.scalar(select(Role).where(Role.key == key))
        if role is None:
            role = Role(key=key, label=label)
            db.add(role)
            db.flush()
        have = {rp.permission for rp in role.permissions}
        for perm in perms - have:
            db.add(RolePermission(role_id=role.id, permission=perm))
        out[key] = role
    db.commit()
    return out
