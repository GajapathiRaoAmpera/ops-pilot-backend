"""Bootstrap only. Run: PYTHONPATH=. uv run python scripts/seed.py

Always: creates/updates the roles and their permissions (idempotent).
If OPSPILOT_BOOTSTRAP_ADMIN_EMAIL is set and no organization exists: also creates the first
organization (OPSPILOT_BOOTSTRAP_ORG_NAME), one workspace, and ONE admin with a generated temporary
password (printed once; the admin must change it at first sign-in). Everyone else is added by
that admin through the API/UI. No demo users, no shared passwords.
Optional: OPSPILOT_SEED_GITHUB_REPO=owner/name connects the first workspace to a repository.
"""
import os
import secrets

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import get_engine
from app.models import Integration, Membership, Organization, User, Workspace
from app.rbac import seed_roles
from app.security import hash_password

with Session(get_engine()) as db:
    roles = seed_roles(db)
    print(f"Roles ready: {', '.join(sorted(roles))}")
    email = (os.environ.get("OPSPILOT_BOOTSTRAP_ADMIN_EMAIL") or "").strip().lower()
    if not email:
        print("No OPSPILOT_BOOTSTRAP_ADMIN_EMAIL set: roles only.")
    elif db.scalar(select(Organization)) is not None:
        print("An organization already exists: not creating another.")
    else:
        org = Organization(name=os.environ.get("OPSPILOT_BOOTSTRAP_ORG_NAME", "My Organization"))
        db.add(org)
        db.flush()
        ws = Workspace(org_id=org.id, name="Default Workspace")
        db.add(ws)
        db.flush()
        repo = os.environ.get("OPSPILOT_SEED_GITHUB_REPO")
        if repo:
            db.add(Integration(org_id=org.id, workspace_id=ws.id, provider="github", config={"repo": repo}))
        temp = secrets.token_urlsafe(14)
        admin = User(email=email, name=os.environ.get("OPSPILOT_BOOTSTRAP_ADMIN_NAME", "Administrator"),
                     password_hash=hash_password(temp), must_change_password=True)
        db.add(admin)
        db.flush()
        db.add(Membership(user_id=admin.id, org_id=org.id, role_id=roles["org_admin"].id))
        db.commit()
        print(f"Created org '{org.name}' and admin {email}\nTemporary password (shown once): {temp}")
