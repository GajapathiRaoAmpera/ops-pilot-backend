"""Dev seed: one org, one workspace, one user per MVP role. Run: PYTHONPATH=. uv run python scripts/seed.py

Passwords come from OPSPILOT_SEED_PASSWORD, or are generated and printed once. Local development only.
Set OPSPILOT_SEED_GITHUB_REPO=owner/name to connect the demo workspace to a repository.
"""
import os
import secrets

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import get_engine
from app.models import Integration, Membership, Organization, User, Workspace
from app.rbac import seed_roles
from app.security import hash_password

USERS = {
    "admin@opspilot.local": ("Org Admin", "org_admin"),
    "devops@opspilot.local": ("DevOps Engineer", "devops_engineer"),
    "auditor@opspilot.local": ("Security Auditor", "security_auditor"),
    "viewer@opspilot.local": ("Viewer", "viewer"),
}

with Session(get_engine()) as db:
    roles = seed_roles(db)
    org = db.scalar(select(Organization).where(Organization.name == "Demo Org"))
    if org is None:
        org = Organization(name="Demo Org")
        db.add(org)
        db.flush()
        ws = Workspace(org_id=org.id, name="Demo Workspace")
        db.add(ws)
        db.flush()
        repo = os.environ.get("OPSPILOT_SEED_GITHUB_REPO")
        if repo:
            db.add(Integration(org_id=org.id, workspace_id=ws.id, provider="github", config={"repo": repo}))
        password = os.environ.get("OPSPILOT_SEED_PASSWORD") or secrets.token_urlsafe(12)
        for email, (name, role) in USERS.items():
            u = User(email=email, name=name, password_hash=hash_password(password))
            db.add(u)
            db.flush()
            db.add(Membership(user_id=u.id, org_id=org.id, role_id=roles[role].id))
        db.commit()
        print(f"Seeded. Users: {', '.join(USERS)}  Password: {password}")
    else:
        print("Already seeded.")
