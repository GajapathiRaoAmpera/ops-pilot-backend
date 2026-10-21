"""Bootstrap only. Run: PYTHONPATH=. uv run python scripts/seed.py

Always: creates/updates roles and permissions (idempotent).
If OPSPILOT_BOOTSTRAP_PLATFORM_ADMIN_EMAIL is set and no platform admin exists: creates ONE platform
admin with a generated temporary password (printed once; must be changed at first sign-in).
The platform admin then creates organizations (each gets an invitation link for its first admin),
and org admins invite everyone else. No demo users, no organizations, no shared passwords.
"""
import os
import secrets

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import get_engine
from app.models import User
from app.rbac import seed_roles
from app.security import hash_password

with Session(get_engine()) as db:
    roles = seed_roles(db)
    print(f"Roles ready: {', '.join(sorted(roles))}")
    email = (os.environ.get("OPSPILOT_BOOTSTRAP_PLATFORM_ADMIN_EMAIL") or "").strip().lower()
    if not email:
        print("No OPSPILOT_BOOTSTRAP_PLATFORM_ADMIN_EMAIL set: roles only.")
    elif db.scalar(select(User).where(User.is_platform_admin.is_(True))) is not None:
        print("A platform admin already exists: not creating another.")
    elif db.scalar(select(User).where(User.email == email)) is not None:
        print("That email already has an account: not modifying it.")
    else:
        temp = secrets.token_urlsafe(14)
        db.add(User(email=email, name="Platform Administrator", password_hash=hash_password(temp),
                    is_platform_admin=True, must_change_password=True))
        db.commit()
        print(f"Created platform admin {email}\nTemporary password (shown once): {temp}")
