"""Platform operator: creates tenants. Has NO access to any tenant's operational data."""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app import audit
from app.db import get_db
from app.deps import Principal, csrf_origin_check, require_platform_admin
from app.models import Membership, Organization, Workspace
from app.onboarding import create_invitation

router = APIRouter(prefix="/platform", tags=["platform"])


class OrgBody(BaseModel):
    name: str = Field(min_length=2, max_length=200)
    adminEmail: str = Field(min_length=3, max_length=320, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


@router.post("/organizations", status_code=201, dependencies=[Depends(csrf_origin_check)])
def create_org(body: OrgBody, p: Principal = Depends(require_platform_admin), db: Session = Depends(get_db)):
    name = body.name.strip()
    if db.scalar(select(Organization).where(func.lower(Organization.name) == name.lower())):
        raise HTTPException(409, "organization_exists")
    org = Organization(name=name)
    db.add(org)
    db.flush()
    db.add(Workspace(org_id=org.id, name="Default Workspace"))
    db.commit()
    inv, token = create_invitation(db, kind="invite", org_id=org.id, email=body.adminEmail, invited_by=p.user.id,
                                   role_key="org_admin")
    audit.record(db, "organization.created", actor_id=p.user.id, org_id=org.id, resource=f"org:{org.id}")
    return {"id": str(org.id), "name": org.name, "adminInvitation": {"email": inv.email, "token": token,
            "expiresAt": inv.expires_at.isoformat()}}


@router.get("/organizations")
def list_orgs(_: Principal = Depends(require_platform_admin), db: Session = Depends(get_db)):
    out = []
    for org in db.scalars(select(Organization).order_by(Organization.name)):
        out.append({"id": str(org.id), "name": org.name,
                    "workspaces": db.scalar(select(func.count()).select_from(Workspace).where(Workspace.org_id == org.id)),
                    "members": db.scalar(select(func.count(func.distinct(Membership.user_id))).where(Membership.org_id == org.id))})
    return {"organizations": out}  # counts only: no tenant content
