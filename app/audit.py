import uuid

from sqlalchemy.orm import Session

from app.models import AuditEvent


def record(
    db: Session,
    action: str,
    *,
    actor_id: uuid.UUID | None = None,
    org_id: uuid.UUID | None = None,
    workspace_id: uuid.UUID | None = None,
    resource: str = "",
    outcome: str = "success",
    detail: str = "",
) -> None:
    """Never pass secrets or credentials in `detail`."""
    db.add(AuditEvent(action=action, actor_id=actor_id, org_id=org_id, workspace_id=workspace_id,
                      resource=resource, outcome=outcome, detail=detail[:1000]))
    db.commit()
