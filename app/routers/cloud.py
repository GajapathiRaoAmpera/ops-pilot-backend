"""Per-workspace Google Cloud connection (read-only). Organization administrators only.

The service-account key is write-only: stored encrypted, never returned. Nothing here changes a cloud resource.
"""
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit
from app.config import Settings, get_settings
from app.crypto import SecretKeyMissing, decrypt, encrypt
from app.db import get_db
from app.deps import WorkspaceAccess, csrf_origin_check, workspace_access
from app.integrations.gcp import GcpClient, GcpError, parse_key
from app.models import Integration
from app.rbac import P

router = APIRouter(prefix="/workspaces/{ws_id}/cloud/gcp", tags=["cloud"])
MANAGE = workspace_access(P["cloud_manage"])
PROVIDER = "gcp"


class ConnectBody(BaseModel):
    key: str = Field(min_length=50, max_length=10_000)  # the service-account JSON file's contents


def get_transport():
    return None  # tests override this with a mock transport


def _row(db: Session, acc: WorkspaceAccess) -> Integration | None:
    return db.scalar(select(Integration).where(Integration.workspace_id == acc.workspace.id,
                                               Integration.provider == PROVIDER))


def _status(row: Integration | None) -> dict:
    cfg = (row.config or {}) if row else {}
    return {"connected": row is not None, "projectId": cfg.get("projectId"), "serviceAccount": cfg.get("clientEmail"),
            "keySet": bool(row and row.secret_ciphertext)}


def _ctx(acc: WorkspaceAccess) -> dict:
    return {"actor_id": acc.principal.user.id, "org_id": acc.workspace.org_id, "workspace_id": acc.workspace.id}


def _client(row: Integration, settings: Settings, transport) -> GcpClient:
    plain = decrypt(settings, row.secret_ciphertext) if row.secret_ciphertext else None
    if not plain:
        raise HTTPException(409, "key_unreadable")
    try:
        return GcpClient(parse_key(plain), (row.config or {})["projectId"], transport)
    except GcpError as exc:
        raise HTTPException(409, "key_unreadable") from exc


@router.get("")
def get_status(acc: WorkspaceAccess = Depends(MANAGE), db: Session = Depends(get_db)):
    return _status(_row(db, acc))


@router.put("", dependencies=[Depends(csrf_origin_check)])
def connect(body: ConnectBody, acc: WorkspaceAccess = Depends(MANAGE), db: Session = Depends(get_db),
            settings: Settings = Depends(get_settings)):
    try:
        key = parse_key(body.key)
    except GcpError as exc:
        raise HTTPException(422, "invalid_key") from exc
    try:
        cipher = encrypt(settings, body.key)
    except SecretKeyMissing as exc:
        raise HTTPException(503, "encryption_not_configured") from exc
    row = _row(db, acc)
    if row is None:
        row = Integration(org_id=acc.workspace.org_id, workspace_id=acc.workspace.id, provider=PROVIDER, config={})
        db.add(row)
    row.secret_ciphertext = cipher
    row.config = {"projectId": key["project_id"], "clientEmail": key["client_email"]}
    row.updated_by, row.updated_at = acc.principal.user.id, datetime.now(UTC)
    db.commit()
    audit.record(db, "cloud.gcp.connected", resource=f"project:{key['project_id']}", **_ctx(acc))
    return _status(row)


@router.delete("", dependencies=[Depends(csrf_origin_check)])
def disconnect(acc: WorkspaceAccess = Depends(MANAGE), db: Session = Depends(get_db)):
    row = _row(db, acc)
    if row is None:
        raise HTTPException(404, "not_found")
    project = (row.config or {}).get("projectId", "")
    db.delete(row)
    db.commit()
    audit.record(db, "cloud.gcp.disconnected", resource=f"project:{project}", **_ctx(acc))
    return {"connected": False}


@router.post("/test", dependencies=[Depends(csrf_origin_check)])
def test_connection(acc: WorkspaceAccess = Depends(MANAGE), db: Session = Depends(get_db),
                    settings: Settings = Depends(get_settings), transport=Depends(get_transport)):
    row = _row(db, acc)
    if row is None:
        raise HTTPException(409, "integration_not_connected")
    try:
        info = _client(row, settings, transport).project()
    except GcpError as exc:
        audit.record(db, "cloud.gcp.test", outcome="failure", detail=str(exc), **_ctx(acc))
        return {"ok": False, "reason": str(exc)}
    audit.record(db, "cloud.gcp.test", **_ctx(acc))
    return {"ok": True, "project": info}


@router.get("/inventory")
def inventory(acc: WorkspaceAccess = Depends(MANAGE), db: Session = Depends(get_db),
              settings: Settings = Depends(get_settings), transport=Depends(get_transport)):
    row = _row(db, acc)
    if row is None:
        raise HTTPException(409, "integration_not_connected")
    client = _client(row, settings, transport)
    out: dict = {"projectId": client.project_id, "fetchedAt": datetime.now(UTC).isoformat(), "errors": {}}
    for name, fn in (("compute", client.compute), ("cloudRun", client.cloud_run), ("gke", client.gke)):
        try:
            out[name] = fn()
        except GcpError as exc:  # one API being disabled must not hide the others
            out[name], out["errors"][name] = [], str(exc)
    row.last_synced_at = datetime.now(UTC)
    db.commit()
    audit.record(db, "cloud.gcp.inventory", resource=f"project:{client.project_id}", **_ctx(acc))
    return out
