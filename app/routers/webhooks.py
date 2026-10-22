import hashlib
import hmac
import json

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import Settings, get_settings
from app.db import get_db
from app.integrations.github import run_from_api, valid_repo
from app.models import Repository
from app.routers.pipelines import upsert_run

router = APIRouter(tags=["webhooks"])


@router.post("/webhooks/github")
async def github_webhook(request: Request, db: Session = Depends(get_db),
                         settings: Settings = Depends(get_settings)):
    secret = settings.github_webhook_secret
    if not secret:
        raise HTTPException(503, "webhook_not_configured")
    body = await request.body()
    expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, request.headers.get("x-hub-signature-256", "")):
        raise HTTPException(401, "bad_signature")
    if request.headers.get("x-github-event") != "workflow_run":
        return {"ignored": True}
    payload = json.loads(body)
    repo = (payload.get("repository") or {}).get("full_name", "")
    run = payload.get("workflow_run")
    if not run or not valid_repo(repo):
        raise HTTPException(400, "bad_payload")
    updated = 0
    for row in db.scalars(select(Repository).where(Repository.provider == "github", Repository.full_name == repo)):
        upsert_run(db, row, run_from_api(run))
        updated += 1
    db.commit()
    return {"updated": updated}
