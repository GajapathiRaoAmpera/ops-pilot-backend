import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from sqlalchemy.orm import Session

from app.routers import (
    actions,
    auth,
    cloud,
    governance,
    integrations,
    investigations,
    invitations,
    members,
    pipelines,
    platform,
    webhooks,
)

log = logging.getLogger("opspilot")


@asynccontextmanager
async def lifespan(_: FastAPI):
    """Refuse unsafe production settings, then keep role permissions in step with the code (idempotent)."""
    from app.config import get_settings

    settings = get_settings()
    if settings.environment == "production":
        problems = settings.production_problems()
        if problems:
            raise RuntimeError("Refusing to start in production: " + "; ".join(problems))
    try:
        from app.db import get_engine
        from app.rbac import seed_roles

        with Session(get_engine()) as db:
            seed_roles(db)
    except Exception:  # never block startup; the DB may be migrating or briefly unreachable
        log.exception("role permission sync skipped")
    yield


app = FastAPI(title="OpsPilot API", version="0.6.0", lifespan=lifespan)
app.include_router(auth.router)
app.include_router(members.router)
app.include_router(invitations.router)
app.include_router(platform.router)
app.include_router(pipelines.router)
app.include_router(actions.router)
app.include_router(integrations.router)
app.include_router(cloud.router)
app.include_router(investigations.router)
app.include_router(investigations.fixes)
app.include_router(governance.router)
app.include_router(webhooks.router)


@app.get("/healthz", tags=["system"])
def healthz() -> dict[str, str]:
    """Liveness only; no dependency checks and no tenant data."""
    return {"status": "ok"}
