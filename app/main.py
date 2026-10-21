from fastapi import FastAPI

from app.routers import (
    actions,
    auth,
    governance,
    integrations,
    invitations,
    members,
    pipelines,
    platform,
    webhooks,
)

app = FastAPI(title="OpsPilot API", version="0.6.0")
app.include_router(auth.router)
app.include_router(members.router)
app.include_router(invitations.router)
app.include_router(platform.router)
app.include_router(pipelines.router)
app.include_router(actions.router)
app.include_router(integrations.router)
app.include_router(governance.router)
app.include_router(webhooks.router)


@app.get("/healthz", tags=["system"])
def healthz() -> dict[str, str]:
    """Liveness only; no dependency checks and no tenant data."""
    return {"status": "ok"}
