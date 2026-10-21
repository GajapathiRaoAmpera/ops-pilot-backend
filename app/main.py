from fastapi import FastAPI

from app.routers import actions, auth, governance, pipelines, webhooks

app = FastAPI(title="OpsPilot API", version="0.3.0")
app.include_router(auth.router)
app.include_router(pipelines.router)
app.include_router(actions.router)
app.include_router(governance.router)
app.include_router(webhooks.router)


@app.get("/healthz", tags=["system"])
def healthz() -> dict[str, str]:
    """Liveness only; no dependency checks and no tenant data."""
    return {"status": "ok"}
