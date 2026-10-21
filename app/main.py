from fastapi import FastAPI

app = FastAPI(title="OpsPilot API", version="0.1.0")


@app.get("/healthz", tags=["system"])
def healthz() -> dict[str, str]:
    """Liveness only; no dependency checks and no tenant data."""
    return {"status": "ok"}
