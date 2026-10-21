# OpsPilot backend

FastAPI control plane. See `docs/` (threat model, data model, API contract, `openapi.json`).

```bash
docker compose up -d db           # Postgres on 127.0.0.1:5433
cp .env.example .env              # add OPSPILOT_GITHUB_TOKEN etc. (never commit)
PYTHONPATH=. uv run alembic upgrade head
OPSPILOT_SEED_GITHUB_REPO=owner/repo PYTHONPATH=. uv run python scripts/seed.py
OPSPILOT_COOKIE_SECURE=false uv run uvicorn app.main:app --port 8000   # secure cookies need HTTPS
uv run pytest
```
