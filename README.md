# OpsPilot backend

FastAPI control plane. See `docs/` (threat model, data model, API contract, `openapi.json`).

```bash
docker compose up -d db           # Postgres on 127.0.0.1:5433
cp .env.example .env              # add OPSPILOT_GITHUB_TOKEN etc. (never commit)
PYTHONPATH=. uv run alembic upgrade head
OPSPILOT_SEED_GITHUB_REPO=owner/repo PYTHONPATH=. uv run python scripts/seed.py
OPSPILOT_COOKIE_SECURE=false uv run uvicorn app.main:app --port 8000   # secure cookies need HTTPS
uv run pytest   # set OPSPILOT_TEST_DATABASE_URL (a separate empty DB) to also run the Postgres concurrency test
```

## Connecting GitHub for a workspace
1. Generate a key once and put it in `.env`: `OPSPILOT_SECRET_KEY=<Fernet key>` (see `.env.example`). Restart the API.
2. Apply `docs/supabase/004_integration_secrets.sql` (Supabase SQL editor) or `alembic upgrade head`.
3. In the app: Settings -> GitHub Actions -> enter `owner/repo` and a fine-grained token (Actions read; Actions write for re-runs) -> Test connection.
4. Pipelines -> Sync now. The token is encrypted at rest and never returned by any endpoint.
