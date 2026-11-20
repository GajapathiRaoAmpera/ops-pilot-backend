.PHONY: help install db migrate seed dev test lint fix check openapi check-db

RUN := PYTHONPATH=. uv run

help: ## List targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-10s %s\n", $$1, $$2}'

install: ## Install deps (incl. dev)
	uv sync

db: ## Start local Postgres on 127.0.0.1:5433
	docker compose up -d db

migrate: ## Apply migrations
	$(RUN) alembic upgrade head

seed: ## Seed data (set OPSPILOT_SEED_GITHUB_REPO=owner/repo)
	$(RUN) python scripts/seed.py

dev: ## Run API on :8000 with reload (insecure cookies for local HTTP)
	OPSPILOT_COOKIE_SECURE=false uv run uvicorn app.main:app --port 8000 --reload

test: ## Run tests
	uv run pytest

lint: ## Ruff check
	uv run ruff check .

fix: ## Ruff autofix
	uv run ruff check --fix .

check: lint test ## Lint + tests (same as CI)

openapi: ## Regenerate docs/openapi.json
	$(RUN) python scripts/export_openapi.py

check-db: ## Verify DB connection and schema
	$(RUN) python scripts/check_db.py
