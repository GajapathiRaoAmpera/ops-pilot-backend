import os

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.config import Settings, get_settings
from app.db import SCHEMA, Base, get_db
from app.integrations.github import GitHubFactory
from app.main import app
from app.models import Integration, Membership, Organization, User, Workspace
from app.rbac import seed_roles
from app.routers import auth as auth_router
from app.routers.integrations import get_factory
from app.routers.pipelines import get_github_factory
from app.security import hash_password

PG_URL = os.environ.get("OPSPILOT_TEST_DATABASE_URL")
PASSWORD = "test-password-123"
ORIGIN = {"origin": "http://localhost:3000"}


RERUNS: list[str] = []
RERUN_STATUS = {"code": 201}


def gh_handler(request: httpx.Request) -> httpx.Response:
    if request.method == "POST" and request.url.path.endswith("/rerun-failed-jobs"):
        RERUNS.append(request.url.path)
        return httpx.Response(RERUN_STATUS["code"])
    if request.url.path.endswith("/actions/runs/101"):
        return httpx.Response(200, json={"id": 101, "name": "build", "status": "queued", "head_sha": "a" * 40})
    if request.url.path.endswith("/actions/runs"):
        return httpx.Response(200, json={"workflow_runs": [{
            "id": 101, "name": "build", "head_branch": "main", "head_sha": "a" * 40,
            "status": "completed", "conclusion": "failure", "html_url": "https://github.com/o/r/actions/runs/101",
            "run_started_at": "2026-01-01T00:00:00Z"}]})
    return httpx.Response(404)


@pytest.fixture()
def env():
    if PG_URL:  # real Postgres: needed for true concurrency tests
        engine = create_engine(PG_URL)
        with engine.begin() as c:
            c.exec_driver_sql(f"DROP SCHEMA IF EXISTS {SCHEMA} CASCADE")
            c.exec_driver_sql(f"CREATE SCHEMA {SCHEMA}")
    else:
        engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
        engine = engine.execution_options(schema_translate_map={SCHEMA: None})  # SQLite has no schemas
    Base.metadata.create_all(engine)
    factory = sessionmaker(engine, expire_on_commit=False)
    db = factory()
    roles = seed_roles(db)
    orgs = {}
    for name in ("A", "B"):
        org = Organization(name=f"Org {name}")
        db.add(org)
        db.flush()
        ws = Workspace(org_id=org.id, name=f"WS {name}")
        db.add(ws)
        db.flush()
        db.add(Integration(org_id=org.id, workspace_id=ws.id, provider="github", config={"repo": "o/r"}))
        orgs[name] = (org, ws)
    users = {}
    for key in ("org_admin", "workspace_admin", "devops_engineer", "developer", "security_auditor", "viewer"):
        u = User(email=f"{key}@a.test", name=key, password_hash=hash_password(PASSWORD))
        db.add(u)
        db.flush()
        scoped = orgs["A"][1].id if key in ("workspace_admin", "developer") else None
        db.add(Membership(user_id=u.id, org_id=orgs["A"][0].id, workspace_id=scoped, role_id=roles[key].id))
        users[key] = u
    pa = User(email="platform@x.test", name="platform", password_hash=hash_password(PASSWORD), is_platform_admin=True)
    db.add(pa)
    outsider = User(email="outsider@b.test", name="outsider", password_hash=hash_password(PASSWORD))
    db.add(outsider)
    db.flush()
    db.add(Membership(user_id=outsider.id, org_id=orgs["B"][0].id, role_id=roles["org_admin"].id))
    db.commit()

    from cryptography.fernet import Fernet

    settings = Settings(github_token="test-token", secret_key=Fernet.generate_key().decode(), cookie_secure=False, sync_min_interval_seconds=0,
                        github_webhook_secret="whsec")

    def _db():
        with factory() as s:
            yield s

    app.dependency_overrides[get_db] = _db
    app.dependency_overrides[get_settings] = lambda: settings
    factory_obj = GitHubFactory(settings, httpx.MockTransport(gh_handler))
    app.dependency_overrides[get_github_factory] = lambda: factory_obj
    app.dependency_overrides[get_factory] = lambda: factory_obj
    auth_router._FAILS.clear()
    RERUNS.clear()
    RERUN_STATUS["code"] = 201
    yield {"ws_a": orgs["A"][1], "ws_b": orgs["B"][1], "factory": factory}
    app.dependency_overrides.clear()


def login(email: str) -> TestClient:
    c = TestClient(app)
    r = c.post("/auth/login", json={"email": email, "password": PASSWORD}, headers=ORIGIN)
    assert r.status_code == 200, r.text
    return c
