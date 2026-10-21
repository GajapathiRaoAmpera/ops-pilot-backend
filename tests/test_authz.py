import hashlib
import hmac
import json

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.routers import auth as auth_router
from tests.conftest import ORIGIN, PASSWORD, login


def test_login_me_logout(env):
    c = login("devops_engineer@a.test")
    me = c.get("/auth/me").json()
    assert me["role"] == "DevOps Engineer"
    assert "cicd:pipelines:execute" in me["permissions"]
    assert "sys:rbac:read" not in me["permissions"]
    assert c.post("/auth/logout", headers=ORIGIN).status_code == 200
    assert c.get("/auth/me").status_code == 401


def test_bad_credentials_and_rate_limit(env):
    c = TestClient(app)
    for _ in range(5):
        r = c.post("/auth/login", json={"email": "viewer@a.test", "password": "nope"}, headers=ORIGIN)
        assert r.status_code == 401
    assert c.post("/auth/login", json={"email": "viewer@a.test", "password": PASSWORD},
                  headers=ORIGIN).status_code == 429
    assert c.post("/auth/login", json={"email": "ghost@x.test", "password": "x"},
                  headers=ORIGIN).status_code == 401


def test_login_rejects_foreign_origin(env):
    r = TestClient(app).post("/auth/login", json={"email": "viewer@a.test", "password": PASSWORD},
                             headers={"origin": "https://evil.test"})
    assert r.status_code == 403


def test_cookie_flags(env):
    r = TestClient(app).post("/auth/login", json={"email": "viewer@a.test", "password": PASSWORD}, headers=ORIGIN)
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=lax" in cookie


ENDPOINTS = [
    ("GET", "/workspaces/{ws}/overview", "viewer"),
    ("GET", "/workspaces/{ws}/pipelines/runs", "viewer"),
    ("POST", "/workspaces/{ws}/pipelines/sync", "devops_engineer"),
]


@pytest.mark.parametrize("method,path,min_role", ENDPOINTS)
def test_unauthenticated_is_401(env, method, path, min_role):
    r = TestClient(app).request(method, path.format(ws=env["ws_a"].id), headers=ORIGIN)
    assert r.status_code == 401


@pytest.mark.parametrize("method,path,min_role", ENDPOINTS)
def test_cross_tenant_is_404(env, method, path, min_role):
    c = login("outsider@b.test")
    assert c.request(method, path.format(ws=env["ws_a"].id), headers=ORIGIN).status_code == 404


def test_permission_matrix(env):
    ws = env["ws_a"].id
    expect = {
        "viewer": {"runs": 200, "sync": 403, "rbac": 403, "audit": 403},
        "devops_engineer": {"runs": 200, "sync": 200, "rbac": 403, "audit": 403},
        "developer": {"runs": 200, "sync": 403, "rbac": 403, "audit": 403},
        "workspace_admin": {"runs": 200, "sync": 200, "rbac": 403, "audit": 403},
        "security_auditor": {"runs": 200, "sync": 403, "rbac": 200, "audit": 200},
        "org_admin": {"runs": 200, "sync": 200, "rbac": 200, "audit": 200},
    }
    for role, exp in expect.items():
        c = login(f"{role}@a.test")
        assert c.get(f"/workspaces/{ws}/pipelines/runs").status_code == exp["runs"], role
        assert c.post(f"/workspaces/{ws}/pipelines/sync", headers=ORIGIN).status_code == exp["sync"], role
        assert c.get("/rbac/matrix").status_code == exp["rbac"], role
        assert c.get("/audit-events").status_code == exp["audit"], role


def test_sync_then_list_and_logs_not_cross_tenant(env):
    ws = env["ws_a"].id
    c = login("devops_engineer@a.test")
    assert c.post(f"/workspaces/{ws}/pipelines/sync", headers=ORIGIN).json() == {"synced": 1}
    runs = c.get(f"/workspaces/{ws}/pipelines/runs").json()
    assert runs["runs"][0]["conclusion"] == "failure"
    run_id = runs["runs"][0]["id"]
    # A run id from workspace A is not reachable through workspace B's path.
    o = login("outsider@b.test")
    assert o.get(f"/workspaces/{env['ws_b'].id}/pipelines/runs/{run_id}").status_code == 404
    ov = c.get(f"/workspaces/{ws}/overview").json()
    assert ov["pipelines"]["counts"] == {"failure": 1}
    assert "approvals" not in ov["notConnected"] and ov["approvals"]["pending"] == 0


def test_audit_trail_is_tenant_scoped(env):
    login("devops_engineer@a.test")
    a = login("org_admin@a.test").get("/audit-events").json()["events"]
    b = login("outsider@b.test").get("/audit-events").json()["events"]
    assert any(e["action"] == "auth.login" for e in a)
    assert not any(e["resource"] == "user:devops_engineer@a.test" for e in b)


def _sig(body: bytes) -> str:
    return "sha256=" + hmac.new(b"whsec", body, hashlib.sha256).hexdigest()


def test_webhook_signature(env):
    payload = {"repository": {"full_name": "o/r"}, "workflow_run": {
        "id": 202, "name": "deploy", "status": "completed", "conclusion": "success", "head_sha": "b" * 40}}
    body = json.dumps(payload).encode()
    c = TestClient(app)
    h = {"x-github-event": "workflow_run"}
    assert c.post("/webhooks/github", content=body, headers={**h, "x-hub-signature-256": "sha256=bad"}).status_code == 401
    r = c.post("/webhooks/github", content=body, headers={**h, "x-hub-signature-256": _sig(body)})
    assert r.status_code == 200 and r.json() == {"updated": 2}  # both fixture workspaces track o/r


def test_lockout_window_is_configurable(env):
    from app.config import Settings, get_settings
    app.dependency_overrides[get_settings] = lambda: Settings(
        cookie_secure=False, login_max_failures=2, login_window_seconds=0)
    c = TestClient(app)
    for _ in range(3):  # a zero-second window never accumulates failures
        assert c.post("/auth/login", json={"email": "viewer@a.test", "password": "nope"}, headers=ORIGIN).status_code == 401
    auth_router._FAILS.clear()
    app.dependency_overrides[get_settings] = lambda: Settings(
        cookie_secure=False, login_max_failures=2, login_window_seconds=600)
    for _ in range(2):
        assert c.post("/auth/login", json={"email": "viewer@a.test", "password": "nope"}, headers=ORIGIN).status_code == 401
    assert c.post("/auth/login", json={"email": "viewer@a.test", "password": PASSWORD}, headers=ORIGIN).status_code == 429


def test_audit_filters_names_and_cursor(env):
    login("viewer@a.test")
    TestClient(app).post("/auth/login", json={"email": "viewer@a.test", "password": "wrong"}, headers=ORIGIN)
    aud = login("security_auditor@a.test")
    ev = aud.get("/audit-events?limit=1").json()
    assert len(ev["events"]) == 1 and ev["nextBefore"] is not None
    assert ev["events"][0]["actorName"] in {"security_auditor", "viewer", None}
    older = aud.get(f"/audit-events?limit=50&before_id={ev['nextBefore']}").json()["events"]
    assert all(e["id"] < ev["nextBefore"] for e in older)
    only_login = aud.get("/audit-events?action=auth.login&outcome=success").json()["events"]
    assert only_login and all(e["action"] == "auth.login" and e["outcome"] == "success" for e in only_login)


def test_startup_syncs_new_permissions_into_existing_roles(env):
    from sqlalchemy import delete

    from app.models import Role, RolePermission
    from app.rbac import seed_roles

    with env["factory"]() as db:
        role = db.query(Role).filter_by(key="org_admin").one()
        db.execute(delete(RolePermission).where(RolePermission.role_id == role.id,
                                                 RolePermission.permission == "ws:integrations:manage"))
        db.commit()
        assert "ws:integrations:manage" not in {rp.permission for rp in db.query(Role).filter_by(key="org_admin").one().permissions}
    with env["factory"]() as db:
        seed_roles(db)  # what lifespan runs
    with env["factory"]() as db:
        assert "ws:integrations:manage" in {rp.permission for rp in db.query(Role).filter_by(key="org_admin").one().permissions}
