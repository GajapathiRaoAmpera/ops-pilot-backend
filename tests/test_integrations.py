import httpx
from sqlalchemy import select

from app.config import Settings, get_settings
from app.integrations.github import GitHubFactory
from app.main import app
from app.models import AuditEvent, Integration
from app.routers.integrations import get_factory
from app.routers.pipelines import get_github_factory
from tests.conftest import ORIGIN, login

TOKEN_A = "ghp_" + "A" * 36
TOKEN_B = "ghp_" + "B" * 36


def path(ws):
    return f"/workspaces/{ws}/integrations/github"


def test_connect_encrypts_token_and_never_returns_it(env):
    ws = env["ws_a"].id
    admin = login("org_admin@a.test")
    r = admin.put(path(ws), headers=ORIGIN, json={"repo": "acme/api", "token": TOKEN_A})
    assert r.status_code == 200 and r.json() == {"connected": True, "repo": "acme/api", "tokenSet": True, "lastSyncedAt": None}
    assert TOKEN_A not in r.text and TOKEN_A not in admin.get(path(ws)).text
    with env["factory"]() as db:
        row = db.scalar(select(Integration).where(Integration.workspace_id == ws))
        assert row.secret_ciphertext and TOKEN_A not in row.secret_ciphertext
        assert TOKEN_A not in " ".join(e.detail + e.resource for e in db.scalars(select(AuditEvent)))


def test_repo_and_token_validation(env):
    admin = login("org_admin@a.test")
    ws = env["ws_a"].id
    for bad in ("nope", "a/b/c", "../etc/passwd", "a b/c"):
        assert admin.put(path(ws), headers=ORIGIN, json={"repo": bad}).status_code == 422, bad
    assert admin.put(path(ws), headers=ORIGIN, json={"repo": "a/b", "token": "short"}).status_code == 422


def test_connect_requires_encryption_key(env):
    app.dependency_overrides[get_settings] = lambda: Settings(cookie_secure=False, secret_key="")
    r = login("org_admin@a.test").put(path(env["ws_a"].id), headers=ORIGIN, json={"repo": "a/b", "token": TOKEN_A})
    assert r.status_code == 503 and r.json()["detail"] == "encryption_not_configured"


def test_permissions_and_tenancy(env):
    ws = env["ws_a"].id
    body = {"repo": "acme/api", "token": TOKEN_A}
    for role in ("devops_engineer", "developer", "security_auditor", "viewer"):
        c = login(f"{role}@a.test")
        assert c.get(path(ws)).status_code == 403, role
        assert c.put(path(ws), headers=ORIGIN, json=body).status_code == 403, role
    wa = login("workspace_admin@a.test")
    assert wa.put(path(ws), headers=ORIGIN, json=body).status_code == 200  # workspace admin may connect
    assert wa.put(path(env["ws_b"].id), headers=ORIGIN, json=body).status_code == 404
    out = login("outsider@b.test")
    assert out.put(path(ws), headers=ORIGIN, json=body).status_code == 404
    assert out.delete(path(ws), headers=ORIGIN).status_code == 404


def test_disconnect_removes_token_and_row(env):
    ws = env["ws_a"].id
    admin = login("org_admin@a.test")
    admin.put(path(ws), headers=ORIGIN, json={"repo": "acme/api", "token": TOKEN_A})
    assert admin.delete(path(ws), headers=ORIGIN).json() == {"connected": False}
    assert admin.get(path(ws)).json()["connected"] is False
    with env["factory"]() as db:
        assert db.scalar(select(Integration).where(Integration.workspace_id == ws)) is None


def test_test_endpoint_reports_coarse_reasons_only(env):
    ws = env["ws_a"].id
    admin = login("org_admin@a.test")
    admin.put(path(ws), headers=ORIGIN, json={"repo": "acme/api", "token": TOKEN_A})
    assert admin.post(path(ws) + "/test", headers=ORIGIN).json() == {"ok": True}
    settings = app.dependency_overrides[get_settings]()
    denied = GitHubFactory(settings, httpx.MockTransport(lambda r: httpx.Response(401, json={"message": "Bad credentials"})))
    app.dependency_overrides[get_factory] = lambda: denied
    r = admin.post(path(ws) + "/test", headers=ORIGIN)
    assert r.json() == {"ok": False, "reason": "unauthorized"} and "Bad credentials" not in r.text


def test_each_workspace_uses_its_own_token(env):
    seen: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.url.path, request.headers.get("authorization", "")))
        return httpx.Response(200, json={"workflow_runs": []})

    settings = app.dependency_overrides[get_settings]()
    factory = GitHubFactory(settings, httpx.MockTransport(handler))
    app.dependency_overrides[get_github_factory] = lambda: factory
    wa, wb = env["ws_a"].id, env["ws_b"].id
    login("org_admin@a.test").put(path(wa), headers=ORIGIN, json={"repo": "acme/a", "token": TOKEN_A})
    login("outsider@b.test").put(path(wb), headers=ORIGIN, json={"repo": "other/b", "token": TOKEN_B})
    login("org_admin@a.test").post(f"/workspaces/{wa}/pipelines/sync", headers=ORIGIN)
    login("outsider@b.test").post(f"/workspaces/{wb}/pipelines/sync", headers=ORIGIN)
    assert ("/repos/acme/a/actions/runs", f"Bearer {TOKEN_A}") in seen
    assert ("/repos/other/b/actions/runs", f"Bearer {TOKEN_B}") in seen
    assert not any(p.startswith("/repos/other") and t.endswith("A" * 36) for p, t in seen)
