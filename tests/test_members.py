from fastapi.testclient import TestClient

from app.main import app
from tests.conftest import ORIGIN, PASSWORD, login

NEW = {"email": "New.Person@a.test", "name": "New Person", "role": "viewer"}


def test_admin_adds_member_who_must_change_password(env):
    admin = login("org_admin@a.test")
    r = admin.post("/org/members", headers=ORIGIN, json=NEW)
    assert r.status_code == 201
    temp = r.json()["temporaryPassword"]
    assert r.json()["email"] == "new.person@a.test" and r.json()["role"] == "viewer"

    c = TestClient(app)
    assert c.post("/auth/login", headers=ORIGIN, json={"email": NEW["email"], "password": temp}).status_code == 200
    assert c.get("/auth/me").json()["mustChangePassword"] is True
    ws = env["ws_a"].id
    assert c.get(f"/workspaces/{ws}/overview").json()["detail"] == "password_change_required"  # blocked until changed
    assert c.post("/auth/change-password", headers=ORIGIN,
                  json={"currentPassword": "wrong-password", "newPassword": "a-brand-new-pass-1"}).status_code == 401
    assert c.post("/auth/change-password", headers=ORIGIN,
                  json={"currentPassword": temp, "newPassword": "short"}).status_code == 422
    assert c.post("/auth/change-password", headers=ORIGIN,
                  json={"currentPassword": temp, "newPassword": "a-brand-new-pass-1"}).status_code == 200
    assert c.get(f"/workspaces/{ws}/overview").status_code == 200
    assert c.get("/rbac/matrix").status_code == 403  # viewer role only


def test_only_admins_manage_members(env):
    for role in ("devops_engineer", "security_auditor", "viewer"):
        c = login(f"{role}@a.test")
        assert c.get("/org/members").status_code == 403, role
        assert c.post("/org/members", headers=ORIGIN, json=NEW).status_code == 403, role
    assert TestClient(app).get("/org/members").status_code == 401


def test_member_list_is_tenant_scoped(env):
    a = {m["email"] for m in login("org_admin@a.test").get("/org/members").json()["members"]}
    b = {m["email"] for m in login("outsider@b.test").get("/org/members").json()["members"]}
    assert "outsider@b.test" not in a and a.isdisjoint(b) and b == {"outsider@b.test"}


def test_cannot_touch_other_orgs_users_or_self(env):
    admin_a = login("org_admin@a.test")
    outsider_id = login("outsider@b.test").get("/auth/me").json()["user"]["id"]
    assert admin_a.patch(f"/org/members/{outsider_id}", headers=ORIGIN, json={"role": "viewer"}).status_code == 404
    assert admin_a.delete(f"/org/members/{outsider_id}", headers=ORIGIN).status_code == 404
    me = admin_a.get("/auth/me").json()["user"]["id"]
    assert admin_a.patch(f"/org/members/{me}", headers=ORIGIN, json={"role": "viewer"}).status_code == 409
    assert admin_a.delete(f"/org/members/{me}", headers=ORIGIN).status_code == 409


def test_role_change_applies_immediately_and_disable_revokes_sessions(env):
    admin = login("org_admin@a.test")
    viewer = login("viewer@a.test")
    vid = viewer.get("/auth/me").json()["user"]["id"]
    assert viewer.get("/rbac/matrix").status_code == 403
    assert admin.patch(f"/org/members/{vid}", headers=ORIGIN, json={"role": "security_auditor"}).status_code == 200
    assert viewer.get("/rbac/matrix").status_code == 200  # no re-login needed
    assert admin.delete(f"/org/members/{vid}", headers=ORIGIN).json()["disabled"] is True
    assert viewer.get("/auth/me").status_code == 401  # existing session killed
    assert TestClient(app).post("/auth/login", headers=ORIGIN,
                                json={"email": "viewer@a.test", "password": PASSWORD}).status_code == 401


def test_duplicate_email_and_unknown_role_rejected(env):
    admin = login("org_admin@a.test")
    assert admin.post("/org/members", headers=ORIGIN, json={**NEW, "email": "viewer@a.test"}).status_code == 409
    assert admin.post("/org/members", headers=ORIGIN, json={**NEW, "role": "platform_god"}).status_code == 422
    actions = [e["action"] for e in admin.get("/audit-events").json()["events"]]
    assert "member.added" not in actions
