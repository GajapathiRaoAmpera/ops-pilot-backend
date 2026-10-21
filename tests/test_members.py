from fastapi.testclient import TestClient

from app.main import app
from tests.conftest import ORIGIN, PASSWORD, login

NEWPW = "a-brand-new-pass-1"


def accept(token, email_name="New Person", password=NEWPW):
    return TestClient(app).post("/invitations/accept", headers=ORIGIN,
                                json={"token": token, "name": email_name, "password": password})


def test_platform_admin_creates_org_and_first_admin_onboards_via_link(env):
    pa = login("platform@x.test")
    me = pa.get("/auth/me").json()
    assert me["permissions"] == ["platform:orgs:manage"] and me["workspaces"] == []
    r = pa.post("/platform/organizations", headers=ORIGIN, json={"name": "Acme", "adminEmail": "Boss@Acme.test"})
    assert r.status_code == 201
    token = r.json()["adminInvitation"]["token"]
    assert any(o["name"] == "Acme" and o["workspaces"] == 1 for o in pa.get("/platform/organizations").json()["organizations"])
    # public preview never needs a session
    prev = TestClient(app).get(f"/invitations/{token}").json()
    assert prev["email"] == "boss@acme.test" and prev["role"] == "Organization Administrator"
    assert accept(token, "The Boss").status_code == 200
    assert accept(token, "Again").status_code == 404  # single use
    boss = TestClient(app)
    assert boss.post("/auth/login", headers=ORIGIN, json={"email": "boss@acme.test", "password": NEWPW}).status_code == 200
    m = boss.get("/auth/me").json()
    assert m["organization"]["name"] == "Acme" and "sys:members:manage" in m["permissions"]
    assert "platform:orgs:manage" not in m["permissions"]
    assert boss.get("/platform/organizations").status_code == 403


def test_platform_admin_has_no_tenant_access_and_others_cannot_use_platform(env):
    pa = login("platform@x.test")
    assert pa.get(f"/workspaces/{env['ws_a'].id}/overview").status_code == 404
    assert pa.get("/org/members").status_code == 403
    for role in ("org_admin", "workspace_admin", "devops_engineer"):
        c = login(f"{role}@a.test")
        assert c.post("/platform/organizations", headers=ORIGIN, json={"name": "Evil", "adminEmail": "e@e.test"}).status_code == 403
        assert c.get("/platform/organizations").status_code == 403


def test_org_admin_invites_org_wide_and_workspace_scoped(env):
    admin = login("org_admin@a.test")
    ws = str(env["ws_a"].id)
    r = admin.post("/org/invitations", headers=ORIGIN, json={"email": "dev1@a.test", "role": "devops_engineer", "workspaceId": ws})
    assert r.status_code == 201
    assert accept(r.json()["token"]).status_code == 200
    c = TestClient(app)
    c.post("/auth/login", headers=ORIGIN, json={"email": "dev1@a.test", "password": NEWPW})
    assert c.get(f"/workspaces/{ws}/pipelines/runs").status_code == 200
    assert c.get("/org/members").status_code == 403  # workspace role never grants org-level rights
    assert admin.post("/org/invitations", headers=ORIGIN, json={"email": "dev1@a.test", "role": "viewer", "workspaceId": ws}).status_code == 409
    assert admin.post("/org/invitations", headers=ORIGIN, json={"email": "x@a.test", "role": "org_admin", "workspaceId": ws}).status_code == 422
    assert admin.post("/org/invitations", headers=ORIGIN, json={"email": "x@a.test", "role": "nope"}).status_code == 422


def test_workspace_admin_scope_and_no_escalation(env):
    wa = login("workspace_admin@a.test")
    ws = str(env["ws_a"].id)
    assert wa.get("/org/members").status_code == 403
    assert wa.post("/org/invitations", headers=ORIGIN, json={"email": "z@a.test", "role": "viewer"}).status_code == 403
    for bad in ("org_admin", "workspace_admin", "security_auditor"):
        assert wa.post(f"/workspaces/{ws}/invitations", headers=ORIGIN, json={"email": "z@a.test", "role": bad}).status_code == 403, bad
    ok = wa.post(f"/workspaces/{ws}/invitations", headers=ORIGIN, json={"email": "z@a.test", "role": "developer"})
    assert ok.status_code == 201
    assert wa.post(f"/workspaces/{env['ws_b'].id}/invitations", headers=ORIGIN, json={"email": "z@a.test", "role": "viewer"}).status_code == 404
    assert login("developer@a.test").post(f"/workspaces/{ws}/invitations", headers=ORIGIN,
                                          json={"email": "q@a.test", "role": "viewer"}).status_code == 403
    members = wa.get(f"/workspaces/{ws}/members").json()["members"]
    assert {m["email"] for m in members} == {"workspace_admin@a.test", "developer@a.test"}
    dev = next(m for m in members if m["email"] == "developer@a.test")
    assert wa.patch(f"/workspaces/{ws}/memberships/{dev['membershipId']}", headers=ORIGIN, json={"role": "org_admin"}).status_code == 403
    assert wa.patch(f"/workspaces/{ws}/memberships/{dev['membershipId']}", headers=ORIGIN, json={"role": "viewer"}).status_code == 200
    me = next(m for m in members if m["email"] == "workspace_admin@a.test")
    assert wa.delete(f"/workspaces/{ws}/memberships/{me['membershipId']}", headers=ORIGIN).status_code == 409
    assert wa.delete(f"/workspaces/{ws}/memberships/{dev['membershipId']}", headers=ORIGIN).status_code == 200


def test_workspace_admin_can_approve_but_not_own_request(env):
    ws = env["ws_a"].id
    wa = login("workspace_admin@a.test")
    wa.post(f"/workspaces/{ws}/pipelines/sync", headers=ORIGIN)
    run_id = wa.get(f"/workspaces/{ws}/pipelines/runs").json()["runs"][0]["id"]
    req = wa.post(f"/workspaces/{ws}/action-requests", headers=ORIGIN,
                  json={"runId": run_id, "type": "rerun_failed_jobs"}).json()
    assert wa.post(f"/workspaces/{ws}/approvals/{req['id']}/decision", headers=ORIGIN,
                   json={"decision": "approve"}).status_code == 403  # separation of duties
    assert login("org_admin@a.test").post(f"/workspaces/{ws}/approvals/{req['id']}/decision", headers=ORIGIN,
                                          json={"decision": "approve"}).status_code == 200


def test_developer_is_read_only(env):
    ws = env["ws_a"].id
    d = login("developer@a.test")
    assert d.get(f"/workspaces/{ws}/pipelines/runs").status_code == 200
    assert d.post(f"/workspaces/{ws}/pipelines/sync", headers=ORIGIN).status_code == 403
    assert d.get(f"/workspaces/{ws}/approvals").status_code == 403


def test_invites_expire_revoke_and_existing_accounts(env):
    admin = login("org_admin@a.test")
    r = admin.post("/org/invitations", headers=ORIGIN, json={"email": "late@a.test", "role": "viewer"}).json()
    # a newer invite for the same person supersedes the old link
    r2 = admin.post("/org/invitations", headers=ORIGIN, json={"email": "late@a.test", "role": "viewer"}).json()
    assert accept(r["token"]).status_code == 404 and TestClient(app).get(f"/invitations/{r2['token']}").status_code == 200
    assert admin.delete(f"/org/invitations/{r2['id']}", headers=ORIGIN).status_code == 200
    assert accept(r2["token"]).status_code == 404
    # expired
    from app.models import Invitation
    r3 = admin.post("/org/invitations", headers=ORIGIN, json={"email": "old@a.test", "role": "viewer"}).json()
    from datetime import UTC, datetime, timedelta
    with env["factory"]() as db:
        inv = db.get(Invitation, __import__("uuid").UUID(r3["id"]))
        inv.expires_at = datetime.now(UTC) - timedelta(minutes=1)
        db.commit()
    assert accept(r3["token"]).status_code == 404
    # existing account must sign in; link only works for that account
    other = login("outsider@b.test")  # org B admin invites an existing user (viewer@a.test) into org B
    inv = other.post("/org/invitations", headers=ORIGIN, json={"email": "viewer@a.test", "role": "viewer"}).json()
    assert accept(inv["token"]).status_code == 409
    assert other.post("/invitations/accept-existing", headers=ORIGIN, json={"token": inv["token"]}).status_code == 404
    v = login("viewer@a.test")
    assert v.post("/invitations/accept-existing", headers=ORIGIN, json={"token": inv["token"]}).status_code == 200
    assert v.post("/invitations/accept-existing", headers=ORIGIN, json={"token": inv["token"]}).status_code == 404


def test_role_change_removal_disable_and_last_admin_guard(env):
    admin = login("org_admin@a.test")
    viewer = login("viewer@a.test")
    members = admin.get("/org/members").json()["members"]
    vm = next(m for m in members if m["email"] == "viewer@a.test")
    assert viewer.get("/rbac/matrix").status_code == 403
    assert admin.patch(f"/org/memberships/{vm['membershipId']}", headers=ORIGIN, json={"role": "security_auditor"}).status_code == 200
    assert viewer.get("/rbac/matrix").status_code == 200  # immediate
    me = next(m for m in members if m["email"] == "org_admin@a.test")
    assert admin.patch(f"/org/memberships/{me['membershipId']}", headers=ORIGIN, json={"role": "viewer"}).status_code == 409
    assert admin.delete(f"/org/memberships/{me['membershipId']}", headers=ORIGIN).status_code == 409
    assert admin.delete(f"/org/members/{vm['userId']}", headers=ORIGIN).status_code == 200
    assert viewer.get("/auth/me").status_code == 401
    assert TestClient(app).post("/auth/login", headers=ORIGIN, json={"email": "viewer@a.test", "password": PASSWORD}).status_code == 401


def test_cross_tenant_member_admin_is_blocked(env):
    admin_a = login("org_admin@a.test")
    b_user = login("outsider@b.test").get("/auth/me").json()["user"]["id"]
    b_mid = login("outsider@b.test").get("/org/members").json()["members"][0]["membershipId"]
    assert admin_a.delete(f"/org/members/{b_user}", headers=ORIGIN).status_code == 404
    assert admin_a.delete(f"/org/memberships/{b_mid}", headers=ORIGIN).status_code == 404
    assert admin_a.post(f"/org/members/{b_user}/reset-link", headers=ORIGIN).status_code == 404
    assert admin_a.post("/org/invitations", headers=ORIGIN,
                        json={"email": "x@a.test", "role": "viewer", "workspaceId": str(env["ws_b"].id)}).status_code == 404


def test_reset_link_sets_new_password_and_ends_sessions(env):
    admin = login("org_admin@a.test")
    dev = login("devops_engineer@a.test")
    uid = dev.get("/auth/me").json()["user"]["id"]
    link = admin.post(f"/org/members/{uid}/reset-link", headers=ORIGIN).json()
    assert accept(link["token"], password="reset-password-123").status_code == 200
    assert dev.get("/auth/me").status_code == 401
    c = TestClient(app)
    assert c.post("/auth/login", headers=ORIGIN, json={"email": "devops_engineer@a.test", "password": PASSWORD}).status_code == 401
    assert c.post("/auth/login", headers=ORIGIN, json={"email": "devops_engineer@a.test", "password": "reset-password-123"}).status_code == 200


def test_weak_password_rejected_on_accept(env):
    t = login("org_admin@a.test").post("/org/invitations", headers=ORIGIN, json={"email": "w@a.test", "role": "viewer"}).json()["token"]
    assert accept(t, password="short").status_code == 422
    assert accept(t).status_code == 200
