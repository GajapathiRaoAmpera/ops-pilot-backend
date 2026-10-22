"""Platform administrator: organizations and their people. Organization administrator: blocking inside the org."""
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.main import app
from app.models import Membership, User
from tests.conftest import ORIGIN, PASSWORD, login


def uid(env, email):
    with env["factory"]() as db:
        return db.scalar(select(User.id).where(User.email == email))


def try_login(email):
    return TestClient(app).post("/auth/login", json={"email": email, "password": PASSWORD}, headers=ORIGIN)


def test_platform_admin_runs_the_organization_lifecycle(env):
    pa = login("platform@x.test")
    org = str(env["ws_a"].org_id)
    assert pa.patch(f"/platform/organizations/{org}", headers=ORIGIN, json={"name": "Org A Renamed"}).json()["name"] == "Org A Renamed"
    assert pa.patch(f"/platform/organizations/{org}", headers=ORIGIN, json={"name": "Org B"}).status_code == 409
    member = login("viewer@a.test")  # an open session before the block

    assert pa.patch(f"/platform/organizations/{org}", headers=ORIGIN, json={"status": "suspended"}).json()["status"] == "suspended"
    assert member.get("/auth/me").status_code == 403  # blocked on the very next request
    r = try_login("viewer@a.test")
    assert r.status_code == 403 and r.json()["detail"] == "access_blocked"

    assert pa.request("DELETE", f"/platform/organizations/{org}", headers=ORIGIN, json={"confirm": "wrong"}).status_code == 422
    assert pa.request("DELETE", f"/platform/organizations/{org}", headers=ORIGIN, json={"confirm": "Org A Renamed"}).json()["status"] == "archived"
    assert pa.patch(f"/platform/organizations/{org}", headers=ORIGIN, json={"status": "active"}).json()["status"] == "active"
    assert try_login("viewer@a.test").status_code == 200  # restored


def test_archive_needs_a_block_first(env):
    pa = login("platform@x.test")
    r = pa.request("DELETE", f"/platform/organizations/{env['ws_b'].org_id}", headers=ORIGIN, json={"confirm": "Org B"})
    assert r.status_code == 409 and r.json()["detail"] == "block_before_delete"


def test_platform_admin_manages_people_inside_any_org(env):
    pa = login("platform@x.test")
    org = env["ws_a"].org_id
    members = pa.get(f"/platform/organizations/{org}/members").json()["members"]
    assert {m["email"] for m in members} >= {"org_admin@a.test", "viewer@a.test"}
    inv = pa.post(f"/platform/organizations/{org}/invitations", headers=ORIGIN, json={"email": "new@a.test", "role": "security_auditor"})
    assert inv.status_code == 201 and inv.json()["token"]
    dev = next(m for m in members if m["email"] == "devops_engineer@a.test")
    assert pa.patch(f"/platform/organizations/{org}/memberships/{dev['membershipId']}", headers=ORIGIN, json={"role": "viewer"}).json()["role"] == "viewer"
    admin = next(m for m in members if m["email"] == "org_admin@a.test")
    r = pa.patch(f"/platform/organizations/{org}/memberships/{admin['membershipId']}", headers=ORIGIN, json={"role": "viewer"})
    assert r.status_code == 409 and r.json()["detail"] == "last_org_admin"  # the same rules as the org's own admins


def test_platform_admin_can_reset_anyone_even_in_several_orgs(env):
    with env["factory"]() as db:
        dev = db.scalar(select(User).where(User.email == "developer@a.test"))
        viewer_role = db.scalar(select(Membership).where(Membership.user_id == uid(env, "viewer@a.test"))).role_id
        db.add(Membership(user_id=dev.id, org_id=env["ws_b"].org_id, role_id=viewer_role))
        db.commit()
    pa = login("platform@x.test")
    r = pa.post(f"/platform/organizations/{env['ws_a'].org_id}/members/{uid(env, 'developer@a.test')}/reset-link", headers=ORIGIN)
    assert r.status_code == 201 and r.json()["token"]
    # ...while the organization's own admin still may not (it would unlock org B too)
    r = login("org_admin@a.test").post(f"/org/members/{uid(env, 'developer@a.test')}/reset-link", headers=ORIGIN)
    assert r.status_code == 409


def test_platform_admin_blocks_a_whole_account(env):
    pa = login("platform@x.test")
    victim = uid(env, "developer@a.test")
    s = login("developer@a.test")
    assert pa.post(f"/platform/users/{victim}/block", headers=ORIGIN, json={"blocked": True}).json()["blocked"] is True
    assert s.get("/auth/me").status_code == 401  # sessions ended
    assert try_login("developer@a.test").status_code == 401
    pa.post(f"/platform/users/{victim}/block", headers=ORIGIN, json={"blocked": False})
    assert try_login("developer@a.test").status_code == 200
    assert pa.post(f"/platform/users/{uid(env, 'platform@x.test')}/block", headers=ORIGIN, json={"blocked": True}).status_code == 409


def test_org_admin_blocks_and_unblocks_a_member(env):
    admin = login("org_admin@a.test")
    dev = uid(env, "devops_engineer@a.test")
    s = login("devops_engineer@a.test")
    assert admin.post(f"/org/members/{dev}/block", headers=ORIGIN).json()["blocked"] is True
    assert s.get("/auth/me").status_code == 403  # no access in this org from the next request
    members = {m["email"]: m for m in admin.get("/org/members").json()["members"]}
    assert members["devops_engineer@a.test"]["blocked"] is True
    admin.post(f"/org/members/{dev}/unblock", headers=ORIGIN)
    assert s.get("/auth/me").status_code == 200
    assert admin.post(f"/org/members/{uid(env, 'org_admin@a.test')}/block", headers=ORIGIN).status_code == 409  # not self


def test_blocking_in_one_org_leaves_the_other(env):
    with env["factory"]() as db:
        dev = db.scalar(select(User).where(User.email == "developer@a.test"))
        role = db.scalar(select(Membership).where(Membership.user_id == uid(env, "viewer@a.test"))).role_id
        db.add(Membership(user_id=dev.id, org_id=env["ws_b"].org_id, role_id=role))
        db.commit()
    login("outsider@b.test").post(f"/org/members/{uid(env, 'developer@a.test')}/block", headers=ORIGIN)
    me = login("developer@a.test").get("/auth/me").json()
    assert [o["name"] for o in me["organizations"]] == ["Org A"]  # B is gone, A still works


def test_others_cannot_use_platform_actions(env):
    for email in ("org_admin@a.test", "security_auditor@a.test"):
        c = login(email)
        assert c.get(f"/platform/organizations/{env['ws_a'].org_id}/members").status_code == 403
        assert c.patch(f"/platform/organizations/{env['ws_b'].org_id}", headers=ORIGIN, json={"status": "suspended"}).status_code == 403


def test_invitations_into_a_blocked_org_stop_working(env):
    admin = login("org_admin@a.test")
    token = admin.post("/org/invitations", headers=ORIGIN, json={"email": "late@a.test", "role": "viewer"}).json()["token"]
    login("platform@x.test").patch(f"/platform/organizations/{env['ws_a'].org_id}", headers=ORIGIN, json={"status": "suspended"})
    assert TestClient(app).get(f"/invitations/{token}").status_code in (404, 410)


def test_platform_admin_in_an_org_sees_only_the_platform(env):
    with env["factory"]() as db:
        pa = db.scalar(select(User).where(User.email == "platform@x.test"))
        admin = db.scalar(select(Membership).join(User).where(User.email == "org_admin@a.test"))
        db.add(Membership(user_id=pa.id, org_id=admin.org_id, role_id=admin.role_id))
        db.commit()
    c = login("platform@x.test")
    me = c.get("/auth/me").json()
    assert me["permissions"] == ["platform:orgs:manage"] and me["role"] == "Platform Administrator"
    assert c.get(f"/workspaces/{env['ws_a'].id}/approvals").status_code == 403
    assert c.get(f"/platform/organizations/{admin.org_id}/members").status_code == 200
