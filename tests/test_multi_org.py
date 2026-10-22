"""One person in two organizations: every org-level action is scoped to the ACTIVE org, using only rights held there."""
from sqlalchemy import select

from app.models import AuditEvent, Membership, Role, User
from tests.conftest import ORIGIN, login


def join(env, email: str, org_ws, role: str, workspace: bool = False) -> None:
    """Give an existing user a membership in another organization (org-wide, or in its workspace)."""
    with env["factory"]() as db:
        user = db.scalar(select(User).where(User.email == email))
        role_id = db.scalar(select(Role.id).where(Role.key == role))
        db.add(Membership(user_id=user.id, org_id=org_ws.org_id, workspace_id=org_ws.id if workspace else None, role_id=role_id))
        db.commit()


def in_org(client, org_ws):
    client.cookies.set("opspilot_org", str(org_ws.org_id))
    return client


def test_admin_in_one_org_is_only_a_viewer_in_the_other(env):
    join(env, "org_admin@a.test", env["ws_b"], "viewer")
    c = login("org_admin@a.test")
    assert c.get("/org/members").status_code == 200  # default org: A, where they are admin
    in_org(c, env["ws_b"])
    assert c.get("/org/members").status_code == 403  # B: viewer, so no member admin
    assert c.post("/org/invitations", headers=ORIGIN, json={"email": "x@b.test", "role": "org_admin"}).status_code == 403
    assert c.get("/audit-events").status_code == 403
    me = c.get("/auth/me").json()
    assert me["organization"]["name"] == "Org B" and me["role"] == "Viewer"
    assert "sys:members:manage" not in me["permissions"] and "sys:overview:read" in me["permissions"]
    assert {o["name"]: o["role"] for o in me["organizations"]} == {"Org A": "Organization Administrator", "Org B": "Viewer"}


def test_audit_trail_shows_only_the_active_org(env):
    join(env, "security_auditor@a.test", env["ws_b"], "security_auditor")
    login("outsider@b.test").post("/org/workspaces", headers=ORIGIN, json={"name": "B secret project"})
    c = login("security_auditor@a.test")
    a_events = c.get("/audit-events").json()["events"]
    assert a_events and all("B secret" not in (e.get("detail") or "") + (e.get("resource") or "") for e in a_events)
    with env["factory"]() as db:
        b_org = env["ws_b"].org_id
        b_ids = {str(e.id) for e in db.scalars(select(AuditEvent).where(AuditEvent.org_id == b_org))}
    assert not {str(e["id"]) for e in a_events} & b_ids
    b_events = in_org(c, env["ws_b"]).get("/audit-events").json()["events"]
    assert {str(e["id"]) for e in b_events} <= b_ids


def test_admin_rights_in_one_org_do_not_escalate_a_workspace_role_in_another(env):
    join(env, "org_admin@a.test", env["ws_b"], "workspace_admin", workspace=True)
    join(env, "viewer@a.test", env["ws_b"], "viewer", workspace=True)
    c = login("org_admin@a.test")
    ws_b = env["ws_b"].id
    with env["factory"]() as db:
        viewer = db.scalar(select(User).where(User.email == "viewer@a.test"))
        mid = db.scalar(select(Membership.id).where(Membership.user_id == viewer.id, Membership.workspace_id == ws_b))
    r = c.patch(f"/workspaces/{ws_b}/memberships/{mid}", headers=ORIGIN, json={"role": "workspace_admin"})
    assert r.status_code == 403 and r.json()["detail"] == "role_not_grantable"  # a workspace admin in B can't mint peers
    assert c.post(f"/workspaces/{ws_b}/invitations", headers=ORIGIN, json={"email": "n@b.test", "role": "workspace_admin"}).status_code == 403


def test_one_org_cannot_take_over_or_lock_out_a_shared_account(env):
    join(env, "developer@a.test", env["ws_b"], "viewer")
    admin_b = login("outsider@b.test")
    with env["factory"]() as db:
        uid = db.scalar(select(User.id).where(User.email == "developer@a.test"))
    r = admin_b.post(f"/org/members/{uid}/reset-link", headers=ORIGIN)
    assert r.status_code == 409 and r.json()["detail"] == "user_in_other_organizations"
    r = admin_b.delete(f"/org/members/{uid}", headers=ORIGIN)
    assert r.json() == {"ok": True, "disabled": False}
    with env["factory"]() as db:
        assert db.get(User, uid).disabled is False
        assert {m.org_id for m in db.scalars(select(Membership).where(Membership.user_id == uid))} == {env["ws_a"].org_id}
    assert login("developer@a.test").get("/auth/me").status_code == 200  # still works in org A


def test_cookies_are_only_hints(env):
    c = login("viewer@a.test")
    c.cookies.set("opspilot_org", str(env["ws_b"].org_id))  # not a member of B
    c.cookies.set("opspilot_ws", str(env["ws_b"].id))
    me = c.get("/auth/me").json()
    assert me["organization"]["name"] == "Org A" and me["activeWorkspaceId"] == str(env["ws_a"].id)
    c.cookies.set("opspilot_org", "not-a-uuid")
    assert c.get("/auth/me").json()["organization"]["name"] == "Org A"


def test_permissions_follow_the_active_workspace(env):
    """A DevOps engineer in one workspace who only views another must not get DevOps rights there."""
    with env["factory"]() as db:
        from app.models import Workspace
        ws2 = Workspace(org_id=env["ws_a"].org_id, name="WS A2")
        db.add(ws2)
        db.commit()
        ws2_id = ws2.id
    join(env, "developer@a.test", type("W", (), {"org_id": env["ws_a"].org_id, "id": ws2_id})(), "viewer", workspace=True)
    c = login("developer@a.test")  # developer in WS A, viewer in WS A2
    c.cookies.set("opspilot_ws", str(env["ws_a"].id))
    assert "ai:copilot:use" in c.get("/auth/me").json()["permissions"]
    c.cookies.set("opspilot_ws", str(ws2_id))
    me = c.get("/auth/me").json()
    assert me["activeWorkspaceId"] == str(ws2_id) and me["role"] == "Viewer"
    assert "ai:copilot:use" not in me["permissions"]
