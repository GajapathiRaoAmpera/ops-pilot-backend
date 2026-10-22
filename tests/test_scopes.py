"""Each role sees and does what its name promises: no more, no less."""
from sqlalchemy import select

from app.models import Role, RolePermission, Workspace
from app.rbac import ROLES, seed_roles
from tests.conftest import ORIGIN, login


def test_security_auditor_reviews_everything_and_changes_nothing(env):
    ws = env["ws_a"].id
    c = login("security_auditor@a.test")
    for url in (f"/workspaces/{ws}/executions", f"/workspaces/{ws}/investigations", f"/workspaces/{ws}/fix-proposals",
                f"/workspaces/{ws}/investigations/status", f"/workspaces/{ws}/approvals", "/audit-events"):
        assert c.get(url).status_code == 200, url
    run_id = "00000000-0000-0000-0000-000000000000"
    assert c.post(f"/workspaces/{ws}/investigations", headers=ORIGIN, json={"runId": run_id}).status_code == 403
    assert c.post(f"/workspaces/{ws}/fix-proposals", headers=ORIGIN, json={"runId": run_id}).status_code == 403
    assert c.post(f"/workspaces/{ws}/pipelines/sync", headers=ORIGIN).status_code == 403
    assert c.post(f"/workspaces/{ws}/action-requests", headers=ORIGIN,
                  json={"runId": run_id, "type": "rerun_failed_jobs"}).status_code == 403


def test_viewer_cannot_read_ai_history(env):
    ws = env["ws_a"].id
    assert login("viewer@a.test").get(f"/workspaces/{ws}/investigations").status_code == 403


def test_workspace_admin_sees_their_workspace_audit_only(env):
    org = env["ws_a"].org_id
    with env["factory"]() as db:
        other = Workspace(org_id=org, name="WS other")
        db.add(other)
        db.commit()
        other_id = other.id
    admin = login("org_admin@a.test")
    admin.post(f"/workspaces/{other_id}/invitations", headers=ORIGIN, json={"email": "x@a.test", "role": "viewer"})
    admin.post(f"/workspaces/{env['ws_a'].id}/invitations", headers=ORIGIN, json={"email": "y@a.test", "role": "viewer"})
    wa = login("workspace_admin@a.test")  # workspace admin of WS A only
    events = wa.get(f"/workspaces/{env['ws_a'].id}/audit-events").json()["events"]
    assert events and all(e["workspaceId"] == str(env["ws_a"].id) for e in events)
    assert wa.get(f"/workspaces/{other_id}/audit-events").status_code == 404  # not their workspace
    assert wa.get("/audit-events").status_code == 403  # not the whole organization
    assert login("devops_engineer@a.test").get(f"/workspaces/{env['ws_a'].id}/audit-events").status_code == 403


def test_startup_sync_removes_permissions_a_role_no_longer_has(env):
    with env["factory"]() as db:
        viewer = db.scalar(select(Role).where(Role.key == "viewer"))
        db.add(RolePermission(role_id=viewer.id, permission="sys:settings:read"))  # a retired permission
        db.commit()
        seed_roles(db)
        perms = {rp.permission for rp in db.scalar(select(Role).where(Role.key == "viewer")).permissions}
    assert perms == ROLES["viewer"][1]
    assert not any("sys:settings:read" in p for _, p in ROLES.values())
