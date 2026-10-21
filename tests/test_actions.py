from concurrent.futures import ThreadPoolExecutor

import pytest

from tests.conftest import ORIGIN, PG_URL, RERUN_STATUS, RERUNS, login


def _failed_run(env):
    ws = env["ws_a"].id
    dev = login("devops_engineer@a.test")
    dev.post(f"/workspaces/{ws}/pipelines/sync", headers=ORIGIN)
    run_id = dev.get(f"/workspaces/{ws}/pipelines/runs").json()["runs"][0]["id"]
    return ws, dev, run_id


def _request(dev, ws, run_id):
    return dev.post(f"/workspaces/{ws}/action-requests", headers=ORIGIN,
                    json={"runId": run_id, "type": "rerun_failed_jobs", "reason": "flaky"})


def test_nothing_executes_without_approval(env):
    ws, dev, run_id = _failed_run(env)
    r = _request(dev, ws, run_id)
    assert r.status_code == 201 and r.json()["status"] == "pending" and r.json()["risk"] == "medium"  # fixture run is on main
    assert RERUNS == []
    assert _request(dev, ws, run_id).status_code == 409  # duplicate open request


def test_approve_executes_once_and_is_audited(env):
    ws, dev, run_id = _failed_run(env)
    req = _request(dev, ws, run_id).json()
    admin = login("org_admin@a.test")
    out = admin.post(f"/workspaces/{ws}/approvals/{req['id']}/decision", headers=ORIGIN,
                     json={"decision": "approve", "reason": "ok"})
    assert out.status_code == 200, out.text
    body = out.json()
    assert body["status"] == "succeeded" and body["execution"]["result"]["observedStatus"] == "queued"
    assert len(RERUNS) == 1
    # A second decision cannot re-run it.
    again = admin.post(f"/workspaces/{ws}/approvals/{req['id']}/decision", headers=ORIGIN,
                       json={"decision": "approve"})
    assert again.status_code == 409 and len(RERUNS) == 1
    actions = [e["action"] for e in admin.get("/audit-events").json()["events"]]
    for a in ("action.requested", "approval.approve", "execution.started", "execution.succeeded"):
        assert a in actions
    ex_id = body["execution"]["id"]
    assert dev.get(f"/workspaces/{ws}/executions/{ex_id}").json()["status"] == "succeeded"


@pytest.mark.skipif(not PG_URL, reason="needs OPSPILOT_TEST_DATABASE_URL (Postgres)")
def test_concurrent_approvals_execute_once(env):
    ws, dev, run_id = _failed_run(env)
    req = _request(dev, ws, run_id).json()
    admins = [login("org_admin@a.test") for _ in range(4)]

    def go(c):
        return c.post(f"/workspaces/{ws}/approvals/{req['id']}/decision", headers=ORIGIN,
                      json={"decision": "approve"}).status_code

    with ThreadPoolExecutor(4) as pool:
        codes = list(pool.map(go, admins))
    assert codes.count(200) == 1 and len(RERUNS) == 1


def test_separation_of_duties(env):
    ws = env["ws_a"].id
    admin = login("org_admin@a.test")
    admin.post(f"/workspaces/{ws}/pipelines/sync", headers=ORIGIN)
    run_id = admin.get(f"/workspaces/{ws}/pipelines/runs").json()["runs"][0]["id"]
    req = _request(admin, ws, run_id).json()
    r = admin.post(f"/workspaces/{ws}/approvals/{req['id']}/decision", headers=ORIGIN, json={"decision": "approve"})
    assert r.status_code == 403 and r.json()["detail"] == "separation_of_duties"
    assert RERUNS == []


def test_reject_does_not_execute(env):
    ws, dev, run_id = _failed_run(env)
    req = _request(dev, ws, run_id).json()
    r = login("org_admin@a.test").post(f"/workspaces/{ws}/approvals/{req['id']}/decision", headers=ORIGIN,
                                       json={"decision": "reject", "reason": "no"})
    assert r.json()["status"] == "rejected" and r.json()["execution"] is None and RERUNS == []


def test_role_and_tenant_limits(env):
    ws, dev, run_id = _failed_run(env)
    req = _request(dev, ws, run_id).json()
    path = f"/workspaces/{ws}/approvals/{req['id']}/decision"
    body = {"decision": "approve"}
    assert dev.post(path, headers=ORIGIN, json=body).status_code == 403  # requester role cannot approve
    assert login("viewer@a.test").post(path, headers=ORIGIN, json=body).status_code == 403
    assert login("security_auditor@a.test").post(path, headers=ORIGIN, json=body).status_code == 403
    assert login("viewer@a.test").post(f"/workspaces/{ws}/action-requests", headers=ORIGIN,
                                       json={"runId": req["runId"], "type": "rerun_failed_jobs"}).status_code == 403
    assert login("outsider@b.test").post(path, headers=ORIGIN, json=body).status_code == 404
    assert login("outsider@b.test").get(f"/workspaces/{ws}/approvals").status_code == 404
    assert login("security_auditor@a.test").get(f"/workspaces/{ws}/approvals").status_code == 200
    assert RERUNS == []


def test_unallowlisted_action_rejected(env):
    ws, dev, run_id = _failed_run(env)
    r = dev.post(f"/workspaces/{ws}/action-requests", headers=ORIGIN, json={"runId": run_id, "type": "rm_rf"})
    assert r.status_code == 422


def test_github_failure_is_reported_not_hidden(env):
    ws, dev, run_id = _failed_run(env)
    req = _request(dev, ws, run_id).json()
    RERUN_STATUS["code"] = 403
    r = login("org_admin@a.test").post(f"/workspaces/{ws}/approvals/{req['id']}/decision", headers=ORIGIN,
                                       json={"decision": "approve"})
    assert r.json()["status"] == "failed" and r.json()["execution"]["error"] == "github_403"
