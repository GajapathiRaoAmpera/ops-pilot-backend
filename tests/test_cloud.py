import json

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from sqlalchemy import select

from app.main import app
from app.models import AuditEvent, Integration
from app.routers.cloud import get_transport
from tests.conftest import ORIGIN, login


def make_key() -> str:
    pem = rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    return json.dumps({"type": "service_account", "project_id": "demo-project-1", "private_key": pem,
                       "client_email": "viewer@demo-project-1.iam.gserviceaccount.com"})


def handler(request: httpx.Request) -> httpx.Response:
    url = str(request.url)
    if url.startswith("https://oauth2.googleapis.com/token"):
        return httpx.Response(200, json={"access_token": "t0k"})
    assert request.method == "GET" or "oauth2" in url  # nothing but reads
    if "cloudresourcemanager" in url:
        return httpx.Response(200, json={"projectId": "demo-project-1", "name": "Demo", "lifecycleState": "ACTIVE"})
    if "aggregated/instances" in url:
        return httpx.Response(200, json={"items": {"zones/us-central1-a": {"instances": [
            {"name": "vm-1", "zone": "x/zones/us-central1-a", "machineType": "x/machineTypes/e2-small", "status": "RUNNING"}]}}})
    if "run.googleapis.com" in url:
        return httpx.Response(200, json={"services": [{"name": "projects/p/locations/us-central1/services/api",
                                                        "uri": "https://api.run.app", "conditions": [{"type": "Ready", "state": "CONDITION_SUCCEEDED"}]}]})
    return httpx.Response(403, json={"error": "disabled"})  # GKE API not enabled


def path(ws, tail=""):
    return f"/workspaces/{ws}/cloud/gcp{tail}"


def test_connect_encrypts_key_and_never_returns_it(env):
    ws, key = env["ws_a"].id, make_key()
    admin = login("org_admin@a.test")
    r = admin.put(path(ws), headers=ORIGIN, json={"key": key})
    assert r.status_code == 200 and r.json() == {"connected": True, "projectId": "demo-project-1",
                                                  "serviceAccount": "viewer@demo-project-1.iam.gserviceaccount.com", "keySet": True}
    assert "BEGIN PRIVATE KEY" not in r.text and "BEGIN PRIVATE KEY" not in admin.get(path(ws)).text
    with env["factory"]() as db:
        row = db.scalar(select(Integration).where(Integration.provider == "gcp"))
        assert "PRIVATE KEY" not in row.secret_ciphertext
        assert not any("PRIVATE KEY" in (e.detail + e.resource) for e in db.scalars(select(AuditEvent)))


def test_rejects_malformed_keys(env):
    admin = login("org_admin@a.test")
    for bad in ("x" * 60, json.dumps({"type": "authorized_user", "a": "b" * 60}),
                json.dumps({"type": "service_account", "project_id": "p", "client_email": "e", "private_key": "nope" * 20})):
        assert admin.put(path(env["ws_a"].id), headers=ORIGIN, json={"key": bad}).status_code == 422


def test_only_org_admin_can_use_it(env):
    ws = env["ws_a"].id
    for role in ("workspace_admin", "devops_engineer", "developer", "security_auditor", "viewer"):
        c = login(f"{role}@a.test")
        assert c.get(path(ws)).status_code == 403, role
        assert c.put(path(ws), headers=ORIGIN, json={"key": make_key()}).status_code == 403, role
        assert c.get(path(ws, "/inventory")).status_code == 403, role
    assert login("outsider@b.test").get(path(ws)).status_code == 404  # other tenant


def test_inventory_is_partial_when_one_api_is_disabled(env):
    app.dependency_overrides[get_transport] = lambda: httpx.MockTransport(handler)
    ws, admin = env["ws_a"].id, login("org_admin@a.test")
    assert admin.get(path(ws, "/inventory")).status_code == 409  # not connected yet
    admin.put(path(ws), headers=ORIGIN, json={"key": make_key()})
    assert admin.post(path(ws, "/test"), headers=ORIGIN).json()["ok"] is True
    inv = admin.get(path(ws, "/inventory")).json()
    assert inv["compute"] == [{"name": "vm-1", "zone": "us-central1-a", "machineType": "e2-small", "status": "RUNNING"}]
    assert inv["cloudRun"][0] == {"name": "api", "region": "us-central1", "uri": "https://api.run.app", "status": "ready"}
    assert inv["gke"] == [] and inv["errors"] == {"gke": "forbidden"}
    assert admin.delete(path(ws), headers=ORIGIN).json() == {"connected": False}
    with env["factory"]() as db:
        acts = {e.action for e in db.scalars(select(AuditEvent))}
    assert {"cloud.gcp.connected", "cloud.gcp.inventory", "cloud.gcp.disconnected"} <= acts
