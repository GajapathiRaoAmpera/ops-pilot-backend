import base64
import io
import json
import zipfile

import httpx

from app.ai.fix_agent import _apply
from app.ai.groq import GroqClient
from app.config import get_settings
from app.integrations.github import GitHubFactory
from app.main import app
from app.routers.investigations import get_ai
from app.routers.pipelines import get_github_factory
from tests.conftest import ORIGIN, gh_handler, login

SHA = "a" * 40
APP_PY = "def add(a, b):\n    return a - b\n"
FILES = {"src/app.py": APP_PY, ".github/workflows/ci.yml": "on: push\n", "README.md": "# demo\n"}
WRITES: list[tuple[str, str, dict]] = []


def github(request: httpx.Request) -> httpx.Response:
    path, method = request.url.path, request.method
    if method in ("POST", "PUT", "PATCH", "DELETE") and not path.endswith("/rerun-failed-jobs"):
        WRITES.append((method, path, json.loads(request.content or b"{}")))
        if path.endswith("/git/refs"):
            return httpx.Response(201, json={"ref": "x"})
        if "/contents/" in path:
            return httpx.Response(200, json={"content": {}})
        if path.endswith("/pulls"):
            return httpx.Response(201, json={"number": 7, "html_url": "https://github.com/o/r/pull/7"})
    if path.endswith("/logs"):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("test/1.txt", "FAILED tests/test_app.py::test_add - assert -1 == 3\nsrc/app.py:2 in add\n")
        return httpx.Response(200, content=buf.getvalue())
    if f"/git/trees/{SHA}" in path:
        return httpx.Response(200, json={"tree": [{"path": p, "type": "blob"} for p in FILES]})
    if "/contents/" in path:
        name = path.split("/contents/", 1)[1]
        if name in FILES:
            return httpx.Response(200, json={"type": "file", "encoding": "base64", "sha": f"blob-{name}",
                                             "content": base64.b64encode(FILES[name].encode()).decode()})
    return gh_handler(request)


def groq(*replies: dict) -> GroqClient:
    queue = list(replies)

    def handler(request: httpx.Request) -> httpx.Response:
        reply = queue.pop(0) if len(queue) > 1 else queue[0]
        return httpx.Response(200, json={"choices": [{"message": {"content": json.dumps(reply)}}]})
    return GroqClient("gsk_test", "test-model", httpx.MockTransport(handler))


CHOOSE = {"files": ["src/app.py", "not/in/repo.py"], "why": "the test calls add"}
GOOD = {"canFix": True, "title": "Fix add()", "explanation": "add() subtracted instead of adding.",
        "edits": [{"path": "src/app.py", "find": "return a - b", "replace": "return a + b"}]}


def setup(env, *replies):
    WRITES.clear()
    settings = app.dependency_overrides[get_settings]().model_copy(update={"groq_api_key": "gsk_test"})
    app.dependency_overrides[get_settings] = lambda: settings
    factory = GitHubFactory(settings, httpx.MockTransport(github))
    app.dependency_overrides[get_github_factory] = lambda: factory
    app.dependency_overrides[get_ai] = lambda: groq(*replies)
    dev = login("devops_engineer@a.test")
    ws = env["ws_a"].id
    dev.post(f"/workspaces/{ws}/pipelines/sync", headers=ORIGIN)
    run_id = dev.get(f"/workspaces/{ws}/pipelines/runs").json()["runs"][0]["id"]
    return dev, ws, run_id


def test_propose_then_approve_opens_a_pull_request_with_exactly_the_reviewed_change(env):
    dev, ws, run_id = setup(env, CHOOSE, GOOD)
    fix = dev.post(f"/workspaces/{ws}/fix-proposals", headers=ORIGIN, json={"runId": run_id}).json()
    assert fix["status"] == "proposed" and fix["files"] == ["src/app.py"]
    assert "-    return a - b" in fix["diff"] and "+    return a + b" in fix["diff"]
    assert [t["step"] for t in fix["trace"]] == ["list_files", "choose_files", "read_files", "propose", "check"]
    assert WRITES == []  # proposing never writes to GitHub

    req = dev.post(f"/workspaces/{ws}/action-requests", headers=ORIGIN,
                   json={"runId": run_id, "type": "open_fix_pr", "proposalId": fix["id"], "reason": "AI fix"}).json()
    assert req["risk"] == "high" and req["proposal"]["diff"] == fix["diff"]
    assert dev.post(f"/workspaces/{ws}/approvals/{req['id']}/decision", headers=ORIGIN,
                    json={"decision": "approve"}).status_code == 403  # requester cannot approve
    done = login("org_admin@a.test").post(f"/workspaces/{ws}/approvals/{req['id']}/decision", headers=ORIGIN,
                                          json={"decision": "approve"}).json()
    assert done["status"] == "succeeded", done
    assert done["execution"]["result"]["prUrl"] == "https://github.com/o/r/pull/7"
    (_, p1, ref), (m2, p2, put), (_, p3, pr) = WRITES
    assert p1.endswith("/git/refs") and ref["sha"] == SHA and ref["ref"].startswith("refs/heads/opspilot/fix-101-")
    assert m2 == "PUT" and p2.endswith("/contents/src/app.py") and put["sha"] == "blob-src/app.py"
    assert base64.b64decode(put["content"]).decode() == "def add(a, b):\n    return a + b\n"
    assert p3.endswith("/pulls") and pr["base"] == "main" and pr["head"] == ref["ref"].removeprefix("refs/heads/")
    assert "Review before merging" in pr["body"]
    assert not any(p.endswith("/merges") or "/merge" in p for _, p, _ in WRITES)  # never merges


def test_unsafe_patches_are_rejected_and_the_agent_gets_one_retry(env):
    workflow = {**GOOD, "edits": [{"path": ".github/workflows/ci.yml", "find": "on: push", "replace": "on: pull_request"}]}
    dev, ws, run_id = setup(env, {"files": ["src/app.py"]}, workflow, workflow)
    fix = dev.post(f"/workspaces/{ws}/fix-proposals", headers=ORIGIN, json={"runId": run_id}).json()
    assert fix["status"] == "no_fix" and "safety checks" in fix["explanation"]
    assert [t["step"] for t in fix["trace"]][-3:] == ["propose", "check", "give_up"]
    assert dev.post(f"/workspaces/{ws}/action-requests", headers=ORIGIN,
                    json={"runId": run_id, "type": "open_fix_pr", "proposalId": fix["id"]}).status_code == 409


def test_patch_rules():
    files = {"src/app.py": {"text": APP_PY, "sha": "s"}}
    for edits, why in [
        ([{"path": "src/app.py", "find": "b", "replace": "c"}], "occurs"),  # not unique
        ([{"path": "src/other.py", "find": "x", "replace": "y"}], "not one of the files"),
        ([{"path": "src/app.py", "find": "return a - b", "replace": 'token = "ghp_' + "x" * 36 + '"'}], "secret"),
        ([{"path": "src/app.py", "find": "return a - b", "replace": "return a - b"}], "do not change"),
    ]:
        try:
            _apply(edits, files)
        except ValueError as exc:
            assert why in str(exc), (why, exc)
        else:
            raise AssertionError(why)


def test_who_may_propose(env):
    _, ws, run_id = setup(env, CHOOSE, GOOD)
    assert login("developer@a.test").post(f"/workspaces/{ws}/fix-proposals", headers=ORIGIN, json={"runId": run_id}).status_code == 403
    assert login("viewer@a.test").post(f"/workspaces/{ws}/fix-proposals", headers=ORIGIN, json={"runId": run_id}).status_code == 403
    assert login("outsider@b.test").post(f"/workspaces/{ws}/fix-proposals", headers=ORIGIN, json={"runId": run_id}).status_code == 404


def test_declined_fix_is_recorded_honestly(env):
    dev, ws, run_id = setup(env, CHOOSE, {"canFix": False, "explanation": "The registry credentials expired."})
    fix = dev.post(f"/workspaces/{ws}/fix-proposals", headers=ORIGIN, json={"runId": run_id}).json()
    assert fix["status"] == "no_fix" and fix["explanation"] == "The registry credentials expired." and fix["diff"] == ""


def test_missing_contents_permission_is_explained(env):
    dev, ws, run_id = setup(env, CHOOSE, GOOD)

    def no_contents(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403) if "/git/trees/" in request.url.path else github(request)
    settings = app.dependency_overrides[get_settings]()
    factory = GitHubFactory(settings, httpx.MockTransport(no_contents))
    app.dependency_overrides[get_github_factory] = lambda: factory
    fix = dev.post(f"/workspaces/{ws}/fix-proposals", headers=ORIGIN, json={"runId": run_id}).json()
    assert fix["status"] == "no_fix" and "Contents: Read and write" in fix["explanation"]
