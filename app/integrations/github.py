"""Read-only GitHub Actions adapter. No write operations in this phase."""
import base64
import io
import re
import zipfile
from dataclasses import dataclass
from datetime import datetime

import httpx

from app.config import Settings

MAX_LOG_BYTES = 200_000
_REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_SECRET_RE = re.compile(
    r"(gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}"
    r"|(?i:(?:password|secret|token|api[_-]?key)\s*[=:]\s*)\S+)"
)


class GitHubError(Exception):
    pass


@dataclass
class RunData:
    external_id: str
    workflow: str
    branch: str
    commit_sha: str
    status: str
    conclusion: str | None
    html_url: str
    started_at: datetime | None


_PATH_RE = re.compile(r"^[A-Za-z0-9_.@+-][A-Za-z0-9_./@+-]*$")
_BRANCH_RE = re.compile(r"^[A-Za-z0-9._/-]{1,200}$")


def valid_path(path: str) -> bool:
    """A repository-relative file path: no absolute paths, no "." or ".." segments, no odd characters."""
    return (bool(_PATH_RE.match(path)) and len(path) <= 400
            and not any(seg in ("", ".", "..") for seg in path.split("/")))


def valid_branch(name: str) -> bool:
    return bool(_BRANCH_RE.match(name)) and ".." not in name and not name.startswith("/") and not name.endswith("/")


def valid_repo(repo: str) -> bool:
    """owner/name only; "." and ".." segments are refused so a name can never walk the API path."""
    return bool(_REPO_RE.match(repo)) and not any(part in (".", "..") for part in repo.split("/"))


def redact(text: str) -> str:
    return _SECRET_RE.sub("[REDACTED]", text)


def _parse_dt(v: str | None) -> datetime | None:
    return datetime.fromisoformat(v) if v else None


def run_from_api(r: dict) -> RunData:
    return RunData(
        external_id=str(r["id"]),
        workflow=r.get("name") or "",
        branch=r.get("head_branch") or "",
        commit_sha=(r.get("head_sha") or "")[:40],
        status=r.get("status") or "",
        conclusion=r.get("conclusion"),
        html_url=r.get("html_url") or "",
        started_at=_parse_dt(r.get("run_started_at")),
    )


class GitHubClient:
    def __init__(self, settings: Settings, transport: httpx.BaseTransport | None = None, token: str | None = None):
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        token = settings.github_token if token is None else token
        if token:
            headers["Authorization"] = f"Bearer {token}"
        self._http = httpx.Client(
            base_url=settings.github_api_url, headers=headers, timeout=10.0,
            transport=transport, follow_redirects=True,
        )

    @property
    def configured(self) -> bool:
        return "Authorization" in self._http.headers

    def _get(self, path: str, **params) -> httpx.Response:
        try:
            res = self._http.get(path, params=params)
        except httpx.HTTPError as exc:
            raise GitHubError("github_unreachable") from exc
        if res.status_code >= 400:
            raise GitHubError(f"github_{res.status_code}")
        return res

    def rerun_failed_jobs(self, repo: str, run_id: str) -> None:
        """WRITE. Only reachable from an approved, audited execution."""
        if not valid_repo(repo) or not run_id.isdigit():
            raise GitHubError("invalid_request")
        try:
            res = self._http.post(f"/repos/{repo}/actions/runs/{run_id}/rerun-failed-jobs")
        except httpx.HTTPError as exc:
            raise GitHubError("github_unreachable") from exc
        if res.status_code != 201:
            raise GitHubError(f"github_{res.status_code}")

    # ---- read access used by the fix agent ----
    def list_files(self, repo: str, ref: str, limit: int = 3000) -> list[str]:
        """Paths of the files (blobs) at a commit. Large repositories are truncated by GitHub; that is acceptable."""
        if not valid_repo(repo) or not re.fullmatch(r"[0-9a-f]{7,40}|[A-Za-z0-9._/-]{1,200}", ref):
            raise GitHubError("invalid_request")
        data = self._get(f"/repos/{repo}/git/trees/{ref}", recursive="1").json()
        return [t["path"] for t in data.get("tree", []) if t.get("type") == "blob"][:limit]

    def get_file(self, repo: str, path: str, ref: str) -> tuple[str, str]:
        """(text, blob sha). Raises GitHubError("not_text") for binary or oversized files."""
        if not valid_repo(repo) or not valid_path(path):
            raise GitHubError("invalid_request")
        d = self._get(f"/repos/{repo}/contents/{path}", ref=ref).json()
        if not isinstance(d, dict) or d.get("type") != "file" or d.get("encoding") != "base64":
            raise GitHubError("not_text")
        raw = base64.b64decode(d.get("content", ""))
        if len(raw) > 100_000 or b"\x00" in raw:
            raise GitHubError("not_text")
        return raw.decode("utf-8", "replace"), d["sha"]

    def default_branch(self, repo: str) -> str:
        if not valid_repo(repo):
            raise GitHubError("invalid_request")
        return self._get(f"/repos/{repo}").json().get("default_branch") or "main"

    def branch_head(self, repo: str, branch: str) -> str:
        if not valid_repo(repo) or not valid_branch(branch):
            raise GitHubError("invalid_request")
        return self._get(f"/repos/{repo}/git/ref/heads/{branch}").json()["object"]["sha"]

    # ---- WRITE: only reachable from an approved, audited execution ----
    def _send(self, method: str, path: str, ok: tuple[int, ...], body: dict) -> dict:
        try:
            res = self._http.request(method, path, json=body)
        except httpx.HTTPError as exc:
            raise GitHubError("github_unreachable") from exc
        if res.status_code not in ok:
            raise GitHubError(f"github_{res.status_code}")
        return res.json()

    def create_branch(self, repo: str, branch: str, from_sha: str) -> None:
        if not valid_repo(repo) or not valid_branch(branch) or not re.fullmatch(r"[0-9a-f]{40}", from_sha):
            raise GitHubError("invalid_request")
        self._send("POST", f"/repos/{repo}/git/refs", (201,), {"ref": f"refs/heads/{branch}", "sha": from_sha})

    def put_file(self, repo: str, path: str, branch: str, text: str, blob_sha: str, message: str) -> None:
        """Updates one existing file on a branch. GitHub refuses it if the file changed since blob_sha was read."""
        if not valid_repo(repo) or not valid_path(path) or not valid_branch(branch):
            raise GitHubError("invalid_request")
        self._send("PUT", f"/repos/{repo}/contents/{path}", (200, 201), {
            "message": message, "branch": branch, "sha": blob_sha,
            "content": base64.b64encode(text.encode()).decode()})

    def create_pull(self, repo: str, head: str, base: str, title: str, body: str) -> dict:
        if not valid_repo(repo) or not valid_branch(head) or not valid_branch(base):
            raise GitHubError("invalid_request")
        d = self._send("POST", f"/repos/{repo}/pulls", (201,), {"title": title, "head": head, "base": base, "body": body,
                                                                  "maintainer_can_modify": True})
        return {"number": d.get("number"), "url": d.get("html_url")}

    def list_runs(self, repo: str, limit: int = 20) -> list[RunData]:
        if not valid_repo(repo):
            raise GitHubError("invalid_repo")
        data = self._get(f"/repos/{repo}/actions/runs", per_page=min(limit, 50)).json()
        return [run_from_api(r) for r in data.get("workflow_runs", [])]

    def get_run(self, repo: str, run_id: str) -> RunData:
        if not valid_repo(repo) or not run_id.isdigit():
            raise GitHubError("invalid_request")
        return run_from_api(self._get(f"/repos/{repo}/actions/runs/{run_id}").json())

    def get_logs(self, repo: str, run_id: str) -> str:
        """Run logs (zip) as redacted, size-capped text. Content is UNTRUSTED."""
        if not valid_repo(repo) or not run_id.isdigit():
            raise GitHubError("invalid_request")
        raw = self._get(f"/repos/{repo}/actions/runs/{run_id}/logs").content
        try:
            with zipfile.ZipFile(io.BytesIO(raw)) as zf:
                parts = []
                for name in sorted(zf.namelist()):
                    parts.append(f"=== {name} ===\n" + zf.read(name).decode("utf-8", "replace"))
        except zipfile.BadZipFile as exc:
            raise GitHubError("bad_log_archive") from exc
        return redact("\n".join(parts))[:MAX_LOG_BYTES]


class GitHubFactory:
    """Builds a client with the integration's own decrypted token (env token only as a dev fallback)."""

    def __init__(self, settings: Settings, transport: httpx.BaseTransport | None = None):
        self._settings = settings
        self._transport = transport

    def for_integration(self, integration) -> GitHubClient:
        from app.crypto import decrypt  # local import keeps this module importable without a key

        token = None
        if integration is not None and integration.secret_ciphertext:
            token = decrypt(self._settings, integration.secret_ciphertext) or ""  # undecryptable => unauthenticated
        return GitHubClient(self._settings, self._transport, token=token)
