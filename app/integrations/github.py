"""Read-only GitHub Actions adapter. No write operations in this phase."""
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


def valid_repo(repo: str) -> bool:
    return bool(_REPO_RE.match(repo))


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
    def __init__(self, settings: Settings, transport: httpx.BaseTransport | None = None):
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        if settings.github_token:
            headers["Authorization"] = f"Bearer {settings.github_token}"
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
