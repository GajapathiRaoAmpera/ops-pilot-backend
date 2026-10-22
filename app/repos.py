"""Repository lookups shared by the routers: which repositories a workspace tracks and which token reaches each."""
import uuid
from types import SimpleNamespace

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.integrations.github import GitHubClient, GitHubFactory
from app.models import Integration, Repository

MAX_REPOS_PER_WORKSPACE = 50


def workspace_integration(db: Session, workspace_id: uuid.UUID) -> Integration | None:
    return db.scalar(select(Integration).where(Integration.workspace_id == workspace_id, Integration.provider == "github"))


def workspace_repos(db: Session, workspace_id: uuid.UUID) -> list[Repository]:
    return list(db.scalars(select(Repository).where(Repository.workspace_id == workspace_id, Repository.provider == "github")
                           .order_by(Repository.full_name)))


def find_repo(db: Session, workspace_id: uuid.UUID, full_name: str) -> Repository | None:
    return db.scalar(select(Repository).where(Repository.workspace_id == workspace_id, Repository.provider == "github",
                                              Repository.full_name == full_name))


def client_for(factory: GitHubFactory, db: Session, workspace_id: uuid.UUID, full_name: str) -> GitHubClient:
    """The repository's own token if it has one, else the workspace's shared token, else none."""
    repo = find_repo(db, workspace_id, full_name)
    integ = workspace_integration(db, workspace_id)
    cipher = (repo.secret_ciphertext if repo and repo.secret_ciphertext else None) or (integ.secret_ciphertext if integ else None)
    return factory.for_integration(SimpleNamespace(secret_ciphertext=cipher))
