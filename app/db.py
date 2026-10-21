from collections.abc import Iterator

from sqlalchemy import MetaData, create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import get_settings

SCHEMA = "opspilot"  # all application tables live here, not in Postgres' (or Supabase's) `public`


class Base(DeclarativeBase):
    metadata = MetaData(schema=SCHEMA)


_engine = None
_factory: sessionmaker[Session] | None = None


def get_engine():
    global _engine, _factory
    if _engine is None:
        _engine = create_engine(
            get_settings().database_url,
            pool_pre_ping=True,
            # Required for Supabase's transaction pooler (pgbouncer); harmless otherwise.
            connect_args={"prepare_threshold": None},
        )
        _factory = sessionmaker(_engine, expire_on_commit=False)
    return _engine


def get_db() -> Iterator[Session]:
    get_engine()
    assert _factory is not None
    with _factory() as db:
        yield db
