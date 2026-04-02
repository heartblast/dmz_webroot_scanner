from __future__ import annotations

from contextlib import contextmanager
from functools import lru_cache

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from config.settings import load_settings


@lru_cache(maxsize=1)
def get_engine() -> Engine:
    settings = load_settings()
    database = settings.database
    if settings.config_error and database.backend == "postgresql":
        raise RuntimeError(settings.config_error)
    if database.backend == "sqlite":
        database.sqlite_path.parent.mkdir(parents=True, exist_ok=True)
        engine = create_engine(
            database.sqlalchemy_url,
            future=True,
            connect_args={"check_same_thread": False},
        )

        @event.listens_for(engine, "connect")
        def _set_sqlite_pragma(dbapi_connection, _connection_record) -> None:
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute(f"PRAGMA busy_timeout={database.sqlite_busy_timeout_ms}")
            cursor.close()

        return engine

    if database.backend == "postgresql":
        return create_engine(
            database.sqlalchemy_url,
            future=True,
            pool_pre_ping=database.pool_pre_ping,
            pool_size=database.pool_size,
            max_overflow=database.max_overflow,
        )

    raise ValueError(f"Unsupported backend: {database.backend}")


@lru_cache(maxsize=1)
def get_session_factory() -> sessionmaker[Session]:
    return sessionmaker(bind=get_engine(), expire_on_commit=False, future=True)


@contextmanager
def session_scope() -> Session:
    session = get_session_factory()()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
